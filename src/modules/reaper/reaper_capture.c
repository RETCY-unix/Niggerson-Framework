/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  REAPER_CAPTURE.C - PACKET INTERCEPTION ENGINE
 *  Raw socket packet capture without libpcap
 *  
 *  Features:
 *  - Promiscuous mode activation
 *  - Protocol dissection (Ethernet → IP → TCP/UDP)
 *  - MAC/IP filtering
 *  - Async capture with ring buffer
 *  
 *  Zero Dependencies | Full Stealth | Military Grade
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include "reaper_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <poll.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  PROMISCUOUS MODE
 * ═══════════════════════════════════════════════════════════════════════════ */

static int enable_promiscuous(const char* iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    // Get current flags
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        close(fd);
        return -2;
    }
    
    // Enable promiscuous
    ifr.ifr_flags |= IFF_PROMISC;
    
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        close(fd);
        return -3;
    }
    
    close(fd);
    return 0;
}

static int disable_promiscuous(const char* iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        close(fd);
        return -2;
    }
    
    ifr.ifr_flags &= ~IFF_PROMISC;
    
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        close(fd);
        return -3;
    }
    
    close(fd);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CREATE CAPTURE SOCKET
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_create_capture_socket(const char* iface) {
    // Create raw socket to capture all traffic
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) return -1;
    
    // Get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        return -2;
    }
    
    // Bind to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -3;
    }
    
    // Enable promiscuous mode
    if (enable_promiscuous(iface) < 0) {
        // Non-fatal, continue anyway
    }
    
    return sock;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PACKET DISSECTION
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    struct ether_header* eth;
    struct ip* ip;
    struct tcphdr* tcp;
    struct udphdr* udp;
    uint8_t* payload;
    int payload_len;
    protocol_t protocol;
} dissected_packet_t;

static int dissect_packet(const uint8_t* data, int len, dissected_packet_t* pkt) {
    memset(pkt, 0, sizeof(*pkt));
    
    if (len < (int)sizeof(struct ether_header)) return -1;
    
    pkt->eth = (struct ether_header*)data;
    
    // Only process IP packets
    if (ntohs(pkt->eth->ether_type) != ETHERTYPE_IP) return -2;
    
    int offset = sizeof(struct ether_header);
    if (len < offset + (int)sizeof(struct ip)) return -3;
    
    pkt->ip = (struct ip*)(data + offset);
    
    // Verify IP version
    if (pkt->ip->ip_v != 4) return -4;
    
    int ip_hlen = pkt->ip->ip_hl * 4;
    offset += ip_hlen;
    
    // Process TCP
    if (pkt->ip->ip_p == IPPROTO_TCP) {
        if (len < offset + (int)sizeof(struct tcphdr)) return -5;
        
        pkt->tcp = (struct tcphdr*)(data + offset);
        int tcp_hlen = pkt->tcp->th_off * 4;
        offset += tcp_hlen;
        
        pkt->protocol = detect_protocol(ntohs(pkt->tcp->th_dport));
        if (pkt->protocol == PROTO_UNKNOWN) {
            pkt->protocol = detect_protocol(ntohs(pkt->tcp->th_sport));
        }
    }
    // Process UDP
    else if (pkt->ip->ip_p == IPPROTO_UDP) {
        if (len < offset + (int)sizeof(struct udphdr)) return -6;
        
        pkt->udp = (struct udphdr*)(data + offset);
        offset += sizeof(struct udphdr);
        
        pkt->protocol = detect_protocol(ntohs(pkt->udp->uh_dport));
        if (pkt->protocol == PROTO_UNKNOWN) {
            pkt->protocol = detect_protocol(ntohs(pkt->udp->uh_sport));
        }
    }
    else {
        return -7;  // Not TCP/UDP
    }
    
    // Set payload
    if (offset < len) {
        pkt->payload = (uint8_t*)(data + offset);
        pkt->payload_len = len - offset;
    }
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PACKET FILTERING
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool should_capture(reaper_session_t* session, const dissected_packet_t* pkt) {
    // Check if packet involves our target or gateway
    uint32_t src = pkt->ip->ip_src.s_addr;
    uint32_t dst = pkt->ip->ip_dst.s_addr;
    uint32_t target = session->target_ip.s_addr;
    uint32_t gateway = session->gateway_ip.s_addr;
    
    // Capture packets to/from target
    if (src == target || dst == target) return true;
    
    // In full intercept mode, capture gateway traffic too
    if (session->mode & REAPER_MODE_INTERCEPT) {
        if (src == gateway || dst == gateway) return true;
    }
    
    return false;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CAPTURE THREAD
 * ═══════════════════════════════════════════════════════════════════════════ */

void* reaper_capture_thread(void* arg) {
    reaper_session_t* session = (reaper_session_t*)arg;
    
    uint8_t buffer[MAX_PACKET_SIZE];
    
    while (session->running) {
        struct pollfd pfd = { .fd = session->capture_sock, .events = POLLIN };
        int ret = poll(&pfd, 1, 100);  // 100ms timeout
        
        if (ret <= 0) continue;
        
        ssize_t len = recv(session->capture_sock, buffer, sizeof(buffer), 0);
        if (len < 0) continue;
        
        // Dissect packet
        dissected_packet_t dissected;
        if (dissect_packet(buffer, len, &dissected) < 0) continue;
        
        // Check if we should capture this packet
        if (!should_capture(session, &dissected)) continue;
        
        // Build captured packet structure
        captured_packet_t cap;
        memset(&cap, 0, sizeof(cap));
        
        cap.timestamp = (uint32_t)time(NULL);
        cap.length = len;
        cap.protocol = dissected.protocol;
        memcpy(cap.src_mac, dissected.eth->ether_shost, 6);
        memcpy(cap.dst_mac, dissected.eth->ether_dhost, 6);
        cap.src_ip = dissected.ip->ip_src;
        cap.dst_ip = dissected.ip->ip_dst;
        
        if (dissected.tcp) {
            cap.src_port = ntohs(dissected.tcp->th_sport);
            cap.dst_port = ntohs(dissected.tcp->th_dport);
        } else if (dissected.udp) {
            cap.src_port = ntohs(dissected.udp->uh_sport);
            cap.dst_port = ntohs(dissected.udp->uh_dport);
        }
        
        // Copy payload
        if (dissected.payload && dissected.payload_len > 0) {
            int copy_len = dissected.payload_len < MAX_PACKET_SIZE ? 
                           dissected.payload_len : MAX_PACKET_SIZE;
            memcpy(cap.data, dissected.payload, copy_len);
        }
        
        // Add to ring buffer
        ring_buffer_push(&session->packet_buffer, &cap);
        session->packets_captured++;
    }
    
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  START/STOP CAPTURE
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_start_capture(reaper_session_t* session) {
    // Create capture socket
    session->capture_sock = reaper_create_capture_socket(session->interface);
    if (session->capture_sock < 0) {
        return -1;
    }
    
    // Start capture thread
    if (pthread_create(&session->capture_thread, NULL, reaper_capture_thread, session) != 0) {
        close(session->capture_sock);
        session->capture_sock = -1;
        return -2;
    }
    
    return 0;
}

int reaper_stop_capture(reaper_session_t* session) {
    if (session->capture_sock >= 0) {
        // Disable promiscuous mode
        disable_promiscuous(session->interface);
        
        close(session->capture_sock);
        session->capture_sock = -1;
    }
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PACKET ANALYSIS UTILITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

// Check if payload contains HTTP request
bool reaper_is_http_request(const uint8_t* data, int len) {
    if (len < 4) return false;
    
    return (strncmp((char*)data, "GET ", 4) == 0 ||
            strncmp((char*)data, "POST", 4) == 0 ||
            strncmp((char*)data, "HEAD", 4) == 0 ||
            strncmp((char*)data, "PUT ", 4) == 0 ||
            strncmp((char*)data, "DELE", 4) == 0 ||  // DELETE
            strncmp((char*)data, "OPTI", 4) == 0);   // OPTIONS
}

// Check if payload contains HTTP response
bool reaper_is_http_response(const uint8_t* data, int len) {
    if (len < 4) return false;
    return strncmp((char*)data, "HTTP", 4) == 0;
}

// Check if this is a DNS query
bool reaper_is_dns_query(const uint8_t* data, int len) {
    if (len < 12) return false;
    
    // DNS header: flags in bytes 2-3
    // Query has QR bit (bit 15) = 0
    uint16_t flags = (data[2] << 8) | data[3];
    return (flags & 0x8000) == 0;
}

// Extract HTTP Host header
int reaper_extract_http_host(const uint8_t* data, int len, char* host, int host_len) {
    const char* host_hdr = strstr((char*)data, "Host:");
    if (!host_hdr) host_hdr = strstr((char*)data, "host:");
    if (!host_hdr) return -1;
    
    host_hdr += 5;  // Skip "Host:"
    while (*host_hdr == ' ') host_hdr++;
    
    int i = 0;
    while (host_hdr[i] && host_hdr[i] != '\r' && host_hdr[i] != '\n' && i < host_len - 1) {
        host[i] = host_hdr[i];
        i++;
    }
    host[i] = '\0';
    
    return 0;
}

// Extract DNS query domain
int reaper_extract_dns_domain(const uint8_t* data, int len, char* domain, int domain_len) {
    if (len < 12) return -1;
    
    // Skip DNS header (12 bytes)
    const uint8_t* qname = data + 12;
    int remaining = len - 12;
    
    int out_idx = 0;
    while (remaining > 0 && *qname != 0) {
        int label_len = *qname++;
        remaining--;
        
        if (label_len > remaining || label_len > 63) return -2;
        
        if (out_idx > 0 && out_idx < domain_len - 1) {
            domain[out_idx++] = '.';
        }
        
        for (int i = 0; i < label_len && out_idx < domain_len - 1; i++) {
            domain[out_idx++] = *qname++;
            remaining--;
        }
    }
    domain[out_idx] = '\0';
    
    return 0;
}
