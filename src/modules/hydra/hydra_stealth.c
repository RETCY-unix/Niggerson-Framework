/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  HYDRA_STEALTH.C - PHANTOM RECONNAISSANCE ENGINE
 *  Multi-Mode Stealth Scanner with Advanced Evasion
 *  
 *  Capabilities:
 *  - SYN/ACK/FIN/XMAS/NULL/UDP/Window/Maimon scans
 *  - Packet fragmentation for IDS evasion
 *  - Decoy scanning with spoofed sources
 *  - Randomized fingerprints on every packet
 *  - Adaptive timing with jitter
 *  
 *  Zero external dependencies - pure raw sockets
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include "hydra_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  INTERNAL STRUCTURES
 * ═══════════════════════════════════════════════════════════════════════════ */

// Pseudo header for TCP checksum calculation
struct pseudo_header_v4 {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zeros;
    uint8_t  protocol;
    uint16_t length;
};

// Scan state for async response handling
typedef struct {
    volatile int running;
    int raw_sock;
    struct in_addr target;
    port_result_t* results;
    int* result_count;
    int max_results;
    pthread_mutex_t lock;
    scan_mode_t mode;
} scan_state_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  CHECKSUM CALCULATION
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint16_t phantom_checksum(const void* data, int len) {
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

static uint16_t phantom_tcp_checksum(struct ip* iph, struct tcphdr* tcph, int tcp_len) {
    struct pseudo_header_v4 psh;
    char* pseudo_packet;
    uint16_t checksum;
    
    psh.src_addr = iph->ip_src.s_addr;
    psh.dst_addr = iph->ip_dst.s_addr;
    psh.zeros = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(tcp_len);
    
    int psize = sizeof(psh) + tcp_len;
    pseudo_packet = malloc(psize);
    if (!pseudo_packet) return 0;
    
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcph, tcp_len);
    
    checksum = phantom_checksum(pseudo_packet, psize);
    free(pseudo_packet);
    
    return checksum;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  RAW PACKET CRAFTING
 * ═══════════════════════════════════════════════════════════════════════════ */

// Build IP header with randomized fingerprint
static void phantom_build_ip(struct ip* iph, 
                              const packet_fingerprint_t* fp,
                              struct in_addr* src,
                              struct in_addr* dst,
                              uint8_t protocol,
                              int payload_len) {
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + payload_len);
    iph->ip_id = htons(fp->ip_id);
    iph->ip_off = 0;
    iph->ip_ttl = fp->ttl;
    iph->ip_p = protocol;
    iph->ip_sum = 0;
    iph->ip_src = *src;
    iph->ip_dst = *dst;
    
    iph->ip_sum = phantom_checksum(iph, sizeof(struct ip));
}

// Build TCP header based on scan mode
static void phantom_build_tcp(struct tcphdr* tcph,
                               const packet_fingerprint_t* fp,
                               uint16_t dst_port,
                               scan_mode_t mode) {
    memset(tcph, 0, sizeof(struct tcphdr));
    
    tcph->th_sport = htons(fp->src_port);
    tcph->th_dport = htons(dst_port);
    tcph->th_seq = htonl(fp->tcp_seq);
    tcph->th_ack = htonl(fp->tcp_ack);
    tcph->th_off = 5;  // 20 bytes, no options
    tcph->th_win = htons(fp->tcp_window);
    tcph->th_sum = 0;
    tcph->th_urp = 0;
    
    // Set flags based on scan mode
    switch (mode) {
        case SCAN_MODE_SYN:
            tcph->th_flags = TH_SYN;
            break;
        case SCAN_MODE_ACK:
            tcph->th_flags = TH_ACK;
            break;
        case SCAN_MODE_FIN:
            tcph->th_flags = TH_FIN;
            break;
        case SCAN_MODE_XMAS:
            tcph->th_flags = TH_FIN | TH_PUSH | TH_URG;
            break;
        case SCAN_MODE_NULL:
            tcph->th_flags = 0;
            break;
        case SCAN_MODE_WINDOW:
            tcph->th_flags = TH_ACK;
            break;
        case SCAN_MODE_MAIMON:
            tcph->th_flags = TH_FIN | TH_ACK;
            break;
        default:
            tcph->th_flags = TH_SYN;
    }
}

// Build complete TCP probe packet
static int phantom_build_tcp_packet(char* buffer, 
                                     int buflen,
                                     phantom_config_t* cfg,
                                     struct in_addr* src,
                                     uint16_t dst_port) {
    if (buflen < (int)(sizeof(struct ip) + sizeof(struct tcphdr))) {
        return -1;
    }
    
    struct ip* iph = (struct ip*)buffer;
    struct tcphdr* tcph = (struct tcphdr*)(buffer + sizeof(struct ip));
    
    // Generate fresh fingerprint for this packet
    packet_fingerprint_t fp;
    phantom_generate_fingerprint(&cfg->prng, &fp);
    
    // Build headers
    phantom_build_ip(iph, &fp, src, &cfg->target, IPPROTO_TCP, sizeof(struct tcphdr));
    phantom_build_tcp(tcph, &fp, dst_port, cfg->mode);
    
    // Calculate TCP checksum
    tcph->th_sum = phantom_tcp_checksum(iph, tcph, sizeof(struct tcphdr));
    
    return sizeof(struct ip) + sizeof(struct tcphdr);
}

// Build fragmented TCP packet (for IDS evasion)
static int phantom_build_fragmented_packet(char* frag1, int* frag1_len,
                                            char* frag2, int* frag2_len,
                                            phantom_config_t* cfg,
                                            struct in_addr* src,
                                            uint16_t dst_port) {
    char full_packet[128];
    int full_len = phantom_build_tcp_packet(full_packet, sizeof(full_packet), 
                                            cfg, src, dst_port);
    if (full_len < 0) return -1;
    
    struct ip* orig_iph = (struct ip*)full_packet;
    int ip_hlen = sizeof(struct ip);
    int tcp_len = full_len - ip_hlen;
    
    // Fragment 1: IP header + first 8 bytes of TCP
    int frag1_payload = 8;
    struct ip* iph1 = (struct ip*)frag1;
    memcpy(iph1, orig_iph, ip_hlen);
    iph1->ip_len = htons(ip_hlen + frag1_payload);
    iph1->ip_off = htons(IP_MF);  // More fragments
    iph1->ip_sum = 0;
    iph1->ip_sum = phantom_checksum(iph1, ip_hlen);
    memcpy(frag1 + ip_hlen, full_packet + ip_hlen, frag1_payload);
    *frag1_len = ip_hlen + frag1_payload;
    
    // Fragment 2: IP header + remaining TCP
    int frag2_payload = tcp_len - frag1_payload;
    struct ip* iph2 = (struct ip*)frag2;
    memcpy(iph2, orig_iph, ip_hlen);
    iph2->ip_len = htons(ip_hlen + frag2_payload);
    iph2->ip_off = htons(frag1_payload / 8);  // Offset in 8-byte units
    iph2->ip_sum = 0;
    iph2->ip_sum = phantom_checksum(iph2, ip_hlen);
    memcpy(frag2 + ip_hlen, full_packet + ip_hlen + frag1_payload, frag2_payload);
    *frag2_len = ip_hlen + frag2_payload;
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  RESPONSE LISTENER THREAD
 * ═══════════════════════════════════════════════════════════════════════════ */

static void* phantom_listener_thread(void* arg) {
    scan_state_t* state = (scan_state_t*)arg;
    
    char buffer[65536];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    
    // Set receive timeout
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms
    setsockopt(state->raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    while (state->running) {
        int len = recvfrom(state->raw_sock, buffer, sizeof(buffer), 0,
                          (struct sockaddr*)&src_addr, &addr_len);
        if (len < 0) continue;
        
        struct ip* iph = (struct ip*)buffer;
        
        // Verify source is our target
        if (iph->ip_src.s_addr != state->target.s_addr) continue;
        
        if (iph->ip_p == IPPROTO_TCP) {
            int ip_hlen = iph->ip_hl * 4;
            struct tcphdr* tcph = (struct tcphdr*)(buffer + ip_hlen);
            
            uint16_t port = ntohs(tcph->th_sport);
            port_state_t pstate = PORT_FILTERED;
            
            // Interpret response based on flags and scan mode
            uint8_t flags = tcph->th_flags;
            
            if (state->mode == SCAN_MODE_SYN) {
                if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                    pstate = PORT_OPEN;
                } else if (flags & TH_RST) {
                    pstate = PORT_CLOSED;
                }
            }
            else if (state->mode == SCAN_MODE_ACK || state->mode == SCAN_MODE_WINDOW) {
                if (flags & TH_RST) {
                    // For Window scan, check window size
                    if (state->mode == SCAN_MODE_WINDOW) {
                        if (ntohs(tcph->th_win) > 0) {
                            pstate = PORT_OPEN;
                        } else {
                            pstate = PORT_CLOSED;
                        }
                    } else {
                        pstate = PORT_UNFILTERED;
                    }
                }
            }
            else if (state->mode == SCAN_MODE_FIN || 
                     state->mode == SCAN_MODE_XMAS || 
                     state->mode == SCAN_MODE_NULL ||
                     state->mode == SCAN_MODE_MAIMON) {
                if (flags & TH_RST) {
                    pstate = PORT_CLOSED;
                }
                // No response = open|filtered (handled by timeout)
            }
            
            // Store result
            pthread_mutex_lock(&state->lock);
            if (*state->result_count < state->max_results) {
                port_result_t* r = &state->results[*state->result_count];
                r->port = port;
                r->state = pstate;
                strncpy(r->service, phantom_lookup_service(port), sizeof(r->service) - 1);
                r->banner[0] = '\0';
                r->response_time_us = 0;
                (*state->result_count)++;
            }
            pthread_mutex_unlock(&state->lock);
        }
    }
    
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PORT RANDOMIZATION
 * ═══════════════════════════════════════════════════════════════════════════ */

static void phantom_shuffle_ports(phantom_prng_t* prng, uint16_t* ports, int count) {
    // Fisher-Yates shuffle
    for (int i = count - 1; i > 0; i--) {
        int j = phantom_rand_range(prng, 0, i);
        uint16_t tmp = ports[i];
        ports[i] = ports[j];
        ports[j] = tmp;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAIN STEALTH SCANNER
 * ═══════════════════════════════════════════════════════════════════════════ */

int phantom_scan_ports(phantom_config_t* cfg,
                        port_result_t* results,
                        int max_results,
                        int* result_count,
                        void (*progress_cb)(int current, int total, void* ctx),
                        void* progress_ctx) {
    
    *result_count = 0;
    
    // Create raw socket for sending
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        return -1;
    }
    
    // Enable IP_HDRINCL
    int one = 1;
    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(send_sock);
        return -2;
    }
    
    // Create raw socket for receiving
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock < 0) {
        close(send_sock);
        return -3;
    }
    
    // Get local IP for source
    struct in_addr src_addr;
    if (cfg->spoof_source) {
        src_addr = cfg->spoofed_source;
    } else {
        // Get actual local IP (should be passed in or detected)
        // For now use a placeholder - in real impl, detect from interface
        char local_ip[32];
        extern int get_local_ip(char* ip_buf, int len);
        if (get_local_ip(local_ip, sizeof(local_ip))) {
            inet_pton(AF_INET, local_ip, &src_addr);
        } else {
            src_addr.s_addr = INADDR_ANY;
        }
    }
    
    // Build port list
    int port_count = cfg->port_end - cfg->port_start + 1;
    uint16_t* ports = malloc(port_count * sizeof(uint16_t));
    if (!ports) {
        close(send_sock);
        close(recv_sock);
        return -4;
    }
    
    for (int i = 0; i < port_count; i++) {
        ports[i] = cfg->port_start + i;
    }
    
    // Randomize port order if configured
    if (cfg->randomize_ports) {
        phantom_shuffle_ports(&cfg->prng, ports, port_count);
    }
    
    // Setup listener state
    scan_state_t state = {
        .running = 1,
        .raw_sock = recv_sock,
        .target = cfg->target,
        .results = results,
        .result_count = result_count,
        .max_results = max_results,
        .mode = cfg->mode
    };
    pthread_mutex_init(&state.lock, NULL);
    
    // Start listener thread
    pthread_t listener_thread;
    if (pthread_create(&listener_thread, NULL, phantom_listener_thread, &state) != 0) {
        free(ports);
        close(send_sock);
        close(recv_sock);
        return -5;
    }
    
    // Destination address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr = cfg->target;
    
    char packet[128];
    
    // Scan loop
    for (int i = 0; i < port_count; i++) {
        uint16_t port = ports[i];
        
        // Send decoys first if enabled
        if (cfg->use_decoys) {
            for (int d = 0; d < cfg->num_decoys; d++) {
                int len = phantom_build_tcp_packet(packet, sizeof(packet), 
                                                    cfg, &cfg->decoys[d], port);
                if (len > 0) {
                    sendto(send_sock, packet, len, 0, 
                           (struct sockaddr*)&dest, sizeof(dest));
                    usleep(1000);  // Small delay between decoys
                }
            }
        }
        
        // Send real probe
        if (cfg->use_fragmentation) {
            char frag1[64], frag2[64];
            int frag1_len, frag2_len;
            
            if (phantom_build_fragmented_packet(frag1, &frag1_len, 
                                                frag2, &frag2_len,
                                                cfg, &src_addr, port) == 0) {
                sendto(send_sock, frag1, frag1_len, 0,
                       (struct sockaddr*)&dest, sizeof(dest));
                usleep(500);
                sendto(send_sock, frag2, frag2_len, 0,
                       (struct sockaddr*)&dest, sizeof(dest));
            }
        } else {
            int len = phantom_build_tcp_packet(packet, sizeof(packet), 
                                                cfg, &src_addr, port);
            if (len > 0) {
                sendto(send_sock, packet, len, 0,
                       (struct sockaddr*)&dest, sizeof(dest));
            }
        }
        
        // Progress callback
        if (progress_cb) {
            progress_cb(i + 1, port_count, progress_ctx);
        }
        
        // Adaptive delay
        usleep(phantom_get_delay(&cfg->prng, cfg->timing));
    }
    
    // Wait for final responses
    usleep(cfg->timeout_ms * 1000);
    
    // Cleanup
    state.running = 0;
    pthread_join(listener_thread, NULL);
    pthread_mutex_destroy(&state.lock);
    
    free(ports);
    close(send_sock);
    close(recv_sock);
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  UDP SCANNER
 * ═══════════════════════════════════════════════════════════════════════════ */

int phantom_scan_udp(phantom_config_t* cfg,
                      port_result_t* results,
                      int max_results,
                      int* result_count) {
    
    *result_count = 0;
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = cfg->timeout_ms / 1000;
    tv.tv_usec = (cfg->timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr = cfg->target;
    
    for (uint16_t port = cfg->port_start; port <= cfg->port_end && *result_count < max_results; port++) {
        dest.sin_port = htons(port);
        
        // Send empty UDP packet
        sendto(sock, "", 0, 0, (struct sockaddr*)&dest, sizeof(dest));
        
        // Check for ICMP port unreachable (means closed)
        // This is simplified - full impl would use raw ICMP socket
        char buf[64];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        
        int ret = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
        
        port_result_t* r = &results[*result_count];
        r->port = port;
        r->response_time_us = 0;
        strncpy(r->service, phantom_lookup_service(port), sizeof(r->service) - 1);
        r->banner[0] = '\0';
        
        if (ret > 0) {
            r->state = PORT_OPEN;  // Got response
            (*result_count)++;
        } else if (errno == ECONNREFUSED) {
            r->state = PORT_CLOSED;
            // Don't count closed ports by default
        } else {
            r->state = PORT_OPEN_FILTERED;
            (*result_count)++;
        }
        
        usleep(phantom_get_delay(&cfg->prng, cfg->timing));
    }
    
    close(sock);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  DECOY CONFIGURATION
 * ═══════════════════════════════════════════════════════════════════════════ */

int phantom_add_decoy(phantom_config_t* cfg, const char* ip) {
    if (cfg->num_decoys >= MAX_DECOYS) return -1;
    
    if (inet_pton(AF_INET, ip, &cfg->decoys[cfg->num_decoys]) != 1) {
        return -2;
    }
    
    cfg->num_decoys++;
    cfg->use_decoys = true;
    return 0;
}

// Generate random decoys
int phantom_generate_decoys(phantom_config_t* cfg, int count) {
    if (count > MAX_DECOYS) count = MAX_DECOYS;
    
    for (int i = 0; i < count; i++) {
        // Generate believable IPs (avoid 0.x.x.x, 127.x.x.x, etc.)
        uint8_t octets[4];
        do {
            phantom_get_entropy(&cfg->prng, octets, 4);
            octets[0] = phantom_rand_range(&cfg->prng, 1, 223);  // Avoid reserved ranges
        } while (octets[0] == 10 || octets[0] == 127 || 
                 (octets[0] == 192 && octets[1] == 168) ||
                 (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31));
        
        cfg->decoys[cfg->num_decoys].s_addr = *(uint32_t*)octets;
        cfg->num_decoys++;
    }
    
    cfg->use_decoys = true;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SCAN MODE STRING CONVERSION
 * ═══════════════════════════════════════════════════════════════════════════ */

const char* phantom_mode_to_string(scan_mode_t mode) {
    switch (mode) {
        case SCAN_MODE_SYN:    return "SYN Stealth";
        case SCAN_MODE_ACK:    return "ACK";
        case SCAN_MODE_FIN:    return "FIN";
        case SCAN_MODE_XMAS:   return "XMAS";
        case SCAN_MODE_NULL:   return "NULL";
        case SCAN_MODE_UDP:    return "UDP";
        case SCAN_MODE_WINDOW: return "Window";
        case SCAN_MODE_MAIMON: return "Maimon";
        default:               return "Unknown";
    }
}

scan_mode_t phantom_string_to_mode(const char* str) {
    if (strcasecmp(str, "syn") == 0)    return SCAN_MODE_SYN;
    if (strcasecmp(str, "ack") == 0)    return SCAN_MODE_ACK;
    if (strcasecmp(str, "fin") == 0)    return SCAN_MODE_FIN;
    if (strcasecmp(str, "xmas") == 0)   return SCAN_MODE_XMAS;
    if (strcasecmp(str, "null") == 0)   return SCAN_MODE_NULL;
    if (strcasecmp(str, "udp") == 0)    return SCAN_MODE_UDP;
    if (strcasecmp(str, "window") == 0) return SCAN_MODE_WINDOW;
    if (strcasecmp(str, "maimon") == 0) return SCAN_MODE_MAIMON;
    return SCAN_MODE_SYN;  // Default
}

const char* phantom_timing_to_string(timing_mode_t timing) {
    switch (timing) {
        case TIMING_PARANOID:   return "Paranoid (T0)";
        case TIMING_SNEAKY:     return "Sneaky (T1)";
        case TIMING_POLITE:     return "Polite (T2)";
        case TIMING_NORMAL:     return "Normal (T3)";
        case TIMING_AGGRESSIVE: return "Aggressive (T4)";
        case TIMING_INSANE:     return "Insane (T5)";
        default:                return "Unknown";
    }
}
