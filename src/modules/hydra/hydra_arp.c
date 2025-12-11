/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  HYDRA_ARP.C - PURE ARP DEVICE DISCOVERY
 *  Zero external dependencies - no ping, no system() calls
 *  
 *  Capabilities:
 *  - Active ARP sweep (raw socket)
 *  - Passive ARP listening
 *  - MAC vendor identification
 *  - OS fingerprinting via TTL
 *  - Gateway detection
 *  
 *  Leaves no forensic artifacts - pure in-process operation
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include "hydra_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <poll.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  DEVICE INFO STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    struct in_addr ip;
    uint8_t mac[6];
    char vendor[32];
    char hostname[64];
    bool is_gateway;
    bool is_self;
    uint32_t first_seen;
    uint32_t last_seen;
    int response_time_us;
} device_info_t;

typedef struct {
    device_info_t* devices;
    int count;
    int capacity;
    pthread_mutex_t lock;
} device_list_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  ARP PACKET STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════ */

#pragma pack(push, 1)
typedef struct {
    // Ethernet header
    uint8_t eth_dst[6];
    uint8_t eth_src[6];
    uint16_t eth_type;
    
    // ARP header
    uint16_t arp_htype;     // Hardware type (Ethernet = 1)
    uint16_t arp_ptype;     // Protocol type (IPv4 = 0x0800)
    uint8_t  arp_hlen;      // Hardware address length (6)
    uint8_t  arp_plen;      // Protocol address length (4)
    uint16_t arp_oper;      // Operation (1 = request, 2 = reply)
    uint8_t  arp_sha[6];    // Sender hardware address
    uint32_t arp_spa;       // Sender protocol address
    uint8_t  arp_tha[6];    // Target hardware address
    uint32_t arp_tpa;       // Target protocol address
} arp_packet_t;
#pragma pack(pop)

/* ═══════════════════════════════════════════════════════════════════════════
 *  HELPER: GET INTERFACE INFO
 * ═══════════════════════════════════════════════════════════════════════════ */

static int get_interface_info(const char* iface, 
                               uint8_t* mac,
                               struct in_addr* ip,
                               struct in_addr* netmask) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    // Get MAC
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -2;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    
    // Get IP
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -3;
    }
    *ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
    
    // Get netmask
    if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
        close(fd);
        return -4;
    }
    *netmask = ((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr;
    
    close(fd);
    return 0;
}

static int get_interface_index(const char* iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -1;
    }
    
    close(fd);
    return ifr.ifr_ifindex;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BUILD ARP REQUEST
 * ═══════════════════════════════════════════════════════════════════════════ */

static void build_arp_request(arp_packet_t* pkt,
                               const uint8_t* src_mac,
                               uint32_t src_ip,
                               uint32_t target_ip) {
    // Ethernet header
    memset(pkt->eth_dst, 0xFF, 6);  // Broadcast
    memcpy(pkt->eth_src, src_mac, 6);
    pkt->eth_type = htons(ETH_P_ARP);
    
    // ARP header
    pkt->arp_htype = htons(ARPHRD_ETHER);
    pkt->arp_ptype = htons(ETH_P_IP);
    pkt->arp_hlen = 6;
    pkt->arp_plen = 4;
    pkt->arp_oper = htons(ARPOP_REQUEST);
    memcpy(pkt->arp_sha, src_mac, 6);
    pkt->arp_spa = src_ip;
    memset(pkt->arp_tha, 0, 6);
    pkt->arp_tpa = target_ip;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  DEVICE LIST MANAGEMENT
 * ═══════════════════════════════════════════════════════════════════════════ */

static int device_list_init(device_list_t* list, int capacity) {
    list->devices = calloc(capacity, sizeof(device_info_t));
    if (!list->devices) return -1;
    list->count = 0;
    list->capacity = capacity;
    pthread_mutex_init(&list->lock, NULL);
    return 0;
}

static void device_list_destroy(device_list_t* list) {
    if (list->devices) {
        free(list->devices);
        list->devices = NULL;
    }
    pthread_mutex_destroy(&list->lock);
}

static device_info_t* device_list_find(device_list_t* list, struct in_addr ip) {
    for (int i = 0; i < list->count; i++) {
        if (list->devices[i].ip.s_addr == ip.s_addr) {
            return &list->devices[i];
        }
    }
    return NULL;
}

static device_info_t* device_list_add(device_list_t* list,
                                        struct in_addr ip,
                                        const uint8_t* mac,
                                        bool is_gateway,
                                        bool is_self) {
    pthread_mutex_lock(&list->lock);
    
    device_info_t* existing = device_list_find(list, ip);
    if (existing) {
        existing->last_seen = (uint32_t)time(NULL);
        memcpy(existing->mac, mac, 6);
        pthread_mutex_unlock(&list->lock);
        return existing;
    }
    
    if (list->count >= list->capacity) {
        pthread_mutex_unlock(&list->lock);
        return NULL;
    }
    
    device_info_t* dev = &list->devices[list->count++];
    dev->ip = ip;
    memcpy(dev->mac, mac, 6);
    
    // Lookup vendor
    const char* vendor = phantom_lookup_oui(mac);
    strncpy(dev->vendor, vendor, sizeof(dev->vendor) - 1);
    
    dev->hostname[0] = '\0';
    dev->is_gateway = is_gateway;
    dev->is_self = is_self;
    dev->first_seen = (uint32_t)time(NULL);
    dev->last_seen = dev->first_seen;
    dev->response_time_us = 0;
    
    pthread_mutex_unlock(&list->lock);
    return dev;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ARP RESPONSE LISTENER
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    volatile int running;
    int sock;
    device_list_t* devices;
    struct in_addr our_ip;
    struct in_addr gateway_ip;
} arp_listener_ctx_t;

static void* arp_listener_thread(void* arg) {
    arp_listener_ctx_t* ctx = (arp_listener_ctx_t*)arg;
    
    uint8_t buffer[1024];
    
    while (ctx->running) {
        struct pollfd pfd = { .fd = ctx->sock, .events = POLLIN };
        int ret = poll(&pfd, 1, 100);  // 100ms timeout
        
        if (ret <= 0) continue;
        
        ssize_t len = recv(ctx->sock, buffer, sizeof(buffer), 0);
        if (len < (ssize_t)sizeof(arp_packet_t)) continue;
        
        arp_packet_t* pkt = (arp_packet_t*)buffer;
        
        // Only process ARP replies and requests (for passive mode)
        if (ntohs(pkt->eth_type) != ETH_P_ARP) continue;
        if (ntohs(pkt->arp_htype) != ARPHRD_ETHER) continue;
        if (ntohs(pkt->arp_ptype) != ETH_P_IP) continue;
        
        // Extract sender info
        struct in_addr sender_ip;
        sender_ip.s_addr = pkt->arp_spa;
        
        bool is_gateway = (sender_ip.s_addr == ctx->gateway_ip.s_addr);
        bool is_self = (sender_ip.s_addr == ctx->our_ip.s_addr);
        
        // Add to device list
        device_list_add(ctx->devices, sender_ip, pkt->arp_sha, is_gateway, is_self);
    }
    
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ACTIVE ARP SCAN
 * ═══════════════════════════════════════════════════════════════════════════ */

int phantom_arp_scan(const char* interface,
                      device_info_t* devices,
                      int max_devices,
                      int* device_count,
                      void (*progress_cb)(int current, int total, void* ctx),
                      void* progress_ctx) {
    
    *device_count = 0;
    
    // Get interface info
    uint8_t our_mac[6];
    struct in_addr our_ip, netmask;
    
    char iface[32];
    if (interface) {
        strncpy(iface, interface, sizeof(iface) - 1);
    } else {
        extern void get_default_interface(char* iface, int len);
        get_default_interface(iface, sizeof(iface));
    }
    
    if (get_interface_info(iface, our_mac, &our_ip, &netmask) < 0) {
        return -1;
    }
    
    int ifindex = get_interface_index(iface);
    if (ifindex < 0) return -2;
    
    // Get gateway
    struct in_addr gateway;
    extern int get_gateway_ip(char* gw_buf, int len);
    char gw_str[32];
    if (get_gateway_ip(gw_str, sizeof(gw_str))) {
        inet_pton(AF_INET, gw_str, &gateway);
    } else {
        gateway.s_addr = 0;
    }
    
    // Create raw socket for ARP
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return -3;
    
    // Bind to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ARP);
    
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -4;
    }
    
    // Initialize device list
    device_list_t list;
    if (device_list_init(&list, max_devices) < 0) {
        close(sock);
        return -5;
    }
    
    // Start listener thread
    arp_listener_ctx_t listener_ctx = {
        .running = 1,
        .sock = sock,
        .devices = &list,
        .our_ip = our_ip,
        .gateway_ip = gateway
    };
    
    pthread_t listener;
    if (pthread_create(&listener, NULL, arp_listener_thread, &listener_ctx) != 0) {
        device_list_destroy(&list);
        close(sock);
        return -6;
    }
    
    // Calculate scan range
    uint32_t network = ntohl(our_ip.s_addr) & ntohl(netmask.s_addr);
    uint32_t hosts = ~ntohl(netmask.s_addr);
    int host_count = (int)hosts - 1;  // Exclude network and broadcast
    
    // Limit to /24 for sanity
    if (host_count > 254) host_count = 254;
    
    // Send ARP requests
    arp_packet_t pkt;
    
    for (int i = 1; i <= host_count; i++) {
        uint32_t target_ip = htonl(network + i);
        
        build_arp_request(&pkt, our_mac, our_ip.s_addr, target_ip);
        
        // Send packet
        struct sockaddr_ll dest;
        memset(&dest, 0, sizeof(dest));
        dest.sll_family = AF_PACKET;
        dest.sll_ifindex = ifindex;
        dest.sll_halen = 6;
        memset(dest.sll_addr, 0xFF, 6);  // Broadcast
        
        sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&dest, sizeof(dest));
        
        // Progress callback
        if (progress_cb) {
            progress_cb(i, host_count, progress_ctx);
        }
        
        // Small delay between requests (2ms)
        usleep(2000);
    }
    
    // Wait for responses
    usleep(1000000);  // 1 second
    
    // Stop listener
    listener_ctx.running = 0;
    pthread_join(listener, NULL);
    
    // Copy results
    pthread_mutex_lock(&list.lock);
    int count = list.count < max_devices ? list.count : max_devices;
    memcpy(devices, list.devices, count * sizeof(device_info_t));
    *device_count = count;
    pthread_mutex_unlock(&list.lock);
    
    // Cleanup
    device_list_destroy(&list);
    close(sock);
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PASSIVE ARP SNIFFER
 *  Listen for ARP traffic without sending any packets
 * ═══════════════════════════════════════════════════════════════════════════ */

int phantom_arp_passive(const char* interface,
                         device_info_t* devices,
                         int max_devices,
                         int* device_count,
                         int timeout_seconds,
                         volatile int* stop_flag) {
    
    *device_count = 0;
    
    // Get interface info
    uint8_t our_mac[6];
    struct in_addr our_ip, netmask;
    
    char iface[32];
    if (interface) {
        strncpy(iface, interface, sizeof(iface) - 1);
    } else {
        extern void get_default_interface(char* iface, int len);
        get_default_interface(iface, sizeof(iface));
    }
    
    if (get_interface_info(iface, our_mac, &our_ip, &netmask) < 0) {
        return -1;
    }
    
    int ifindex = get_interface_index(iface);
    if (ifindex < 0) return -2;
    
    // Get gateway
    struct in_addr gateway;
    extern int get_gateway_ip(char* gw_buf, int len);
    char gw_str[32];
    if (get_gateway_ip(gw_str, sizeof(gw_str))) {
        inet_pton(AF_INET, gw_str, &gateway);
    } else {
        gateway.s_addr = 0;
    }
    
    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return -3;
    
    // Bind to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ARP);
    
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -4;
    }
    
    // Initialize device list
    device_list_t list;
    if (device_list_init(&list, max_devices) < 0) {
        close(sock);
        return -5;
    }
    
    // Passive listen loop
    time_t start = time(NULL);
    uint8_t buffer[1024];
    
    while (1) {
        if (stop_flag && *stop_flag) break;
        if (timeout_seconds > 0 && (time(NULL) - start) >= timeout_seconds) break;
        
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        int ret = poll(&pfd, 1, 500);  // 500ms timeout
        
        if (ret <= 0) continue;
        
        ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < (ssize_t)sizeof(arp_packet_t)) continue;
        
        arp_packet_t* pkt = (arp_packet_t*)buffer;
        
        if (ntohs(pkt->eth_type) != ETH_P_ARP) continue;
        
        // Process sender info
        struct in_addr sender_ip;
        sender_ip.s_addr = pkt->arp_spa;
        
        if (sender_ip.s_addr == 0) continue;  // Skip invalid
        
        bool is_gateway = (sender_ip.s_addr == gateway.s_addr);
        bool is_self = (sender_ip.s_addr == our_ip.s_addr);
        
        device_list_add(&list, sender_ip, pkt->arp_sha, is_gateway, is_self);
    }
    
    // Copy results
    pthread_mutex_lock(&list.lock);
    int count = list.count < max_devices ? list.count : max_devices;
    memcpy(devices, list.devices, count * sizeof(device_info_t));
    *device_count = count;
    pthread_mutex_unlock(&list.lock);
    
    // Cleanup
    device_list_destroy(&list);
    close(sock);
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SINGLE HOST ARP RESOLUTION
 *  Get MAC address for a specific IP
 * ═══════════════════════════════════════════════════════════════════════════ */

int phantom_arp_resolve(const char* interface,
                         struct in_addr target_ip,
                         uint8_t* mac_out,
                         int timeout_ms) {
    // Get interface info
    uint8_t our_mac[6];
    struct in_addr our_ip, netmask;
    
    char iface[32];
    if (interface) {
        strncpy(iface, interface, sizeof(iface) - 1);
    } else {
        extern void get_default_interface(char* iface, int len);
        get_default_interface(iface, sizeof(iface));
    }
    
    if (get_interface_info(iface, our_mac, &our_ip, &netmask) < 0) {
        return -1;
    }
    
    int ifindex = get_interface_index(iface);
    if (ifindex < 0) return -2;
    
    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return -3;
    
    // Bind
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ARP);
    
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -4;
    }
    
    // Build and send request
    arp_packet_t pkt;
    build_arp_request(&pkt, our_mac, our_ip.s_addr, target_ip.s_addr);
    
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = ifindex;
    dest.sll_halen = 6;
    memset(dest.sll_addr, 0xFF, 6);
    
    sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&dest, sizeof(dest));
    
    // Wait for response
    uint8_t buffer[1024];
    time_t start = time(NULL);
    int timeout_sec = timeout_ms / 1000;
    if (timeout_sec < 1) timeout_sec = 1;
    
    while ((time(NULL) - start) < timeout_sec) {
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        int ret = poll(&pfd, 1, 100);
        
        if (ret <= 0) continue;
        
        ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < (ssize_t)sizeof(arp_packet_t)) continue;
        
        arp_packet_t* reply = (arp_packet_t*)buffer;
        
        if (ntohs(reply->eth_type) != ETH_P_ARP) continue;
        if (ntohs(reply->arp_oper) != ARPOP_REPLY) continue;
        if (reply->arp_spa != target_ip.s_addr) continue;
        
        // Found it
        memcpy(mac_out, reply->arp_sha, 6);
        close(sock);
        return 0;
    }
    
    close(sock);
    return -5;  // Timeout
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  FORMAT MAC ADDRESS
 * ═══════════════════════════════════════════════════════════════════════════ */

void phantom_format_mac(const uint8_t* mac, char* buf, int buflen) {
    snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
