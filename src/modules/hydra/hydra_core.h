/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  HYDRA_CORE.H - PHANTOM RECONNAISSANCE ENGINE
 *  APT-Grade Network Scanner Core
 *  Zero Dependencies | Full Stealth | Military Grade
 * ═══════════════════════════════════════════════════════════════════════════
 *  
 *  This header defines the core stealth infrastructure for HYDRA:
 *  - Cryptographic PRNG (no predictable rand())
 *  - Packet fingerprint randomization
 *  - Timing jitter utilities
 *  - Scan configuration structures
 *
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifndef HYDRA_CORE_H
#define HYDRA_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  SCAN MODE DEFINITIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    SCAN_MODE_SYN    = 0x01,   // SYN stealth scan (default)
    SCAN_MODE_ACK    = 0x02,   // ACK scan - firewall mapping
    SCAN_MODE_FIN    = 0x04,   // FIN scan - evades some firewalls
    SCAN_MODE_XMAS   = 0x08,   // XMAS scan - FIN+PSH+URG
    SCAN_MODE_NULL   = 0x10,   // NULL scan - no flags
    SCAN_MODE_UDP    = 0x20,   // UDP scan
    SCAN_MODE_WINDOW = 0x40,   // TCP Window scan
    SCAN_MODE_MAIMON = 0x80    // Maimon scan - FIN+ACK
} scan_mode_t;

typedef enum {
    TIMING_PARANOID  = 0,      // 5+ seconds between probes
    TIMING_SNEAKY    = 1,      // 1-5 seconds between probes  
    TIMING_POLITE    = 2,      // 400ms between probes
    TIMING_NORMAL    = 3,      // Adaptive timing
    TIMING_AGGRESSIVE= 4,      // Fast, less stealthy
    TIMING_INSANE    = 5       // Maximum speed (noisy)
} timing_mode_t;

typedef enum {
    PORT_OPEN       = 1,
    PORT_CLOSED     = 2,
    PORT_FILTERED   = 3,
    PORT_UNFILTERED = 4,
    PORT_OPEN_FILTERED = 5
} port_state_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  CRYPTOGRAPHIC PRNG - USES /dev/urandom
 *  Never use predictable rand() in offensive tools
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t state[4];
    int urandom_fd;
} phantom_prng_t;

// Initialize PRNG with entropy from /dev/urandom
static inline int phantom_prng_init(phantom_prng_t* prng) {
    prng->urandom_fd = open("/dev/urandom", O_RDONLY);
    if (prng->urandom_fd < 0) return -1;
    
    // Seed state from urandom
    if (read(prng->urandom_fd, prng->state, sizeof(prng->state)) != sizeof(prng->state)) {
        close(prng->urandom_fd);
        return -1;
    }
    return 0;
}

static inline void phantom_prng_destroy(phantom_prng_t* prng) {
    if (prng->urandom_fd >= 0) {
        close(prng->urandom_fd);
        prng->urandom_fd = -1;
    }
    // Secure wipe state
    explicit_bzero(prng->state, sizeof(prng->state));
}

// xoshiro256** - Fast, high-quality PRNG
static inline uint64_t phantom_prng_next(phantom_prng_t* prng) {
    const uint64_t result = ((prng->state[1] * 5) << 7 | (prng->state[1] * 5) >> 57) * 9;
    const uint64_t t = prng->state[1] << 17;
    
    prng->state[2] ^= prng->state[0];
    prng->state[3] ^= prng->state[1];
    prng->state[1] ^= prng->state[2];
    prng->state[0] ^= prng->state[3];
    prng->state[2] ^= t;
    prng->state[3] = (prng->state[3] << 45) | (prng->state[3] >> 19);
    
    return result;
}

// Get random bytes directly from urandom (for critical entropy)
static inline int phantom_get_entropy(phantom_prng_t* prng, void* buf, size_t len) {
    return read(prng->urandom_fd, buf, len) == (ssize_t)len ? 0 : -1;
}

// Random integer in range [min, max]
static inline uint32_t phantom_rand_range(phantom_prng_t* prng, uint32_t min, uint32_t max) {
    if (min >= max) return min;
    uint64_t range = (uint64_t)(max - min + 1);
    return min + (uint32_t)(phantom_prng_next(prng) % range);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PACKET FINGERPRINT RANDOMIZATION
 *  Eliminates all static signatures that IDS/IPS can match
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint16_t src_port;      // Randomized source port
    uint16_t ip_id;         // Randomized IP identification
    uint8_t  ttl;           // Randomized TTL (realistic range)
    uint32_t tcp_seq;       // Randomized TCP sequence number
    uint32_t tcp_ack;       // Randomized TCP ack (for ACK scans)
    uint16_t tcp_window;    // Randomized TCP window size
    uint32_t tcp_timestamp; // Randomized TCP timestamp option
} packet_fingerprint_t;

// Generate randomized fingerprint for each packet
static inline void phantom_generate_fingerprint(phantom_prng_t* prng, 
                                                  packet_fingerprint_t* fp) {
    // Source port: ephemeral range (32768-60999) for realism
    fp->src_port = phantom_rand_range(prng, 32768, 60999);
    
    // IP ID: full random
    fp->ip_id = phantom_rand_range(prng, 1, 65535);
    
    // TTL: realistic values (Linux: 64, Windows: 128, some routers: 255)
    // Randomly pick from common values to blend in
    uint8_t ttl_options[] = {64, 64, 64, 128, 128, 255, 63, 127};
    fp->ttl = ttl_options[phantom_rand_range(prng, 0, 7)];
    
    // TCP sequence: full random
    fp->tcp_seq = (uint32_t)phantom_prng_next(prng);
    
    // TCP ack: full random (only used in certain scan types)
    fp->tcp_ack = (uint32_t)phantom_prng_next(prng);
    
    // TCP window: realistic values
    uint16_t window_options[] = {5840, 14600, 29200, 65535, 8192, 16384};
    fp->tcp_window = window_options[phantom_rand_range(prng, 0, 5)];
    
    // TCP timestamp: based on system time with jitter
    fp->tcp_timestamp = (uint32_t)time(NULL) + phantom_rand_range(prng, 0, 1000);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  TIMING JITTER - ADAPTIVE DELAYS
 *  Avoids pattern detection by varying inter-packet delays
 * ═══════════════════════════════════════════════════════════════════════════ */

// Get delay in microseconds based on timing mode
static inline uint32_t phantom_get_delay(phantom_prng_t* prng, timing_mode_t mode) {
    uint32_t base, jitter;
    
    switch (mode) {
        case TIMING_PARANOID:
            base = 5000000;   // 5 seconds
            jitter = 3000000; // ±3 seconds
            break;
        case TIMING_SNEAKY:
            base = 1500000;   // 1.5 seconds
            jitter = 1000000; // ±1 second
            break;
        case TIMING_POLITE:
            base = 400000;    // 400ms
            jitter = 200000;  // ±200ms
            break;
        case TIMING_NORMAL:
            base = 100000;    // 100ms
            jitter = 50000;   // ±50ms
            break;
        case TIMING_AGGRESSIVE:
            base = 10000;     // 10ms
            jitter = 5000;    // ±5ms
            break;
        case TIMING_INSANE:
        default:
            base = 1000;      // 1ms
            jitter = 500;     // ±0.5ms
            break;
    }
    
    // Add random jitter
    int32_t random_jitter = (int32_t)phantom_rand_range(prng, 0, jitter * 2) - jitter;
    uint32_t delay = (uint32_t)((int64_t)base + random_jitter);
    
    return delay > 100 ? delay : 100; // Minimum 100us
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SCAN CONFIGURATION
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_DECOYS 16
#define MAX_PORTS 65535

typedef struct {
    // Target
    struct in_addr target;
    uint16_t port_start;
    uint16_t port_end;
    
    // Scan options
    scan_mode_t mode;
    timing_mode_t timing;
    
    // Stealth options
    bool use_decoys;
    int num_decoys;
    struct in_addr decoys[MAX_DECOYS];
    
    bool use_fragmentation;
    uint16_t fragment_mtu;     // Fragment size (default: 8)
    
    bool randomize_ports;      // Scan ports in random order
    bool randomize_hosts;      // For subnet scans
    
    // Source spoofing (optional)
    bool spoof_source;
    struct in_addr spoofed_source;
    
    // Advanced
    int retries;               // Retransmit count
    int timeout_ms;            // Response timeout
    
    // Internal state
    phantom_prng_t prng;
} phantom_config_t;

// Initialize with secure defaults
static inline int phantom_config_init(phantom_config_t* cfg) {
    memset(cfg, 0, sizeof(*cfg));
    
    cfg->port_start = 1;
    cfg->port_end = 1000;
    cfg->mode = SCAN_MODE_SYN;
    cfg->timing = TIMING_NORMAL;
    cfg->use_decoys = false;
    cfg->use_fragmentation = false;
    cfg->fragment_mtu = 8;
    cfg->randomize_ports = true;
    cfg->randomize_hosts = true;
    cfg->spoof_source = false;
    cfg->retries = 2;
    cfg->timeout_ms = 1000;
    
    return phantom_prng_init(&cfg->prng);
}

static inline void phantom_config_destroy(phantom_config_t* cfg) {
    phantom_prng_destroy(&cfg->prng);
    explicit_bzero(cfg, sizeof(*cfg));
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PORT STATE RESULT
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint16_t port;
    port_state_t state;
    char service[32];
    char banner[256];
    uint32_t response_time_us;
} port_result_t;

/* ═══════════════════════════════════════════════════════════════════════════
 *  OUI DATABASE (Built-in MAC vendor lookup)
 *  Selected common vendors - no external file needed
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t oui[3];
    const char* vendor;
} oui_entry_t;

static const oui_entry_t OUI_DATABASE[] = {
    {{0x00, 0x00, 0x0C}, "Cisco"},
    {{0x00, 0x1A, 0xA0}, "Dell"},
    {{0x00, 0x1B, 0x63}, "Apple"},
    {{0x00, 0x1E, 0xC2}, "Apple"},
    {{0x00, 0x21, 0x6A}, "Intel"},
    {{0x00, 0x23, 0x14}, "Intel"},
    {{0x00, 0x24, 0xD7}, "Intel"},
    {{0x00, 0x25, 0x00}, "Apple"},
    {{0x00, 0x26, 0xBB}, "Apple"},
    {{0x00, 0x50, 0x56}, "VMware"},
    {{0x00, 0x0C, 0x29}, "VMware"},
    {{0x00, 0x1C, 0x42}, "Parallels"},
    {{0x08, 0x00, 0x27}, "VirtualBox"},
    {{0x00, 0x16, 0x3E}, "Xen"},
    {{0x00, 0x03, 0xFF}, "Microsoft"},
    {{0x00, 0x15, 0x5D}, "Microsoft Hyper-V"},
    {{0x00, 0x1A, 0x11}, "Google"},
    {{0x3C, 0x5A, 0xB4}, "Google"},
    {{0xF4, 0xF5, 0xD8}, "Google"},
    {{0x18, 0xAF, 0xF8}, "Raspberry Pi"},
    {{0xB8, 0x27, 0xEB}, "Raspberry Pi"},
    {{0xDC, 0xA6, 0x32}, "Raspberry Pi"},
    {{0xE4, 0x5F, 0x01}, "Raspberry Pi"},
    {{0x00, 0x1E, 0x58}, "D-Link"},
    {{0x00, 0x26, 0x5A}, "D-Link"},
    {{0x00, 0x17, 0x9A}, "D-Link"},
    {{0x00, 0x14, 0xBF}, "Linksys"},
    {{0x00, 0x1A, 0x70}, "Linksys"},
    {{0x00, 0x25, 0x9C}, "Linksys"},
    {{0x00, 0x1F, 0x33}, "Netgear"},
    {{0x00, 0x26, 0xF2}, "Netgear"},
    {{0x20, 0x4E, 0x7F}, "Netgear"},
    {{0x00, 0x18, 0xE7}, "TP-Link"},
    {{0x50, 0xC7, 0xBF}, "TP-Link"},
    {{0xEC, 0x08, 0x6B}, "TP-Link"},
    {{0x00, 0x24, 0x01}, "ASUS"},
    {{0x00, 0x26, 0x18}, "ASUS"},
    {{0x60, 0x45, 0xCB}, "ASUS"},
    {{0x00, 0x1D, 0x7E}, "Cisco-Linksys"},
    {{0x00, 0x24, 0xE8}, "Dell"},
    {{0x00, 0x25, 0x64}, "Dell"},
    {{0xB8, 0xAC, 0x6F}, "Dell"},
    {{0x00, 0x21, 0x5C}, "Intel"},
    {{0x00, 0x22, 0xFB}, "Intel"},
    {{0x00, 0x27, 0x10}, "Intel"},
    {{0x3C, 0xD9, 0x2B}, "HP"},
    {{0x00, 0x1A, 0x4B}, "HP"},
    {{0x00, 0x21, 0x5A}, "HP"},
    {{0x00, 0x1C, 0xC4}, "HP"},
    {{0xAC, 0xDE, 0x48}, "Apple"},
    {{0xBC, 0x52, 0xB7}, "Apple"},
    {{0xF0, 0xDB, 0xE2}, "Apple"},
    {{0x78, 0x31, 0xC1}, "Apple"},
    {{0xA4, 0xD1, 0x8C}, "Apple"},
    {{0x6C, 0x40, 0x08}, "Apple"},
    {{0xE0, 0xC9, 0x7A}, "Samsung"},
    {{0x00, 0x26, 0x37}, "Samsung"},
    {{0x5C, 0x3C, 0x27}, "Samsung"},
    {{0xAC, 0x5F, 0x3E}, "Samsung"},
    {{0xC4, 0x42, 0x02}, "Samsung"},
    {{0x78, 0x47, 0x1D}, "Samsung"},
    {{0x30, 0xCD, 0xA7}, "Samsung"},
    {{0x34, 0xBB, 0x26}, "Samsung"},
    {{0x84, 0x2E, 0x27}, "Samsung"},
    {{0xE8, 0x50, 0x8B}, "Samsung"},
    {{0x00, 0x19, 0xC5}, "Sony"},
    {{0x00, 0x24, 0xBE}, "Sony"},
    {{0x00, 0x1D, 0xBA}, "Sony"},
    {{0x40, 0xB8, 0x37}, "Sony"},
    {{0x00, 0x17, 0xFA}, "Microsoft Xbox"},
    {{0x00, 0x50, 0xF2}, "Microsoft"},
    {{0x7C, 0x1E, 0x52}, "Microsoft"},
    {{0x28, 0x18, 0x78}, "Microsoft"},
    {{0x00, 0x09, 0xBF}, "Nintendo"},
    {{0x00, 0x17, 0xAB}, "Nintendo"},
    {{0x00, 0x19, 0x1D}, "Nintendo"},
    {{0x00, 0x1E, 0x35}, "Nintendo"},
    {{0x00, 0x1F, 0xC5}, "Nintendo"},
    {{0x00, 0x21, 0x47}, "Nintendo"},
    {{0x00, 0x22, 0xAA}, "Nintendo"},
    {{0x00, 0x22, 0xD7}, "Nintendo"},
    {{0x00, 0x23, 0xCC}, "Nintendo"},
    {{0x00, 0x24, 0x44}, "Nintendo"},
    {{0x00, 0x24, 0xF3}, "Nintendo"},
    {{0x00, 0x25, 0xA0}, "Nintendo"},
    {{0xCC, 0xFB, 0x65}, "Nintendo"},
    {{0xE8, 0x4E, 0xCE}, "Nintendo"},
    {{0x34, 0xAF, 0x2C}, "Nintendo"},
    {{0x58, 0xBD, 0xA3}, "Nintendo"},
    {{0x98, 0xB6, 0xE9}, "Nintendo"},
    {{0xA4, 0x5C, 0x27}, "Nintendo"},
    {{0x00, 0x04, 0x9F}, "Freebox"},
    {{0xB8, 0x76, 0x3F}, "Xiaomi"},
    {{0x64, 0xCC, 0x2E}, "Xiaomi"},
    {{0x00, 0x23, 0x68}, "Huawei"},
    {{0x00, 0x25, 0x9E}, "Huawei"},
    {{0x00, 0x46, 0x4B}, "Huawei"},
    {{0x00, 0xE0, 0xFC}, "Huawei"},
    {{0x04, 0x02, 0x1F}, "Huawei"},
    {{0x04, 0xC0, 0x6F}, "Huawei"},
    {{0x04, 0xF9, 0x38}, "Huawei"},
    {{0x08, 0x19, 0xA6}, "Huawei"},
    {{0x08, 0x63, 0x61}, "Huawei"},
    {{0x20, 0x0B, 0xC7}, "Huawei"},
    {{0x28, 0x6E, 0xD4}, "Huawei"},
    {{0x30, 0xD1, 0x7E}, "Huawei"},
    {{0xA8, 0xCA, 0x7B}, "Huawei"},
    {{0xAC, 0xE8, 0x7B}, "Huawei"},
    {{0x00, 0x10, 0xFA}, "Apple"},
    {{0x00, 0x14, 0x51}, "Apple"},
    {{0x00, 0x16, 0xCB}, "Apple"},
    {{0x00, 0x17, 0xF2}, "Apple"},
    {{0x00, 0x19, 0xE3}, "Apple"},
    {{0x00, 0x1B, 0x63}, "Apple"},
    {{0x00, 0x1D, 0x4F}, "Apple"},
    {{0x00, 0x1E, 0x52}, "Apple"},
    {{0x00, 0x1F, 0x5B}, "Apple"},
    {{0x00, 0x1F, 0xF3}, "Apple"},
    {{0x00, 0x21, 0xE9}, "Apple"},
    {{0x00, 0x22, 0x41}, "Apple"},
    {{0x00, 0x23, 0x12}, "Apple"},
    {{0x00, 0x23, 0x32}, "Apple"},
    {{0x00, 0x23, 0x6C}, "Apple"},
    {{0x00, 0x23, 0xDF}, "Apple"},
    {{0x00, 0x24, 0x36}, "Apple"},
    {{0x00, 0x25, 0x4B}, "Apple"},
    {{0x00, 0x25, 0xBC}, "Apple"},
    {{0x00, 0x26, 0x08}, "Apple"},
    {{0x00, 0x26, 0x4A}, "Apple"},
    {{0x00, 0x27, 0x02}, "Haier"},
    {{0x00, 0x13, 0xA9}, "Sony"},
    {{0x00, 0x1D, 0x0D}, "Sony"},
    {{0x00, 0x13, 0x02}, "Intel"},
    {{0x00, 0x13, 0xCE}, "Intel"},
    {{0x00, 0x13, 0xE8}, "Intel"},
    {{0x00, 0x15, 0x00}, "Intel"},
    {{0x00, 0x15, 0x17}, "Intel"},
    {{0x00, 0x16, 0x6F}, "Intel"},
    {{0x00, 0x16, 0x76}, "Intel"},
    {{0x00, 0x16, 0xEA}, "Intel"},
    {{0x00, 0x16, 0xEB}, "Intel"},
    {{0xD0, 0x50, 0x99}, "ASRock"},
    {{0x00, 0xE0, 0x4C}, "Realtek"},
    {{0x52, 0x54, 0x00}, "QEMU/KVM"},
    {{0x00, 0x00, 0x00}, NULL}  // Terminator
};

// Lookup vendor by MAC address
static inline const char* phantom_lookup_oui(const uint8_t* mac) {
    for (int i = 0; OUI_DATABASE[i].vendor != NULL; i++) {
        if (mac[0] == OUI_DATABASE[i].oui[0] &&
            mac[1] == OUI_DATABASE[i].oui[1] &&
            mac[2] == OUI_DATABASE[i].oui[2]) {
            return OUI_DATABASE[i].vendor;
        }
    }
    return "Unknown";
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SERVICE IDENTIFICATION DATABASE
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint16_t port;
    const char* name;
    const char* probe;  // NULL for no probe, else string to send
} service_entry_t;

static const service_entry_t SERVICE_DATABASE[] = {
    {20,    "ftp-data",   NULL},
    {21,    "ftp",        "HELP\r\n"},
    {22,    "ssh",        NULL},
    {23,    "telnet",     NULL},
    {25,    "smtp",       "EHLO probe\r\n"},
    {53,    "dns",        NULL},
    {67,    "dhcp",       NULL},
    {68,    "dhcp-client",NULL},
    {69,    "tftp",       NULL},
    {80,    "http",       "GET / HTTP/1.0\r\n\r\n"},
    {110,   "pop3",       NULL},
    {111,   "rpcbind",    NULL},
    {119,   "nntp",       NULL},
    {123,   "ntp",        NULL},
    {135,   "msrpc",      NULL},
    {137,   "netbios-ns", NULL},
    {138,   "netbios-dgm",NULL},
    {139,   "netbios-ssn",NULL},
    {143,   "imap",       NULL},
    {161,   "snmp",       NULL},
    {162,   "snmptrap",   NULL},
    {389,   "ldap",       NULL},
    {443,   "https",      NULL},
    {445,   "smb",        NULL},
    {465,   "smtps",      NULL},
    {514,   "syslog",     NULL},
    {515,   "printer",    NULL},
    {523,   "ibm-db2",    NULL},
    {587,   "submission", NULL},
    {631,   "ipp",        NULL},
    {636,   "ldaps",      NULL},
    {993,   "imaps",      NULL},
    {995,   "pop3s",      NULL},
    {1080,  "socks",      NULL},
    {1433,  "mssql",      NULL},
    {1434,  "mssql-udp",  NULL},
    {1521,  "oracle",     NULL},
    {1723,  "pptp",       NULL},
    {2049,  "nfs",        NULL},
    {2082,  "cpanel",     NULL},
    {2083,  "cpanel-ssl", NULL},
    {2181,  "zookeeper",  NULL},
    {2222,  "ssh-alt",    NULL},
    {3128,  "squid",      NULL},
    {3306,  "mysql",      NULL},
    {3389,  "rdp",        NULL},
    {5432,  "postgresql", NULL},
    {5672,  "amqp",       NULL},
    {5900,  "vnc",        NULL},
    {5984,  "couchdb",    NULL},
    {6379,  "redis",      NULL},
    {6667,  "irc",        NULL},
    {8000,  "http-alt",   "GET / HTTP/1.0\r\n\r\n"},
    {8080,  "http-proxy", "GET / HTTP/1.0\r\n\r\n"},
    {8443,  "https-alt",  NULL},
    {8888,  "http-alt2",  "GET / HTTP/1.0\r\n\r\n"},
    {9000,  "cslistener", NULL},
    {9090,  "zeus-admin", NULL},
    {9200,  "elasticsearch", "GET / HTTP/1.0\r\n\r\n"},
    {9300,  "elasticsearch-cluster", NULL},
    {11211, "memcached",  NULL},
    {27017, "mongodb",    NULL},
    {27018, "mongodb",    NULL},
    {50000, "db2",        NULL},
    {0,     NULL,         NULL}  // Terminator
};

// Lookup service by port
static inline const char* phantom_lookup_service(uint16_t port) {
    for (int i = 0; SERVICE_DATABASE[i].name != NULL; i++) {
        if (SERVICE_DATABASE[i].port == port) {
            return SERVICE_DATABASE[i].name;
        }
    }
    return "unknown";
}

// Get probe for service
static inline const char* phantom_get_service_probe(uint16_t port) {
    for (int i = 0; SERVICE_DATABASE[i].name != NULL; i++) {
        if (SERVICE_DATABASE[i].port == port) {
            return SERVICE_DATABASE[i].probe;
        }
    }
    return NULL;
}

#endif // HYDRA_CORE_H
