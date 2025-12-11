/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  HYDRA MODULE HEADER - PHANTOM RECONNAISSANCE ENGINE
 *  APT-Grade Network Scanner API
 *  
 *  Features:
 *  - Multi-mode stealth scanning (SYN/ACK/FIN/XMAS/NULL/UDP/Window/Maimon)
 *  - Packet fragmentation & decoy scanning
 *  - Pure ARP device discovery (zero external deps)
 *  - Banner grabbing & version detection
 *  - Built-in OUI & service databases
 *  
 *  Zero Dependencies | Full Stealth | Military Grade
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifndef HYDRA_H
#define HYDRA_H

#include "hydra_core.h"

/* ═══════════════════════════════════════════════════════════════════════════
 *  SCAN MODES (from hydra_core.h)
 *  - SCAN_MODE_SYN     : SYN stealth scan (default, most reliable)
 *  - SCAN_MODE_ACK     : ACK scan for firewall mapping
 *  - SCAN_MODE_FIN     : FIN scan (evades some stateless firewalls)
 *  - SCAN_MODE_XMAS    : XMAS scan (FIN+PSH+URG flags)
 *  - SCAN_MODE_NULL    : NULL scan (no flags set)
 *  - SCAN_MODE_UDP     : UDP scan
 *  - SCAN_MODE_WINDOW  : TCP Window scan
 *  - SCAN_MODE_MAIMON  : Maimon scan (FIN+ACK)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════════
 *  TIMING MODES (from hydra_core.h)  
 *  - TIMING_PARANOID   : T0 - 5+ seconds between probes
 *  - TIMING_SNEAKY     : T1 - 1-5 seconds between probes
 *  - TIMING_POLITE     : T2 - 400ms between probes
 *  - TIMING_NORMAL     : T3 - 100ms, adaptive timing
 *  - TIMING_AGGRESSIVE : T4 - 10ms, fast
 *  - TIMING_INSANE     : T5 - 1ms, maximum speed
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════════
 *  HIGH-LEVEL SCANNER API
 *  These are the main functions called from the shell interface
 * ═══════════════════════════════════════════════════════════════════════════ */

// WiFi network discovery (requires wireless interface)
void hydra_scan_networks(void);

// Device discovery on local network
// Uses pure ARP - no external tools, no ping
// Options parsed from args: -passive, -timeout <sec>
void hydra_scan_devices(const char* args);

// Port scanner with APT-grade stealth
// Supports: -mode <syn|ack|fin|xmas|null|udp|window|maimon>
//           -timing <0-5 or paranoid|sneaky|polite|normal|aggressive|insane>
//           -decoys <count> for random decoys
//           -fragment for packet fragmentation
void hydra_scan_ports(const char* target, int start_port, int end_port);

// Advanced port scan with full options
void hydra_scan_ports_advanced(const char* target, 
                                int start_port, 
                                int end_port,
                                const char* mode,
                                const char* timing,
                                int decoy_count,
                                bool fragment);

// Service detection / banner grabbing
// Usage: hydra service <IP> <PORT>
void hydra_service_detect(const char* target, int port);

// Batch service scan on all open ports
void hydra_service_scan(const char* target, int start_port, int end_port);

/* ═══════════════════════════════════════════════════════════════════════════
 *  LOW-LEVEL STEALTH SCANNER API
 *  For advanced usage and scripting
 * ═══════════════════════════════════════════════════════════════════════════ */

// Initialize scan configuration with stealth defaults
// Returns 0 on success, -1 on failure
int phantom_config_init(phantom_config_t* cfg);

// Destroy and securely wipe configuration
void phantom_config_destroy(phantom_config_t* cfg);

// Add decoy IP address for spoofed scanning
int phantom_add_decoy(phantom_config_t* cfg, const char* ip);

// Generate random believable decoy IPs
int phantom_generate_decoys(phantom_config_t* cfg, int count);

// Execute stealth port scan
// Returns number of open ports found, or negative on error
int phantom_scan_ports(phantom_config_t* cfg,
                        port_result_t* results,
                        int max_results,
                        int* result_count,
                        void (*progress_cb)(int current, int total, void* ctx),
                        void* progress_ctx);

// UDP scan
int phantom_scan_udp(phantom_config_t* cfg,
                      port_result_t* results,
                      int max_results,
                      int* result_count);

// Scan mode string conversion
const char* phantom_mode_to_string(scan_mode_t mode);
scan_mode_t phantom_string_to_mode(const char* str);
const char* phantom_timing_to_string(timing_mode_t timing);

/* ═══════════════════════════════════════════════════════════════════════════
 *  LOW-LEVEL ARP SCANNER API
 * ═══════════════════════════════════════════════════════════════════════════ */

// Device info structure (defined in hydra_arp.c)
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

// Active ARP scan - sends ARP requests to all hosts
int phantom_arp_scan(const char* interface,
                      device_info_t* devices,
                      int max_devices,
                      int* device_count,
                      void (*progress_cb)(int current, int total, void* ctx),
                      void* progress_ctx);

// Passive ARP sniffer - listens without sending
int phantom_arp_passive(const char* interface,
                         device_info_t* devices,
                         int max_devices,
                         int* device_count,
                         int timeout_seconds,
                         volatile int* stop_flag);

// Resolve single IP to MAC
int phantom_arp_resolve(const char* interface,
                         struct in_addr target_ip,
                         uint8_t* mac_out,
                         int timeout_ms);

// Format MAC address to string
void phantom_format_mac(const uint8_t* mac, char* buf, int buflen);

// Lookup MAC vendor
const char* phantom_lookup_oui(const uint8_t* mac);

/* ═══════════════════════════════════════════════════════════════════════════
 *  LOW-LEVEL SERVICE DETECTION API
 * ═══════════════════════════════════════════════════════════════════════════ */

// Service result structure
typedef struct {
    uint16_t port;
    char service_name[32];
    char product[64];
    char version[32];
    char info[128];
    char banner[512];
    bool is_ssl;
    int response_time_ms;
} service_result_t;

// Vulnerability signature
typedef struct {
    const char* product;
    const char* max_vulnerable_version;
    const char* cve;
    const char* description;
} vuln_signature_t;

// Grab banner from single port
int phantom_grab_banner(struct in_addr target,
                         uint16_t port,
                         service_result_t* result,
                         int timeout_ms);

// Batch service scan
int phantom_service_scan(struct in_addr target,
                          const uint16_t* ports,
                          int port_count,
                          service_result_t* results,
                          int max_results,
                          int* result_count,
                          int timeout_ms);

// Check for known vulnerabilities based on version
const vuln_signature_t* phantom_check_vulnerabilities(const service_result_t* result);

// Compare version strings
int phantom_compare_versions(const char* v1, const char* v2);

// Lookup service name by port
const char* phantom_lookup_service(uint16_t port);

#endif // HYDRA_H
