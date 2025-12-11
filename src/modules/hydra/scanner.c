/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  HYDRA SCANNER - PHANTOM RECONNAISSANCE ENGINE
 *  APT-Grade Network Scanner Shell Interface
 *  
 *  This file provides the command-line interface for the HYDRA module
 *  and integrates all submodules:
 *  - hydra_stealth.c : Multi-mode stealth port scanner
 *  - hydra_arp.c     : Pure ARP device discovery
 *  - hydra_service.c : Banner grabbing & version detection
 *  
 *  Zero Dependencies | Full Stealth | Military Grade
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include "hydra_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netdb.h>

// Include implementation files (unity build)
#include "hydra_stealth.c"
#include "hydra_arp.c"
#include "hydra_service.c"

// External color definitions from main
extern const char* COLOR_RESET;
extern const char* COLOR_RED;
extern const char* COLOR_GREEN;
extern const char* COLOR_YELLOW;
extern const char* COLOR_BLUE;
extern const char* COLOR_MAGENTA;
extern const char* COLOR_CYAN;
extern const char* COLOR_WHITE;
extern const char* COLOR_BOLD;

// Use macros from vanguard.h
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

/* ═══════════════════════════════════════════════════════════════════════════
 *  PROGRESS CALLBACK FOR VISUAL FEEDBACK
 * ═══════════════════════════════════════════════════════════════════════════ */

static void scan_progress_cb(int current, int total, void* ctx) {
    (void)ctx;
    
    // Update every 5% or every 100 items
    if (current % (total / 20 + 1) == 0 || current % 100 == 0) {
        int percent = (current * 100) / total;
        printf("\r" COLOR_YELLOW "[*] Progress: %d/%d (%d%%)" COLOR_RESET "        ", 
               current, total, percent);
        fflush(stdout);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  WIFI NETWORK SCANNER
 *  Uses nl80211 netlink for native scanning
 * ═══════════════════════════════════════════════════════════════════════════ */

void hydra_scan_networks(void) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════════╗\n");
    printf("║      HYDRA - PHANTOM WiFi SCANNER        ║\n");
    printf("╚══════════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    // For now, use iw command as nl80211 direct implementation is very complex
    // This is a fallback - full nl80211 implementation would be ~500 lines
    printf(COLOR_YELLOW "[*] Scanning wireless networks..." COLOR_RESET "\n\n");
    
    // Get wireless interface
    char iface[32] = "wlan0";
    extern void get_default_interface(char* iface, int len);
    get_default_interface(iface, sizeof(iface));
    
    // Try to find wireless interface from /proc/net/wireless
    FILE* fp = fopen("/proc/net/wireless", "r");
    if (fp) {
        char line[256];
        fgets(line, sizeof(line), fp);  // Skip header 1
        fgets(line, sizeof(line), fp);  // Skip header 2
        if (fgets(line, sizeof(line), fp)) {
            sscanf(line, "%31s", iface);
            // Remove trailing colon
            char* colon = strchr(iface, ':');
            if (colon) *colon = '\0';
        }
        fclose(fp);
    }
    
    printf(COLOR_YELLOW "[*] Interface: %s" COLOR_RESET "\n", iface);
    
    // Use iw for scan (fallback)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iw dev %s scan 2>/dev/null | grep -E 'SSID:|signal:|BSS ' | "
             "awk '/BSS/{bss=$2} /signal/{sig=$2} /SSID:/{print bss, sig, $2}'", iface);
    
    printf(COLOR_GREEN "%-20s %-18s %-10s" COLOR_RESET "\n", "SSID", "BSSID", "SIGNAL");
    printf("─────────────────────────────────────────────────────\n");
    
    fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 50) {
            char bssid[24], ssid[48];
            float signal;
            if (sscanf(line, "%23s %f %47s", bssid, &signal, ssid) >= 2) {
                if (strlen(ssid) == 0) strcpy(ssid, "[Hidden]");
                printf("%-20s %-18s %.0f dBm\n", ssid, bssid, signal);
                count++;
            }
        }
        pclose(fp);
        
        printf("─────────────────────────────────────────────────────\n");
        printf(COLOR_GREEN "[+] Networks found: %d" COLOR_RESET "\n\n", count);
    } else {
        printf(COLOR_RED "[!] Scan failed. Run as root with wireless interface available." COLOR_RESET "\n\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  DEVICE DISCOVERY (PURE ARP - NO PING)
 * ═══════════════════════════════════════════════════════════════════════════ */

void hydra_scan_devices(const char* args) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════════╗\n");
    printf("║      HYDRA - PHANTOM DEVICE SCANNER      ║\n");
    printf("║          Pure ARP | Zero Evidence        ║\n");
    printf("╚══════════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    // Check for root
    extern int check_root(void);
    if (!check_root()) {
        printf(COLOR_RED "[!] Device scanning requires ROOT privileges!" COLOR_RESET "\n\n");
        return;
    }
    
    // Parse args
    bool passive = false;
    int timeout = 30;
    
    if (args) {
        if (strstr(args, "-passive")) passive = true;
        const char* t = strstr(args, "-timeout ");
        if (t) sscanf(t + 9, "%d", &timeout);
    }
    
    // Get interface info
    char iface[32];
    extern void get_default_interface(char* iface, int len);
    get_default_interface(iface, sizeof(iface));
    
    char our_ip[32], gateway[32];
    extern int get_local_ip(char* ip_buf, int len);
    extern int get_gateway_ip(char* gw_buf, int len);
    
    get_local_ip(our_ip, sizeof(our_ip));
    get_gateway_ip(gateway, sizeof(gateway));
    
    printf(COLOR_YELLOW "[*] Interface: %s" COLOR_RESET "\n", iface);
    printf(COLOR_YELLOW "[*] Your IP:   %s" COLOR_RESET "\n", our_ip);
    printf(COLOR_YELLOW "[*] Gateway:   %s" COLOR_RESET "\n", gateway);
    printf(COLOR_YELLOW "[*] Mode:      %s" COLOR_RESET "\n\n", passive ? "PASSIVE (listening)" : "ACTIVE (ARP sweep)");
    
    // Allocate results
    #define MAX_DEVICES 256
    device_info_t* devices = malloc(MAX_DEVICES * sizeof(device_info_t));
    if (!devices) {
        printf(COLOR_RED "[!] Memory allocation failed!" COLOR_RESET "\n\n");
        return;
    }
    
    int device_count = 0;
    int ret;
    
    if (passive) {
        printf(COLOR_YELLOW "[*] Passive listening for %d seconds..." COLOR_RESET "\n", timeout);
        printf(COLOR_YELLOW "[*] Press Ctrl+C to stop early" COLOR_RESET "\n\n");
        
        volatile int stop = 0;
        ret = phantom_arp_passive(iface, devices, MAX_DEVICES, &device_count, timeout, &stop);
    } else {
        printf(COLOR_YELLOW "[*] Sending ARP probes..." COLOR_RESET "\n\n");
        ret = phantom_arp_scan(iface, devices, MAX_DEVICES, &device_count, scan_progress_cb, NULL);
        printf("\n");  // Clear progress line
    }
    
    if (ret < 0) {
        printf(COLOR_RED "[!] Scan failed with error %d" COLOR_RESET "\n\n", ret);
        free(devices);
        return;
    }
    
    // Display results
    printf("\n" COLOR_GREEN "%-16s %-18s %-16s %s" COLOR_RESET "\n", 
           "IP ADDRESS", "MAC ADDRESS", "VENDOR", "TYPE");
    printf("────────────────────────────────────────────────────────────────────\n");
    
    for (int i = 0; i < device_count; i++) {
        device_info_t* d = &devices[i];
        
        char mac_str[20];
        phantom_format_mac(d->mac, mac_str, sizeof(mac_str));
        
        const char* type = "";
        const char* color = COLOR_WHITE;
        
        if (d->is_gateway) {
            type = "[ROUTER]";
            color = COLOR_YELLOW;
        } else if (d->is_self) {
            type = "[YOU]";
            color = COLOR_GREEN;
        }
        
        // Truncate vendor to fit
        char vendor[17];
        strncpy(vendor, d->vendor, 16);
        vendor[16] = '\0';
        
        printf("%s%-16s %-18s %-16s %s" COLOR_RESET "\n", 
               color,
               inet_ntoa(d->ip), 
               mac_str, 
               vendor,
               type);
    }
    
    printf("────────────────────────────────────────────────────────────────────\n");
    printf(COLOR_GREEN "[+] Devices discovered: %d" COLOR_RESET "\n", device_count);
    printf(COLOR_CYAN "[*] No ping used - pure ARP, zero child processes" COLOR_RESET "\n\n");
    
    if (device_count > 1) {
        printf(COLOR_CYAN "[*] To attack a device:" COLOR_RESET "\n");
        printf("    reaper poison <TARGET_IP> %s\n\n", gateway);
    }
    
    free(devices);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PORT SCANNER - APT GRADE
 * ═══════════════════════════════════════════════════════════════════════════ */

void hydra_scan_ports(const char* target, int start_port, int end_port) {
    hydra_scan_ports_advanced(target, start_port, end_port, "syn", "normal", 0, false);
}

void hydra_scan_ports_advanced(const char* target, 
                                int start_port, 
                                int end_port,
                                const char* mode,
                                const char* timing,
                                int decoy_count,
                                bool fragment) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════════╗\n");
    printf("║      HYDRA - PHANTOM PORT SCANNER        ║\n");
    printf("║    Randomized Fingerprints | Zero Trace  ║\n");
    printf("╚══════════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    // Check root
    extern int check_root(void);
    if (!check_root()) {
        printf(COLOR_RED "[!] Stealth scanning requires ROOT privileges!" COLOR_RESET "\n\n");
        return;
    }
    
    // Validate target
    if (!target || strlen(target) == 0) {
        printf(COLOR_RED "[!] Usage: hydra scan <IP> [start-end]" COLOR_RESET "\n\n");
        return;
    }
    
    // Initialize config
    phantom_config_t cfg;
    if (phantom_config_init(&cfg) < 0) {
        printf(COLOR_RED "[!] Failed to initialize scan config!" COLOR_RESET "\n\n");
        return;
    }
    
    // Resolve target
    if (inet_pton(AF_INET, target, &cfg.target) != 1) {
        struct hostent* host = gethostbyname(target);
        if (!host) {
            printf(COLOR_RED "[!] Cannot resolve: %s" COLOR_RESET "\n\n", target);
            phantom_config_destroy(&cfg);
            return;
        }
        memcpy(&cfg.target, host->h_addr_list[0], host->h_length);
    }
    
    // Set options
    cfg.port_start = start_port > 0 ? start_port : 1;
    cfg.port_end = end_port > 0 ? end_port : 1000;
    cfg.mode = phantom_string_to_mode(mode ? mode : "syn");
    
    // Parse timing
    if (timing) {
        if (strcasecmp(timing, "paranoid") == 0 || strcmp(timing, "0") == 0)
            cfg.timing = TIMING_PARANOID;
        else if (strcasecmp(timing, "sneaky") == 0 || strcmp(timing, "1") == 0)
            cfg.timing = TIMING_SNEAKY;
        else if (strcasecmp(timing, "polite") == 0 || strcmp(timing, "2") == 0)
            cfg.timing = TIMING_POLITE;
        else if (strcasecmp(timing, "normal") == 0 || strcmp(timing, "3") == 0)
            cfg.timing = TIMING_NORMAL;
        else if (strcasecmp(timing, "aggressive") == 0 || strcmp(timing, "4") == 0)
            cfg.timing = TIMING_AGGRESSIVE;
        else if (strcasecmp(timing, "insane") == 0 || strcmp(timing, "5") == 0)
            cfg.timing = TIMING_INSANE;
    }
    
    // Decoys
    if (decoy_count > 0) {
        phantom_generate_decoys(&cfg, decoy_count);
    }
    
    // Fragmentation
    cfg.use_fragmentation = fragment;
    
    // Get local IP
    char local_ip[32];
    extern int get_local_ip(char* ip_buf, int len);
    get_local_ip(local_ip, sizeof(local_ip));
    
    // Display scan info
    printf(COLOR_YELLOW "[*] Target:     %s" COLOR_RESET "\n", inet_ntoa(cfg.target));
    printf(COLOR_YELLOW "[*] Ports:      %d - %d (%d ports)" COLOR_RESET "\n", 
           cfg.port_start, cfg.port_end, cfg.port_end - cfg.port_start + 1);
    printf(COLOR_YELLOW "[*] Mode:       %s" COLOR_RESET "\n", phantom_mode_to_string(cfg.mode));
    printf(COLOR_YELLOW "[*] Timing:     %s" COLOR_RESET "\n", phantom_timing_to_string(cfg.timing));
    
    if (cfg.use_decoys) {
        printf(COLOR_YELLOW "[*] Decoys:     %d random IPs" COLOR_RESET "\n", cfg.num_decoys);
    }
    if (cfg.use_fragmentation) {
        printf(COLOR_YELLOW "[*] Fragments:  ENABLED (IDS evasion)" COLOR_RESET "\n");
    }
    
    printf(COLOR_YELLOW "[*] Source:     %s (randomized per-packet)" COLOR_RESET "\n\n", local_ip);
    
    // Allocate results
    #define MAX_RESULTS 65536
    port_result_t* results = malloc(MAX_RESULTS * sizeof(port_result_t));
    if (!results) {
        printf(COLOR_RED "[!] Memory allocation failed!" COLOR_RESET "\n\n");
        phantom_config_destroy(&cfg);
        return;
    }
    
    int result_count = 0;
    time_t start_time = time(NULL);
    
    // Execute scan
    int ret;
    if (cfg.mode == SCAN_MODE_UDP) {
        ret = phantom_scan_udp(&cfg, results, MAX_RESULTS, &result_count);
    } else {
        ret = phantom_scan_ports(&cfg, results, MAX_RESULTS, &result_count, 
                                  scan_progress_cb, NULL);
    }
    
    printf("\n\n");  // Clear progress line
    
    if (ret < 0) {
        printf(COLOR_RED "[!] Scan failed with error %d" COLOR_RESET "\n\n", ret);
        free(results);
        phantom_config_destroy(&cfg);
        return;
    }
    
    // Display results
    printf(COLOR_GREEN "[+] Open ports:" COLOR_RESET "\n");
    printf("─────────────────────────────────────────────────────\n");
    printf(COLOR_GREEN "%-8s %-12s %-12s %s" COLOR_RESET "\n", 
           "PORT", "STATE", "SERVICE", "RESPONSE");
    printf("─────────────────────────────────────────────────────\n");
    
    int open_count = 0;
    for (int i = 0; i < result_count; i++) {
        port_result_t* r = &results[i];
        
        if (r->state == PORT_OPEN || r->state == PORT_OPEN_FILTERED) {
            const char* state_str = r->state == PORT_OPEN ? "open" : "open|filtered";
            printf("%-8d %-12s %-12s\n", r->port, state_str, r->service);
            open_count++;
        }
    }
    
    if (open_count == 0) {
        printf("  (no open ports found)\n");
    }
    
    time_t elapsed = time(NULL) - start_time;
    if (elapsed == 0) elapsed = 1;
    
    printf("─────────────────────────────────────────────────────\n");
    printf(COLOR_GREEN "[+] Scan complete: %d open ports found (%lds)" COLOR_RESET "\n", 
           open_count, elapsed);
    
    // Stealth info
    printf(COLOR_CYAN "[*] Stealth features active:" COLOR_RESET "\n");
    printf("    ✓ Randomized source ports (32768-60999)\n");
    printf("    ✓ Randomized IP IDs\n");
    printf("    ✓ Randomized TTL values\n");
    printf("    ✓ Randomized TCP sequence numbers\n");
    printf("    ✓ Variable inter-packet timing\n");
    if (cfg.randomize_ports) {
        printf("    ✓ Randomized port scan order\n");
    }
    if (cfg.use_decoys) {
        printf("    ✓ Decoy packets from %d fake sources\n", cfg.num_decoys);
    }
    if (cfg.use_fragmentation) {
        printf("    ✓ TCP header fragmentation\n");
    }
    printf("\n");
    
    // Suggest service detection
    if (open_count > 0) {
        printf(COLOR_CYAN "[*] For service detection:" COLOR_RESET "\n");
        printf("    hydra service %s <PORT>\n\n", target);
    }
    
    free(results);
    phantom_config_destroy(&cfg);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SERVICE DETECTION / BANNER GRAB
 * ═══════════════════════════════════════════════════════════════════════════ */

void hydra_service_detect(const char* target, int port) {
    printf("\n");
    printf(COLOR_MAGENTA "╔══════════════════════════════════════════╗\n");
    printf("║      HYDRA - SERVICE DETECTION           ║\n");
    printf("╚══════════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    if (!target || port <= 0 || port > 65535) {
        printf(COLOR_RED "[!] Usage: hydra service <IP> <PORT>" COLOR_RESET "\n\n");
        return;
    }
    
    struct in_addr addr;
    if (inet_pton(AF_INET, target, &addr) != 1) {
        struct hostent* host = gethostbyname(target);
        if (!host) {
            printf(COLOR_RED "[!] Cannot resolve: %s" COLOR_RESET "\n\n", target);
            return;
        }
        memcpy(&addr, host->h_addr_list[0], host->h_length);
    }
    
    printf(COLOR_YELLOW "[*] Target: %s:%d" COLOR_RESET "\n", inet_ntoa(addr), port);
    printf(COLOR_YELLOW "[*] Grabbing banner..." COLOR_RESET "\n\n");
    
    service_result_t result;
    int ret = phantom_grab_banner(addr, port, &result, 5000);
    
    if (ret < 0) {
        printf(COLOR_RED "[!] Connection failed (error %d)" COLOR_RESET "\n\n", ret);
        return;
    }
    
    printf(COLOR_GREEN "┌─ SERVICE INFO ─────────────────────────────────────┐" COLOR_RESET "\n");
    printf("│ Port:     %d\n", result.port);
    printf("│ Service:  %s\n", result.service_name[0] ? result.service_name : "unknown");
    
    if (result.product[0]) {
        printf("│ Product:  %s", result.product);
        if (result.version[0]) {
            printf(" %s", result.version);
        }
        printf("\n");
    }
    
    if (result.info[0]) {
        printf("│ Info:     %s\n", result.info);
    }
    
    if (result.is_ssl) {
        printf("│ SSL/TLS:  " COLOR_GREEN "DETECTED" COLOR_RESET "\n");
    }
    
    printf("│ Response: %d ms\n", result.response_time_ms);
    printf(COLOR_GREEN "└────────────────────────────────────────────────────┘" COLOR_RESET "\n");
    
    // Check for vulnerabilities
    const vuln_signature_t* vuln = phantom_check_vulnerabilities(&result);
    if (vuln) {
        printf("\n");
        printf(COLOR_RED "┌─ ⚠ POTENTIAL VULNERABILITY ──────────────────────┐" COLOR_RESET "\n");
        printf(COLOR_RED "│" COLOR_RESET " CVE:         %s\n", vuln->cve);
        printf(COLOR_RED "│" COLOR_RESET " Description: %s\n", vuln->description);
        printf(COLOR_RED "│" COLOR_RESET " Affected:    %s <= %s\n", vuln->product, vuln->max_vulnerable_version);
        printf(COLOR_RED "└───────────────────────────────────────────────────┘" COLOR_RESET "\n");
    }
    
    // Display raw banner if available
    if (result.banner[0]) {
        printf("\n" COLOR_YELLOW "Raw Banner:" COLOR_RESET "\n");
        printf("─────────────────────────────────────────────────────\n");
        
        // Print first 200 chars, replace control chars
        char banner_clean[256];
        int j = 0;
        for (int i = 0; result.banner[i] && j < 200; i++) {
            char c = result.banner[i];
            if (c >= 32 || c == '\n') {
                banner_clean[j++] = c;
            } else if (c == '\r') {
                // Skip
            } else {
                banner_clean[j++] = '.';
            }
        }
        banner_clean[j] = '\0';
        printf("%s\n", banner_clean);
        printf("─────────────────────────────────────────────────────\n");
    }
    
    printf("\n");
}

void hydra_service_scan(const char* target, int start_port, int end_port) {
    printf("\n");
    printf(COLOR_MAGENTA "╔══════════════════════════════════════════╗\n");
    printf("║      HYDRA - BATCH SERVICE SCAN          ║\n");
    printf("╚══════════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    if (!target) {
        printf(COLOR_RED "[!] Usage: hydra services <IP> [start-end]" COLOR_RESET "\n\n");
        return;
    }
    
    struct in_addr addr;
    if (inet_pton(AF_INET, target, &addr) != 1) {
        struct hostent* host = gethostbyname(target);
        if (!host) {
            printf(COLOR_RED "[!] Cannot resolve: %s" COLOR_RESET "\n\n", target);
            return;
        }
        memcpy(&addr, host->h_addr_list[0], host->h_length);
    }
    
    if (start_port <= 0) start_port = 1;
    if (end_port <= 0) end_port = 1000;
    
    printf(COLOR_YELLOW "[*] Target: %s" COLOR_RESET "\n", inet_ntoa(addr));
    printf(COLOR_YELLOW "[*] Ports:  %d - %d" COLOR_RESET "\n\n", start_port, end_port);
    
    // Build port list
    int port_count = end_port - start_port + 1;
    uint16_t* ports = malloc(port_count * sizeof(uint16_t));
    if (!ports) {
        printf(COLOR_RED "[!] Memory error" COLOR_RESET "\n\n");
        return;
    }
    
    for (int i = 0; i < port_count; i++) {
        ports[i] = start_port + i;
    }
    
    service_result_t* results = malloc(port_count * sizeof(service_result_t));
    if (!results) {
        free(ports);
        printf(COLOR_RED "[!] Memory error" COLOR_RESET "\n\n");
        return;
    }
    
    int result_count = 0;
    
    printf(COLOR_GREEN "%-8s %-15s %-12s %s" COLOR_RESET "\n", 
           "PORT", "PRODUCT", "VERSION", "INFO");
    printf("─────────────────────────────────────────────────────────────────\n");
    
    for (int i = 0; i < port_count; i++) {
        service_result_t r;
        if (phantom_grab_banner(addr, ports[i], &r, 2000) == 0) {
            if (r.product[0] || r.banner[0]) {
                printf("%-8d %-15s %-12s %s\n", 
                       r.port, 
                       r.product[0] ? r.product : "-",
                       r.version[0] ? r.version : "-",
                       r.info);
                results[result_count++] = r;
            }
        }
        
        // Progress
        if (i % 50 == 0) {
            printf("\r" COLOR_YELLOW "[*] Scanning... %d/%d" COLOR_RESET "        \r", i, port_count);
            fflush(stdout);
        }
    }
    
    printf("─────────────────────────────────────────────────────────────────\n");
    printf(COLOR_GREEN "[+] Services detected: %d" COLOR_RESET "\n\n", result_count);
    
    free(ports);
    free(results);
}
