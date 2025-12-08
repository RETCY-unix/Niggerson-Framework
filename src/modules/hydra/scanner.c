/*
 * ═══════════════════════════════════════════════════════════════════════
 *  HYDRA MODULE - NIGGERSON FRAMEWORK
 *  Network Scanner for Linux
 *  - WiFi Network Discovery (iwlist/iw)
 *  - Device Discovery (ARP scan)
 *  - Port Scanner (raw sockets)
 * ═══════════════════════════════════════════════════════════════════════
 */

#include "../../include/vanguard.h"
#include "../../include/platform.h"
#include <time.h>

// ─── WIFI NETWORK SCANNER ───────────────────────────────────────────────
void hydra_scan_networks(void) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════╗\n");
    printf("║      HYDRA - WiFi SCANNER            ║\n");
    printf("╚══════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    char iface[32];
    get_default_interface(iface, sizeof(iface));
    
    printf(COLOR_YELLOW "[*] Interface: %s" COLOR_RESET "\n", iface);
    printf(COLOR_YELLOW "[*] Scanning for networks (requires root)..." COLOR_RESET "\n\n");
    
    // Try iwlist first (more common)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), 
        "iwlist %s scan 2>/dev/null | grep -E 'ESSID|Address|Channel:|Quality|Encryption'",
        iface);
    
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        printf(COLOR_RED "[!] Failed to scan. Run as root: sudo ./vanguard" COLOR_RESET "\n");
        return;
    }
    
    char line[512];
    char ssid[64] = "";
    char bssid[32] = "";
    char channel[16] = "";
    char quality[32] = "";
    char security[32] = "OPEN";
    int count = 0;
    
    printf(COLOR_GREEN "%-24s %-18s %-5s %-12s %s" COLOR_RESET "\n",
           "SSID", "BSSID", "CH", "QUALITY", "SECURITY");
    printf("────────────────────────────────────────────────────────────────────\n");
    
    while (fgets(line, sizeof(line), fp)) {
        // Parse BSSID
        if (strstr(line, "Address:")) {
            char* p = strstr(line, "Address:");
            if (p) {
                p += 8;
                while (*p == ' ') p++;
                strncpy(bssid, p, 17);
                bssid[17] = '\0';
            }
        }
        // Parse Channel
        else if (strstr(line, "Channel:")) {
            char* p = strstr(line, "Channel:");
            if (p) {
                p += 8;
                strncpy(channel, p, 5);
                channel[strcspn(channel, "\r\n ")] = '\0';
            }
        }
        // Parse Quality
        else if (strstr(line, "Quality")) {
            char* p = strstr(line, "Quality=");
            if (p) {
                p += 8;
                strncpy(quality, p, 20);
                quality[strcspn(quality, " ")] = '\0';
            }
        }
        // Parse Encryption
        else if (strstr(line, "Encryption key:on")) {
            strcpy(security, "WPA/WPA2");
        }
        else if (strstr(line, "Encryption key:off")) {
            strcpy(security, "OPEN");
        }
        // Parse ESSID (last field, triggers output)
        else if (strstr(line, "ESSID:")) {
            char* p = strstr(line, "ESSID:\"");
            if (p) {
                p += 7;
                strncpy(ssid, p, 60);
                ssid[strcspn(ssid, "\"\r\n")] = '\0';
                if (strlen(ssid) == 0) strcpy(ssid, "[Hidden]");
                
                // Output this network
                if (strlen(bssid) > 0) {
                    printf("%-24s %-18s %-5s %-12s %s\n",
                           ssid, bssid, channel, quality, security);
                    count++;
                    
                    // Reset for next network
                    bssid[0] = '\0';
                    strcpy(security, "OPEN");
                }
            }
        }
    }
    
    pclose(fp);
    
    printf("────────────────────────────────────────────────────────────────────\n");
    printf(COLOR_GREEN "[+] Networks found: %d" COLOR_RESET "\n\n", count);
    
    if (count == 0) {
        printf(COLOR_YELLOW "[!] No networks found. Ensure:\n");
        printf("    1. Running as root (sudo)\n");
        printf("    2. WiFi interface is up\n");
        printf("    3. wireless-tools package installed" COLOR_RESET "\n\n");
    }
}

// ─── DEVICE SCANNER ─────────────────────────────────────────────────────
void hydra_scan_devices(void) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════╗\n");
    printf("║      HYDRA - DEVICE SCANNER          ║\n");
    printf("╚══════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    char iface[32], our_ip[32], gateway[32], base_ip[32];
    get_default_interface(iface, sizeof(iface));
    
    if (!get_local_ip(our_ip, sizeof(our_ip))) {
        printf(COLOR_RED "[!] Not connected to any network!" COLOR_RESET "\n");
        return;
    }
    
    get_gateway_ip(gateway, sizeof(gateway));
    
    // Extract base IP (e.g., "192.168.1.")
    strncpy(base_ip, our_ip, sizeof(base_ip));
    char* last_dot = strrchr(base_ip, '.');
    if (last_dot) *(last_dot + 1) = '\0';
    
    printf(COLOR_YELLOW "[*] Interface: %s" COLOR_RESET "\n", iface);
    printf(COLOR_YELLOW "[*] Your IP:   %s" COLOR_RESET "\n", our_ip);
    printf(COLOR_YELLOW "[*] Gateway:   %s" COLOR_RESET "\n", gateway);
    printf(COLOR_YELLOW "[*] Subnet:    %s0/24" COLOR_RESET "\n\n", base_ip);
    
    printf(COLOR_YELLOW "[*] Pinging subnet (this takes ~30s)..." COLOR_RESET "\n");
    
    // Fast parallel ping sweep
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "for i in $(seq 1 254); do ping -c 1 -W 1 %s$i &>/dev/null & done; wait 2>/dev/null",
        base_ip);
    system(cmd);
    
    printf(COLOR_YELLOW "[*] Reading ARP table..." COLOR_RESET "\n\n");
    
    // Read ARP table
    FILE* fp = fopen("/proc/net/arp", "r");
    if (!fp) {
        printf(COLOR_RED "[!] Cannot read ARP table!" COLOR_RESET "\n");
        return;
    }
    
    printf(COLOR_GREEN "%-18s %-20s %s" COLOR_RESET "\n", "IP ADDRESS", "MAC ADDRESS", "TYPE");
    printf("────────────────────────────────────────────────────────────────\n");
    
    int found = 0;
    char line[256];
    fgets(line, sizeof(line), fp); // Skip header
    
    while (fgets(line, sizeof(line), fp)) {
        char ip[32], hw_type[8], flags[8], mac[32], mask[8], dev[32];
        if (sscanf(line, "%31s %7s %7s %31s %7s %31s", ip, hw_type, flags, mac, mask, dev) >= 4) {
            // Check if on our subnet and has valid MAC
            if (strncmp(ip, base_ip, strlen(base_ip)) == 0 &&
                strcmp(mac, "00:00:00:00:00:00") != 0) {
                
                const char* type = "";
                const char* color = COLOR_WHITE;
                
                if (strcmp(ip, gateway) == 0) {
                    type = "[ROUTER]";
                    color = COLOR_YELLOW;
                }
                else if (strcmp(ip, our_ip) == 0) {
                    type = "[YOU]";
                    color = COLOR_GREEN;
                }
                
                printf("%s%-18s %-20s %s" COLOR_RESET "\n", color, ip, mac, type);
                found++;
            }
        }
    }
    fclose(fp);
    
    printf("────────────────────────────────────────────────────────────────\n");
    printf(COLOR_GREEN "[+] Devices found: %d" COLOR_RESET "\n\n", found);
    
    if (found > 1) {
        printf(COLOR_CYAN "[*] To attack a device:" COLOR_RESET "\n");
        printf("    reaper poison <TARGET_IP> %s\n\n", gateway);
    }
}

// ─── PORT SCANNER ───────────────────────────────────────────────────────
void hydra_scan_ports(const char* target, int start_port, int end_port) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════╗\n");
    printf("║      HYDRA - PORT SCANNER            ║\n");
    printf("╚══════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    if (!target || strlen(target) == 0) {
        printf(COLOR_RED "[!] Usage: hydra scan <IP> [start-end]" COLOR_RESET "\n");
        return;
    }
    
    // Validate port range
    if (start_port < 1) start_port = 1;
    if (end_port > 65535) end_port = 65535;
    if (start_port > end_port) {
        int tmp = start_port;
        start_port = end_port;
        end_port = tmp;
    }
    
    printf(COLOR_YELLOW "[*] Target: %s" COLOR_RESET "\n", target);
    printf(COLOR_YELLOW "[*] Ports:  %d - %d" COLOR_RESET "\n\n", start_port, end_port);
    
    // Resolve target
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    
    if (inet_pton(AF_INET, target, &addr.sin_addr) != 1) {
        // Try DNS resolution
        struct hostent* host = gethostbyname(target);
        if (!host) {
            printf(COLOR_RED "[!] Cannot resolve: %s" COLOR_RESET "\n", target);
            return;
        }
        memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
    }
    
    printf(COLOR_GREEN "[+] Open ports:" COLOR_RESET "\n");
    printf("────────────────────────────────────────\n");
    
    int open_count = 0;
    time_t start_time = time(NULL);
    
    for (int port = start_port; port <= end_port; port++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        // Set non-blocking with timeout
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms timeout
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        addr.sin_port = htons(port);
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // Port is open!
            const char* service = "";
            switch (port) {
                case 21:   service = "FTP"; break;
                case 22:   service = "SSH"; break;
                case 23:   service = "Telnet"; break;
                case 25:   service = "SMTP"; break;
                case 53:   service = "DNS"; break;
                case 80:   service = "HTTP"; break;
                case 110:  service = "POP3"; break;
                case 135:  service = "MSRPC"; break;
                case 139:  service = "NetBIOS"; break;
                case 143:  service = "IMAP"; break;
                case 443:  service = "HTTPS"; break;
                case 445:  service = "SMB"; break;
                case 993:  service = "IMAPS"; break;
                case 995:  service = "POP3S"; break;
                case 1433: service = "MSSQL"; break;
                case 1521: service = "Oracle"; break;
                case 3306: service = "MySQL"; break;
                case 3389: service = "RDP"; break;
                case 5432: service = "PostgreSQL"; break;
                case 5900: service = "VNC"; break;
                case 6379: service = "Redis"; break;
                case 8080: service = "HTTP-Proxy"; break;
                case 8443: service = "HTTPS-Alt"; break;
                case 27017: service = "MongoDB"; break;
            }
            
            printf(COLOR_GREEN "  %-6d %s" COLOR_RESET "\n", port, service);
            open_count++;
        }
        
        close(sock);
        
        // Progress indicator every 500 ports
        if ((port - start_port) % 500 == 0 && port > start_port) {
            printf("\r" COLOR_YELLOW "[*] Scanned %d/%d ports..." COLOR_RESET, 
                   port - start_port, end_port - start_port + 1);
            fflush(stdout);
        }
    }
    
    time_t elapsed = time(NULL) - start_time;
    if (elapsed == 0) elapsed = 1;
    
    printf("────────────────────────────────────────\n");
    printf(COLOR_GREEN "[+] Scan complete: %d open ports (%lds)" COLOR_RESET "\n\n", 
           open_count, elapsed);
}
