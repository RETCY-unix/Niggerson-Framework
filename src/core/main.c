/*
 * ═══════════════════════════════════════════════════════════════════════
 *  VANGUARD - NIGGERSON FRAMEWORK
 *  Linux-Only Network Security Framework
 *  Main Entry Point
 * ═══════════════════════════════════════════════════════════════════════
 */

#include "../../include/vanguard.h"
#include "../../include/platform.h"

// ─── GLOBAL STATE ───────────────────────────────────────────────────────
static volatile int running = 1;
static char current_interface[32] = "";

// ─── SIGNAL HANDLER ─────────────────────────────────────────────────────
void signal_handler(int sig) {
    if (sig == SIGINT) {
        printf("\n" COLOR_YELLOW "[!] Caught SIGINT - Cleaning up..." COLOR_RESET "\n");
        reaper_stop();
        running = 0;
    }
}

// ─── SHELL OUTPUT FUNCTIONS ─────────────────────────────────────────────
void shell_print(const char* text) {
    printf(COLOR_GREEN "%s" COLOR_RESET "\n", text);
}

void shell_print_color(const char* text, const char* color) {
    printf("%s%s" COLOR_RESET "\n", color, text);
}

void shell_clear(void) {
    printf("\033[2J\033[H");
}

// ─── UTILITY FUNCTIONS ──────────────────────────────────────────────────
int check_root(void) {
    return geteuid() == 0;
}

void get_default_interface(char* iface, int len) {
    FILE* fp = fopen("/proc/net/route", "r");
    if (!fp) {
        strncpy(iface, "wlan0", len);
        return;
    }
    
    char line[256];
    fgets(line, sizeof(line), fp); // Skip header
    
    while (fgets(line, sizeof(line), fp)) {
        char name[32];
        unsigned long dest;
        if (sscanf(line, "%31s %lx", name, &dest) == 2) {
            if (dest == 0) { // Default route
                strncpy(iface, name, len);
                iface[len-1] = '\0';
                fclose(fp);
                return;
            }
        }
    }
    fclose(fp);
    strncpy(iface, "wlan0", len);
}

int get_local_ip(char* ip_buf, int len) {
    char iface[32];
    get_default_interface(iface, sizeof(iface));
    
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return 0;
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            if (strcmp(ifa->ifa_name, iface) == 0) {
                struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
                strncpy(ip_buf, inet_ntoa(addr->sin_addr), len);
                ip_buf[len-1] = '\0';
                freeifaddrs(ifaddr);
                return 1;
            }
        }
    }
    freeifaddrs(ifaddr);
    return 0;
}

int get_gateway_ip(char* gw_buf, int len) {
    FILE* fp = fopen("/proc/net/route", "r");
    if (!fp) return 0;
    
    char line[256];
    fgets(line, sizeof(line), fp); // Skip header
    
    while (fgets(line, sizeof(line), fp)) {
        char name[32];
        unsigned long dest, gw;
        if (sscanf(line, "%31s %lx %lx", name, &dest, &gw) == 3) {
            if (dest == 0 && gw != 0) {
                struct in_addr addr;
                addr.s_addr = gw;
                strncpy(gw_buf, inet_ntoa(addr), len);
                gw_buf[len-1] = '\0';
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

int get_mac_address(const char* iface, unsigned char* mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return 0;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 1;
}

// ─── BANNER ─────────────────────────────────────────────────────────────
void print_banner(void) {
    printf("\n");
    printf(COLOR_GREEN COLOR_BOLD);
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║                                                          ║\n");
    printf("║   ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗   ║\n");
    printf("║   ██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗  ║\n");
    printf("║   ██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║  ║\n");
    printf("║   ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║  ║\n");
    printf("║    ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║  ║\n");
    printf("║     ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝  ║\n");
    printf("║                                                          ║\n");
    printf("║          NIGGERSON FRAMEWORK v%s                  ║\n", VERSION);
    printf("║              [ LINUX EDITION ]                           ║\n");
    printf("║                                                          ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET "\n");
}

void print_help(void) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════════════════════════╗\n");
    printf("║         VANGUARD COMMAND REFERENCE - APT GRADE           ║\n");
    printf("╚══════════════════════════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    printf(COLOR_YELLOW "HYDRA" COLOR_RESET " - Phantom Reconnaissance\n");
    printf("  hydra networks              Scan nearby WiFi networks\n");
    printf("  hydra devices               Find LAN devices (pure ARP)\n");
    printf("  hydra devices -passive      Passive ARP listening\n");
    printf("  hydra scan <IP> [ports]     Stealth port scan\n");
    printf("  hydra scan <IP> -mode <m>   Scan mode: syn,ack,fin,xmas,null,udp\n");
    printf("  hydra scan <IP> -timing <t> Timing: paranoid,sneaky,polite,normal,aggressive,insane\n");
    printf("  hydra scan <IP> -decoys <n> Add n random decoy sources\n");
    printf("  hydra scan <IP> -fragment   Enable packet fragmentation\n");
    printf("  hydra service <IP> <PORT>   Banner grab / version detect\n\n");
    
    printf(COLOR_YELLOW "REAPER" COLOR_RESET " - Silent Interception\n");
    printf("  reaper poison <target> <gateway>    ARP poison (DoS)\n");
    printf("  reaper intercept <target> <gw>      Full MITM + capture\n");
    printf("  reaper harvest <target> <gateway>   Credential harvesting\n");
    printf("  reaper dns <domain> <fake_ip>       Add DNS spoof rule\n");
    printf("  reaper spoof-mac [MAC|random]       Spoof interface MAC\n");
    printf("  reaper restore-mac                  Restore original MAC\n");
    printf("  reaper status                       Show attack stats\n");
    printf("  reaper stop                         Stop + restore ARP\n\n");
    
    printf(COLOR_YELLOW "ZAWARUDO" COLOR_RESET " - Payload Generator\n");
    printf("  zawarudo help        Show payload options\n");
    printf("  zawarudo create ...  Generate Linux payload\n\n");
    
    printf(COLOR_YELLOW "GENERAL" COLOR_RESET "\n");
    printf("  clear                Clear screen\n");
    printf("  help                 Show this help\n");
    printf("  exit                 Quit\n\n");
    
    printf(COLOR_CYAN "STEALTH FEATURES" COLOR_RESET "\n");
    printf("  • Randomized source ports, IP IDs, TTL, TCP seq per packet\n");
    printf("  • Adaptive timing with jitter\n");
    printf("  • No external tool dependencies\n");
    printf("  • Zero child processes / no forensic artifacts\n\n");
}

// ─── COMMAND PARSER ─────────────────────────────────────────────────────
void execute_command(char* cmd) {
    // Trim newline/carriage return
    cmd[strcspn(cmd, "\r\n")] = 0;
    
    // Skip empty commands
    if (strlen(cmd) == 0) return;
    
    // ─── EXIT ───
    if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
        shell_print("[*] Goodbye!");
        running = 0;
        return;
    }
    
    // ─── CLEAR ───
    if (strcmp(cmd, "clear") == 0) {
        shell_clear();
        return;
    }
    
    // ─── HELP ───
    if (strcmp(cmd, "help") == 0) {
        print_help();
        return;
    }
    
    // ─── HYDRA COMMANDS ───
    if (strncmp(cmd, "hydra", 5) == 0) {
        char* args = cmd + 5;
        while (*args == ' ') args++;
        
        if (strncmp(args, "networks", 8) == 0) {
            hydra_scan_networks();
        }
        else if (strncmp(args, "devices", 7) == 0) {
            char* device_args = args + 7;
            while (*device_args == ' ') device_args++;
            hydra_scan_devices(device_args);
        }
        else if (strncmp(args, "service", 7) == 0) {
            // Parse: service <IP> <PORT>
            char target[64] = "";
            int port = 0;
            char* svc_args = args + 7;
            while (*svc_args == ' ') svc_args++;
            
            if (sscanf(svc_args, "%63s %d", target, &port) == 2) {
                hydra_service_detect(target, port);
            } else {
                printf(COLOR_RED "[!] Usage: hydra service <IP> <PORT>" COLOR_RESET "\n");
            }
        }
        else if (strncmp(args, "scan", 4) == 0) {
            char target[64] = "";
            int start_port = 1, end_port = 1000;
            char mode[16] = "syn";
            char timing[16] = "normal";
            int decoys = 0;
            int fragment = 0;
            
            char* scan_args = args + 4;
            while (*scan_args == ' ') scan_args++;
            
            // Parse target and port range
            char range[32] = "";
            sscanf(scan_args, "%63s", target);
            
            // Parse options
            char* opt;
            if ((opt = strstr(scan_args, "-mode "))) sscanf(opt + 6, "%15s", mode);
            if ((opt = strstr(scan_args, "-timing "))) sscanf(opt + 8, "%15s", timing);
            if ((opt = strstr(scan_args, "-decoys "))) sscanf(opt + 8, "%d", &decoys);
            if (strstr(scan_args, "-fragment")) fragment = 1;
            
            // Parse port range (if specified after target)
            char* space = strchr(scan_args, ' ');
            if (space && space[1] >= '0' && space[1] <= '9') {
                sscanf(space + 1, "%d-%d", &start_port, &end_port);
            }
            
            if (strlen(target) > 0 && target[0] != '-') {
                hydra_scan_ports_advanced(target, start_port, end_port, 
                                          mode, timing, decoys, fragment);
            } else {
                printf(COLOR_RED "[!] Usage: hydra scan <IP> [ports] [options]" COLOR_RESET "\n");
                printf(COLOR_YELLOW "Options:" COLOR_RESET "\n");
                printf("  -mode <syn|ack|fin|xmas|null|udp>\n");
                printf("  -timing <0-5 or paranoid|sneaky|polite|normal|aggressive|insane>\n");
                printf("  -decoys <count>\n");
                printf("  -fragment\n");
            }
        }
        else {
            printf(COLOR_YELLOW "[*] HYDRA - Phantom Reconnaissance:" COLOR_RESET "\n");
            printf("    hydra networks           - Scan WiFi\n");
            printf("    hydra devices            - Find LAN devices (pure ARP)\n");
            printf("    hydra devices -passive   - Passive ARP listen\n");
            printf("    hydra scan <IP> [ports]  - Stealth port scan\n");
            printf("    hydra service <IP> <PORT>- Banner/version detect\n");
            printf("  Options: -mode, -timing, -decoys, -fragment\n");
        }
        return;
    }
    
    // ─── REAPER COMMANDS ───
    if (strncmp(cmd, "reaper", 6) == 0) {
        char* args = cmd + 6;
        while (*args == ' ') args++;
        
        if (strncmp(args, "intercept", 9) == 0) {
            char target[32] = "", gateway[32] = "";
            if (sscanf(args + 9, "%31s %31s", target, gateway) == 2) {
                reaper_intercept(target, gateway, REAPER_MODE_FULL);
            } else {
                printf(COLOR_RED "[!] Usage: reaper intercept <target_ip> <gateway_ip>" COLOR_RESET "\n");
            }
        }
        else if (strncmp(args, "poison", 6) == 0) {
            char target[32] = "", gateway[32] = "";
            if (sscanf(args + 6, "%31s %31s", target, gateway) == 2) {
                reaper_poison(target, gateway);
            } else {
                printf(COLOR_RED "[!] Usage: reaper poison <target_ip> <gateway_ip>" COLOR_RESET "\n");
            }
        }
        else if (strncmp(args, "harvest", 7) == 0) {
            char target[32] = "", gateway[32] = "";
            if (sscanf(args + 7, "%31s %31s", target, gateway) == 2) {
                reaper_intercept(target, gateway, REAPER_MODE_DOS | REAPER_MODE_INTERCEPT | REAPER_MODE_HARVEST);
            } else {
                printf(COLOR_RED "[!] Usage: reaper harvest <target_ip> <gateway_ip>" COLOR_RESET "\n");
            }
        }
        else if (strncmp(args, "dns", 3) == 0) {
            char domain[128] = "", ip[32] = "";
            if (sscanf(args + 3, "%127s %31s", domain, ip) == 2) {
                reaper_dns_add(domain, ip);
            } else {
                printf(COLOR_RED "[!] Usage: reaper dns <domain> <fake_ip>" COLOR_RESET "\n");
                printf(COLOR_YELLOW "    Example: reaper dns *.facebook.com 192.168.1.100" COLOR_RESET "\n");
            }
        }
        else if (strncmp(args, "spoof-mac", 9) == 0) {
            char mac[24] = "";
            sscanf(args + 9, "%23s", mac);
            if (strlen(mac) == 0 || strcasecmp(mac, "random") == 0) {
                if (reaper_spoof_mac(NULL) == 0) {
                    printf(COLOR_GREEN "[+] MAC spoofed to random address" COLOR_RESET "\n");
                } else {
                    printf(COLOR_RED "[!] MAC spoofing failed (requires root)" COLOR_RESET "\n");
                }
            } else {
                if (reaper_spoof_mac(mac) == 0) {
                    printf(COLOR_GREEN "[+] MAC spoofed to %s" COLOR_RESET "\n", mac);
                } else {
                    printf(COLOR_RED "[!] MAC spoofing failed" COLOR_RESET "\n");
                }
            }
        }
        else if (strncmp(args, "restore-mac", 11) == 0) {
            if (reaper_restore_mac() == 0) {
                printf(COLOR_GREEN "[+] MAC restored to original" COLOR_RESET "\n");
            } else {
                printf(COLOR_RED "[!] MAC restore failed" COLOR_RESET "\n");
            }
        }
        else if (strncmp(args, "status", 6) == 0) {
            reaper_status();
        }
        else if (strncmp(args, "stop", 4) == 0) {
            reaper_stop();
        }
        else {
            printf(COLOR_YELLOW "[*] REAPER - Silent Interception Engine:" COLOR_RESET "\n");
            printf("    reaper poison <target> <gateway>    ARP poison (DoS mode)\n");
            printf("    reaper intercept <target> <gateway> Full MITM + capture\n");
            printf("    reaper harvest <target> <gateway>   Credential harvesting\n");
            printf("    reaper dns <domain> <fake_ip>       Add DNS spoof rule\n");
            printf("    reaper spoof-mac [MAC|random]       Change interface MAC\n");
            printf("    reaper restore-mac                  Restore original MAC\n");
            printf("    reaper status                       Show attack status\n");
            printf("    reaper stop                         Stop + restore ARP\n");
        }
        return;
    }
    
    // ─── ZAWARUDO COMMANDS ───
    if (strncmp(cmd, "zawarudo", 8) == 0) {
        char* args = cmd + 8;
        while (*args == ' ') args++;
        
        if (strcmp(args, "help") == 0 || strlen(args) == 0) {
            zawarudo_help();
        }
        else if (strncmp(args, "create", 6) == 0) {
            zawarudo_create(args + 6);
        }
        else {
            printf(COLOR_RED "[!] Unknown zawarudo command. Try: zawarudo help" COLOR_RESET "\n");
        }
        return;
    }
    
    // ─── UNKNOWN COMMAND ───
    printf(COLOR_RED "[!] Unknown command: %s (type 'help')" COLOR_RESET "\n", cmd);
}

// ─── MAIN ENTRY POINT ───────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    
    // Seed RNG
    srand(time(NULL));
    
    // Print banner
    print_banner();
    
    // Root check
    if (!check_root()) {
        printf(COLOR_RED COLOR_BOLD);
        printf("╔══════════════════════════════════════╗\n");
        printf("║   ⚠  WARNING: NOT RUNNING AS ROOT   ║\n");
        printf("║   Some features require:             ║\n");
        printf("║       sudo ./vanguard                ║\n");
        printf("╚══════════════════════════════════════╝\n");
        printf(COLOR_RESET "\n");
    } else {
        printf(COLOR_GREEN "[+] Running with root privileges" COLOR_RESET "\n");
    }
    
    // Show network info
    char local_ip[32], gateway[32], iface[32];
    get_default_interface(iface, sizeof(iface));
    
    printf(COLOR_CYAN "[*] Interface: %s" COLOR_RESET "\n", iface);
    
    if (get_local_ip(local_ip, sizeof(local_ip))) {
        printf(COLOR_CYAN "[*] Local IP:  %s" COLOR_RESET "\n", local_ip);
    }
    if (get_gateway_ip(gateway, sizeof(gateway))) {
        printf(COLOR_CYAN "[*] Gateway:   %s" COLOR_RESET "\n", gateway);
    }
    
    printf("\n" COLOR_GREEN "[*] Type 'help' for commands" COLOR_RESET "\n\n");
    
    // Cache interface name
    strncpy(current_interface, iface, sizeof(current_interface));
    
    // Main command loop
    char input[MAX_LINE_LEN];
    
    while (running) {
        printf(COLOR_GREEN COLOR_BOLD "VANGUARD" COLOR_RESET " > ");
        fflush(stdout);
        
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        
        execute_command(input);
    }
    
    printf("\n" COLOR_GREEN "[*] Framework shutdown complete" COLOR_RESET "\n");
    return 0;
}

// ─── MODULE INCLUDES (Unity Build) ──────────────────────────────────────
#include "../modules/hydra/scanner.c"
#include "../modules/reaper/reaper.c"
#include "../modules/zawarudo/zawarudo.c"
