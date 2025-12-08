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
    printf(COLOR_CYAN "╔══════════════════════════════════════╗\n");
    printf("║       VANGUARD COMMAND REFERENCE     ║\n");
    printf("╚══════════════════════════════════════╝" COLOR_RESET "\n\n");
    
    printf(COLOR_YELLOW "HYDRA" COLOR_RESET " - Network Discovery\n");
    printf("  hydra networks       Scan nearby WiFi networks\n");
    printf("  hydra devices        Find devices on your network\n");
    printf("  hydra scan <IP>      Port scan a target\n");
    printf("  hydra scan <IP> <start>-<end>  Scan port range\n\n");
    
    printf(COLOR_YELLOW "REAPER" COLOR_RESET " - MITM Attacks\n");
    printf("  reaper poison <target> <gateway>  ARP poison attack\n");
    printf("  reaper stop          Stop ongoing attack\n\n");
    
    printf(COLOR_YELLOW "ZAWARUDO" COLOR_RESET " - Payload Generator\n");
    printf("  zawarudo help        Show payload options\n");
    printf("  zawarudo create ...  Generate Linux payload\n\n");
    
    printf(COLOR_YELLOW "GENERAL" COLOR_RESET "\n");
    printf("  clear                Clear screen\n");
    printf("  help                 Show this help\n");
    printf("  exit                 Quit\n\n");
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
            hydra_scan_devices();
        }
        else if (strncmp(args, "scan", 4) == 0) {
            char target[64] = "";
            int start_port = 1, end_port = 1000;
            
            char* scan_args = args + 4;
            while (*scan_args == ' ') scan_args++;
            
            // Parse: scan <IP> [start-end]
            char range[32] = "";
            if (sscanf(scan_args, "%63s %31s", target, range) >= 1) {
                if (strlen(range) > 0 && strchr(range, '-')) {
                    sscanf(range, "%d-%d", &start_port, &end_port);
                }
                hydra_scan_ports(target, start_port, end_port);
            } else {
                printf(COLOR_RED "[!] Usage: hydra scan <IP> [start-end]" COLOR_RESET "\n");
            }
        }
        else {
            printf(COLOR_YELLOW "[*] HYDRA Commands:" COLOR_RESET "\n");
            printf("    hydra networks  - Scan nearby WiFi\n");
            printf("    hydra devices   - Find LAN devices\n");
            printf("    hydra scan <IP> - Port scan target\n");
        }
        return;
    }
    
    // ─── REAPER COMMANDS ───
    if (strncmp(cmd, "reaper", 6) == 0) {
        char* args = cmd + 6;
        while (*args == ' ') args++;
        
        if (strncmp(args, "poison", 6) == 0) {
            char target[32] = "", gateway[32] = "";
            if (sscanf(args + 6, "%31s %31s", target, gateway) == 2) {
                reaper_poison(target, gateway);
            } else {
                printf(COLOR_RED "[!] Usage: reaper poison <target_ip> <gateway_ip>" COLOR_RESET "\n");
            }
        }
        else if (strncmp(args, "stop", 4) == 0) {
            reaper_stop();
        }
        else {
            printf(COLOR_YELLOW "[*] REAPER Commands:" COLOR_RESET "\n");
            printf("    reaper poison <target> <gateway>\n");
            printf("    reaper stop\n");
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
