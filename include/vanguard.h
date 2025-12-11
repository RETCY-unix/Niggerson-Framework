/*
 * ═══════════════════════════════════════════════════════════════════════
 *  VANGUARD.H - NIGGERSON FRAMEWORK
 *  Linux-Only Network Security Framework
 * ═══════════════════════════════════════════════════════════════════════
 */

#ifndef VANGUARD_H
#define VANGUARD_H

// ─── LINUX SYSTEM HEADERS ───────────────────────────────────────────────
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

// Network headers
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>

// ─── CONFIGURATION ──────────────────────────────────────────────────────
#define VERSION "2.0-LINUX"
#define MAX_HISTORY 50
#define MAX_LINE_LEN 1024
#define MAX_PORTS 65535

// ─── ANSI COLORS ────────────────────────────────────────────────────────
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

// ─── CORE FUNCTION PROTOTYPES ───────────────────────────────────────────

// Shell output
void shell_print(const char* text);
void shell_print_color(const char* text, const char* color);
void shell_clear(void);

// ─── HYDRA MODULE (Phantom Reconnaissance) ──────────────────────────────
void hydra_scan_networks(void);                    // WiFi network discovery
void hydra_scan_devices(const char* args);         // ARP device discovery (supports -passive)
void hydra_scan_ports(const char* target, int start_port, int end_port);
void hydra_scan_ports_advanced(const char* target, 
                                int start_port, 
                                int end_port,
                                const char* mode,      // syn,ack,fin,xmas,null,udp
                                const char* timing,    // paranoid,sneaky,polite,normal,aggressive,insane
                                int decoy_count,       // Number of random decoys
                                bool fragment);        // Enable fragmentation
void hydra_service_detect(const char* target, int port);  // Banner grab / version detect
void hydra_service_scan(const char* target, int start_port, int end_port);

// ─── REAPER MODULE (MITM / ARP Poison) ──────────────────────────────────
void reaper_poison(const char* target_ip, const char* gateway_ip);
void reaper_stop(void);
int  reaper_is_running(void);

// ─── ZAWARUDO MODULE (Linux Payload Generator) ──────────────────────────
void zawarudo_create(const char* args);
void zawarudo_help(void);

// ─── UTILITY FUNCTIONS ──────────────────────────────────────────────────
int  check_root(void);
void get_default_interface(char* iface, int len);
int  get_local_ip(char* ip_buf, int len);
int  get_gateway_ip(char* gw_buf, int len);
int  get_mac_address(const char* iface, unsigned char* mac);

#endif // VANGUARD_H
