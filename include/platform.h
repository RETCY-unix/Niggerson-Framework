/*
 * ═══════════════════════════════════════════════════════════════════════
 *  PLATFORM.H - NIGGERSON FRAMEWORK  
 *  Linux-Only Platform Definitions
 * ═══════════════════════════════════════════════════════════════════════
 */

#ifndef PLATFORM_H
#define PLATFORM_H

// ─── PLATFORM IDENTIFICATION ────────────────────────────────────────────
#define PLATFORM_LINUX 1
#define PLATFORM_NAME "Linux"

// ─── COMPILE-TIME CHECK ─────────────────────────────────────────────────
#ifdef _WIN32
    #error "This framework is Linux-only. Windows is not supported."
#endif

// ─── LINUX SYSTEM HEADERS ───────────────────────────────────────────────
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <fcntl.h>
#include <errno.h>

// ─── TYPE DEFINITIONS ───────────────────────────────────────────────────
typedef int socket_t;
#define INVALID_SOCK -1
#define closesock close
#define sleep_ms(x) usleep((x) * 1000)

// Windows type compatibility (for any ported code)
typedef unsigned char  BYTE;
typedef unsigned int   DWORD;
typedef unsigned long  ULONG;

// ─── NETWORK INITIALIZATION ─────────────────────────────────────────────
// Linux doesn't need network initialization like Windows WSAStartup
static inline int init_network(void) {
    return 1; // Always succeeds on Linux
}

static inline void cleanup_network(void) {
    // Nothing to clean up on Linux
}

// ─── IP FORWARDING CONTROL ──────────────────────────────────────────────
static inline int enable_ip_forward(void) {
    FILE* fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (!fp) return 0;
    fprintf(fp, "1");
    fclose(fp);
    return 1;
}

static inline int disable_ip_forward(void) {
    FILE* fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (!fp) return 0;
    fprintf(fp, "0");
    fclose(fp);
    return 1;
}

#endif // PLATFORM_H
