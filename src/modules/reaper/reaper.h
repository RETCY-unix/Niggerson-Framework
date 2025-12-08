/*
 * ═══════════════════════════════════════════════════════════════════════
 *  REAPER MODULE HEADER - NIGGERSON FRAMEWORK
 *  MITM / ARP Poisoning for Linux
 * ═══════════════════════════════════════════════════════════════════════
 */

#ifndef REAPER_H
#define REAPER_H

// ─── FUNCTION PROTOTYPES ────────────────────────────────────────────────

// Start ARP Poison Attack
// Sends spoofed ARP packets to intercept traffic between target and gateway
// Requires root privileges
// @param target_ip  IP of the target to poison
// @param gateway_ip IP of the gateway (router)
void reaper_poison(const char* target_ip, const char* gateway_ip);

// Stop ARP Poison Attack
// Stops the poisoning thread and cleans up
void reaper_stop(void);

// Check if Reaper is Running
// @return 1 if running, 0 if stopped
int reaper_is_running(void);

#endif // REAPER_H
