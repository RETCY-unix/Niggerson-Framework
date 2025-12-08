/*
 * ═══════════════════════════════════════════════════════════════════════
 *  HYDRA MODULE HEADER - NIGGERSON FRAMEWORK
 *  Network Scanner for Linux
 * ═══════════════════════════════════════════════════════════════════════
 */

#ifndef HYDRA_H
#define HYDRA_H

// ─── FUNCTION PROTOTYPES ────────────────────────────────────────────────

// WiFi Network Discovery
// Scans for nearby WiFi networks using iwlist
// Requires root privileges
void hydra_scan_networks(void);

// Device Discovery
// Scans the local network for connected devices via ARP
// Requires root privileges
void hydra_scan_devices(void);

// Port Scanner
// Performs TCP connect scan on target
// @param target     Target IP address or hostname
// @param start_port First port to scan
// @param end_port   Last port to scan
void hydra_scan_ports(const char* target, int start_port, int end_port);

#endif // HYDRA_H
