/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  HYDRA_SERVICE.C - SERVICE DETECTION ENGINE
 *  Banner grabbing & version detection without external dependencies
 *  
 *  Capabilities:
 *  - TCP banner grabbing
 *  - Protocol-specific probes (HTTP, SSH, SMTP, MySQL, etc.)
 *  - Version fingerprinting
 *  - SSL/TLS detection (without OpenSSL - just detection, not decryption)
 *  
 *  All operations are stealthy with configurable timeouts
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include "hydra_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  SERVICE RESULT STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════ */

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

/* ═══════════════════════════════════════════════════════════════════════════
 *  PROTOCOL PROBES
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char* name;
    uint16_t default_port;
    const char* probe;
    int probe_len;
    const char* (*parser)(const char* response, service_result_t* result);
} protocol_probe_t;

// HTTP response parser
static const char* parse_http(const char* response, service_result_t* result) {
    // Look for Server header
    const char* server = strstr(response, "Server:");
    if (server) {
        server += 7;
        while (*server == ' ') server++;
        
        int i = 0;
        while (server[i] && server[i] != '\r' && server[i] != '\n' && i < 63) {
            result->product[i] = server[i];
            i++;
        }
        result->product[i] = '\0';
        
        // Try to extract version (look for /)
        char* slash = strchr(result->product, '/');
        if (slash) {
            *slash = '\0';
            strncpy(result->version, slash + 1, sizeof(result->version) - 1);
            
            // Clean up version (stop at space)
            char* space = strchr(result->version, ' ');
            if (space) *space = '\0';
        }
    }
    
    // Get HTTP version line
    if (strncmp(response, "HTTP/", 5) == 0) {
        strncpy(result->info, "HTTP Server", sizeof(result->info) - 1);
    }
    
    return result->product[0] ? result->product : NULL;
}

// SSH parser
static const char* parse_ssh(const char* response, service_result_t* result) {
    // SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    if (strncmp(response, "SSH-", 4) == 0) {
        strncpy(result->product, "SSH", sizeof(result->product) - 1);
        
        const char* ver = response + 4;
        int i = 0;
        while (ver[i] && ver[i] != '\r' && ver[i] != '\n' && i < 127) {
            result->info[i] = ver[i];
            i++;
        }
        result->info[i] = '\0';
        
        // Extract version number
        char* dash = strchr(result->info, '-');
        if (dash) {
            strncpy(result->product, dash + 1, sizeof(result->product) - 1);
            
            // Get version
            char* underscore = strchr(result->product, '_');
            if (underscore) {
                *underscore = '\0';
                strncpy(result->version, underscore + 1, sizeof(result->version) - 1);
                char* space = strchr(result->version, ' ');
                if (space) *space = '\0';
            }
        }
    }
    
    return result->product[0] ? result->product : NULL;
}

// FTP parser
static const char* parse_ftp(const char* response, service_result_t* result) {
    // 220 ProFTPD 1.3.5 Server ready.
    if (strncmp(response, "220", 3) == 0) {
        strncpy(result->product, "FTP", sizeof(result->product) - 1);
        
        const char* info = response + 4;
        int i = 0;
        while (info[i] && info[i] != '\r' && info[i] != '\n' && i < 127) {
            result->info[i] = info[i];
            i++;
        }
        result->info[i] = '\0';
        
        // Look for common FTP servers
        if (strstr(result->info, "ProFTPD")) {
            strncpy(result->product, "ProFTPD", sizeof(result->product) - 1);
        } else if (strstr(result->info, "vsftpd")) {
            strncpy(result->product, "vsftpd", sizeof(result->product) - 1);
        } else if (strstr(result->info, "FileZilla")) {
            strncpy(result->product, "FileZilla", sizeof(result->product) - 1);
        } else if (strstr(result->info, "Pure-FTPd")) {
            strncpy(result->product, "Pure-FTPd", sizeof(result->product) - 1);
        }
    }
    
    return result->product[0] ? result->product : NULL;
}

// SMTP parser
static const char* parse_smtp(const char* response, service_result_t* result) {
    // 220 mail.example.com ESMTP Postfix
    if (strncmp(response, "220", 3) == 0) {
        strncpy(result->product, "SMTP", sizeof(result->product) - 1);
        
        const char* info = response + 4;
        int i = 0;
        while (info[i] && info[i] != '\r' && info[i] != '\n' && i < 127) {
            result->info[i] = info[i];
            i++;
        }
        result->info[i] = '\0';
        
        if (strstr(result->info, "Postfix")) {
            strncpy(result->product, "Postfix", sizeof(result->product) - 1);
        } else if (strstr(result->info, "Exim")) {
            strncpy(result->product, "Exim", sizeof(result->product) - 1);
        } else if (strstr(result->info, "Sendmail")) {
            strncpy(result->product, "Sendmail", sizeof(result->product) - 1);
        } else if (strstr(result->info, "Exchange")) {
            strncpy(result->product, "Microsoft Exchange", sizeof(result->product) - 1);
        }
    }
    
    return result->product[0] ? result->product : NULL;
}

// MySQL parser
static const char* parse_mysql(const char* response, service_result_t* result) {
    // MySQL greeting packet
    if (response[0] > 0 && response[4] == 0x0a) {
        strncpy(result->product, "MySQL", sizeof(result->product) - 1);
        
        // Version string starts at offset 5
        strncpy(result->version, response + 5, sizeof(result->version) - 1);
        char* nul = strchr(result->version, '\0');
        if (nul) *nul = '\0';
        
        snprintf(result->info, sizeof(result->info), "MySQL %s", result->version);
    }
    
    return result->product[0] ? result->product : NULL;
}

// Redis parser
static const char* parse_redis(const char* response, service_result_t* result) {
    if (strncmp(response, "-NOAUTH", 7) == 0 ||
        strncmp(response, "+OK", 3) == 0 ||
        strncmp(response, "$", 1) == 0) {
        strncpy(result->product, "Redis", sizeof(result->product) - 1);
        strncpy(result->info, "Redis Key-Value Store", sizeof(result->info) - 1);
    }
    
    return result->product[0] ? result->product : NULL;
}

// Generic banner parser
static const char* parse_generic(const char* response, service_result_t* result) {
    // Just copy first line as info
    int i = 0;
    while (response[i] && response[i] != '\r' && response[i] != '\n' && i < 127) {
        result->info[i] = response[i];
        i++;
    }
    result->info[i] = '\0';
    
    return result->info[0] ? result->info : NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PROBE DEFINITIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char HTTP_PROBE[] = "GET / HTTP/1.0\r\nHost: target\r\n\r\n";
static const char FTP_PROBE[] = "";  // FTP sends banner first
static const char SMTP_PROBE[] = "";  // SMTP sends banner first
static const char REDIS_PROBE[] = "PING\r\n";

static const protocol_probe_t PROBES[] = {
    {"HTTP",   80,   HTTP_PROBE, sizeof(HTTP_PROBE) - 1, parse_http},
    {"HTTP",   8080, HTTP_PROBE, sizeof(HTTP_PROBE) - 1, parse_http},
    {"HTTP",   8000, HTTP_PROBE, sizeof(HTTP_PROBE) - 1, parse_http},
    {"HTTP",   8443, HTTP_PROBE, sizeof(HTTP_PROBE) - 1, parse_http},
    {"HTTPS",  443,  NULL, 0, NULL},  // SSL detect only
    {"SSH",    22,   NULL, 0, parse_ssh},  // SSH sends banner first
    {"FTP",    21,   FTP_PROBE, 0, parse_ftp},
    {"SMTP",   25,   SMTP_PROBE, 0, parse_smtp},
    {"SMTP",   587,  SMTP_PROBE, 0, parse_smtp},
    {"MySQL",  3306, NULL, 0, parse_mysql},
    {"Redis",  6379, REDIS_PROBE, sizeof(REDIS_PROBE) - 1, parse_redis},
    {NULL, 0, NULL, 0, NULL}
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  NON-BLOCKING CONNECT
 * ═══════════════════════════════════════════════════════════════════════════ */

static int connect_with_timeout(int sock, struct sockaddr_in* addr, int timeout_ms) {
    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    int ret = connect(sock, (struct sockaddr*)addr, sizeof(*addr));
    
    if (ret < 0 && errno == EINPROGRESS) {
        struct pollfd pfd = { .fd = sock, .events = POLLOUT };
        ret = poll(&pfd, 1, timeout_ms);
        
        if (ret > 0) {
            int error;
            socklen_t len = sizeof(error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
            ret = error ? -1 : 0;
        } else {
            ret = -1;  // Timeout
        }
    }
    
    // Restore blocking
    fcntl(sock, F_SETFL, flags);
    
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SSL/TLS DETECTION
 *  Detect SSL by looking for SSL handshake response
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool detect_ssl(int sock) {
    // Send Client Hello
    static const uint8_t CLIENT_HELLO[] = {
        0x16,                   // Content type: Handshake
        0x03, 0x01,             // Version: TLS 1.0
        0x00, 0x05,             // Length
        0x01,                   // Handshake type: Client Hello
        0x00, 0x00, 0x01,       // Length
        0x00                    // Data (minimal)
    };
    
    send(sock, CLIENT_HELLO, sizeof(CLIENT_HELLO), 0);
    
    uint8_t response[5];
    int len = recv(sock, response, sizeof(response), MSG_PEEK);
    
    // Check for SSL/TLS alert or server hello
    if (len >= 5) {
        if (response[0] == 0x16 || response[0] == 0x15) {
            return true;  // TLS handshake or alert
        }
    }
    
    return false;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BANNER GRAB
 * ═══════════════════════════════════════════════════════════════════════════ */

int phantom_grab_banner(struct in_addr target,
                         uint16_t port,
                         service_result_t* result,
                         int timeout_ms) {
    
    memset(result, 0, sizeof(*result));
    result->port = port;
    strncpy(result->service_name, phantom_lookup_service(port), sizeof(result->service_name) - 1);
    
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    // Set timeouts
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = target;
    addr.sin_port = htons(port);
    
    // Connect with timing
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    if (connect_with_timeout(sock, &addr, timeout_ms) < 0) {
        close(sock);
        return -2;
    }
    
    gettimeofday(&end, NULL);
    result->response_time_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                                (end.tv_usec - start.tv_usec) / 1000;
    
    // Find probe for this port
    const protocol_probe_t* probe = NULL;
    for (int i = 0; PROBES[i].name != NULL; i++) {
        if (PROBES[i].default_port == port) {
            probe = &PROBES[i];
            break;
        }
    }
    
    // Send probe if available
    if (probe && probe->probe && probe->probe_len > 0) {
        send(sock, probe->probe, probe->probe_len, 0);
    }
    
    // Receive response
    char buffer[1024];
    int len = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    if (len > 0) {
        buffer[len] = '\0';
        
        // Copy raw banner
        strncpy(result->banner, buffer, sizeof(result->banner) - 1);
        
        // Clean non-printable characters in banner display
        for (int i = 0; i < (int)strlen(result->banner); i++) {
            if (result->banner[i] < 32 && result->banner[i] != '\n' && result->banner[i] != '\r') {
                result->banner[i] = '.';
            }
        }
        
        // Parse with protocol-specific parser
        if (probe && probe->parser) {
            probe->parser(buffer, result);
        } else {
            parse_generic(buffer, result);
        }
    } else if (len == 0) {
        // Connection closed - might be SSL
        result->is_ssl = detect_ssl(sock);
        if (result->is_ssl) {
            strncpy(result->product, "SSL/TLS", sizeof(result->product) - 1);
            strncpy(result->info, "SSL/TLS encrypted service", sizeof(result->info) - 1);
        }
    }
    
    close(sock);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BATCH SERVICE SCAN
 * ═══════════════════════════════════════════════════════════════════════════ */

int phantom_service_scan(struct in_addr target,
                          const uint16_t* ports,
                          int port_count,
                          service_result_t* results,
                          int max_results,
                          int* result_count,
                          int timeout_ms) {
    
    *result_count = 0;
    
    for (int i = 0; i < port_count && *result_count < max_results; i++) {
        service_result_t* r = &results[*result_count];
        
        if (phantom_grab_banner(target, ports[i], r, timeout_ms) == 0) {
            (*result_count)++;
        }
    }
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  VERSION COMPARISON
 * ═══════════════════════════════════════════════════════════════════════════ */

// Compare version strings (e.g., "1.2.3" vs "1.3.0")
int phantom_compare_versions(const char* v1, const char* v2) {
    int major1 = 0, minor1 = 0, patch1 = 0;
    int major2 = 0, minor2 = 0, patch2 = 0;
    
    sscanf(v1, "%d.%d.%d", &major1, &minor1, &patch1);
    sscanf(v2, "%d.%d.%d", &major2, &minor2, &patch2);
    
    if (major1 != major2) return major1 - major2;
    if (minor1 != minor2) return minor1 - minor2;
    return patch1 - patch2;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  KNOWN VULNERABLE VERSIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char* product;
    const char* max_vulnerable_version;
    const char* cve;
    const char* description;
} vuln_signature_t;

static const vuln_signature_t VULN_SIGNATURES[] = {
    {"OpenSSH", "7.4", "CVE-2017-15906", "Zero-length password authentication bypass"},
    {"OpenSSH", "7.2p2", "CVE-2016-10009", "Agent forwarding local command execution"},
    {"ProFTPD", "1.3.5", "CVE-2015-3306", "Remote command execution via mod_copy"},
    {"vsftpd", "2.3.4", "CVE-2011-2523", "Backdoor command execution"},
    {"Apache", "2.4.49", "CVE-2021-41773", "Path traversal and RCE"},
    {"nginx", "1.4.0", "CVE-2013-2028", "Stack-based buffer overflow"},
    {"MySQL", "5.5.9", "CVE-2012-2122", "Authentication bypass"},
    {"Redis", "5.0.4", "CVE-2019-10192", "Heap buffer overflow"},
    {NULL, NULL, NULL, NULL}
};

// Check if service version is potentially vulnerable
const vuln_signature_t* phantom_check_vulnerabilities(const service_result_t* result) {
    for (int i = 0; VULN_SIGNATURES[i].product != NULL; i++) {
        if (strstr(result->product, VULN_SIGNATURES[i].product)) {
            if (result->version[0] && 
                phantom_compare_versions(result->version, VULN_SIGNATURES[i].max_vulnerable_version) <= 0) {
                return &VULN_SIGNATURES[i];
            }
        }
    }
    return NULL;
}
