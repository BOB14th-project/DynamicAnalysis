#include "pch.h"
#include "output.h"
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <errno.h>

static int g_fd = -1;

static inline pid_t get_tid() {
#ifdef SYS_gettid
    return (pid_t)syscall(SYS_gettid);
#else
    return (pid_t)getpid();
#endif
}

static void iso8601_utc(char* buf, size_t n) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm; gmtime_r(&ts.tv_sec, &tm);
    int ms = (int)(ts.tv_nsec / 1000000);
    snprintf(buf, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

static void write_full(int fd, const char* p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w > 0) { p += w; n -= (size_t)w; continue; }
        if (errno == EINTR) continue;
        break;
    }
}

// JSON escape: ", \, control char
static void json_escape_append(char* dst, size_t cap, size_t* off, const char* s) {
    for (; s && *s && *off+2 < cap; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '\\' || c == '"') {
            dst[(*off)++] = '\\';
            dst[(*off)++] = c;
        } else if (c >= 0x20) {
            dst[(*off)++] = c;
        } else {
            if (*off+6 < cap) {
                int n = snprintf(dst+*off, cap-*off, "\\u%04x", c);
                *off += (n>0? n:0);
            }
        }
    }
}

static void hex_append(char* dst, size_t dst_cap, size_t* off,
                       const unsigned char* p, int n) {
    static const char* H = "0123456789abcdef";
    for (int i=0; i<n && *off+2 < dst_cap; ++i) {
        dst[(*off)++] = H[p[i] >> 4];
        dst[(*off)++] = H[p[i] & 0xF];
    }
}

void ndjson_init_from_env(void) {
    const char* path = getenv("HOOK_NDJSON");
    if (!path || !*path) return;
    int fd = open(path, O_CREAT|O_WRONLY|O_APPEND|O_CLOEXEC, 0600);
    if (fd >= 0) g_fd = fd;
}
void ndjson_close(void) {
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
}

__attribute__((constructor))
static void _ctor_ndjson(void) { ndjson_init_from_env(); }

__attribute__((destructor))
static void _dtor_ndjson(void) { ndjson_close(); }

void ndjson_log_key_event(const char* surface,
                          const char* api,
                          const char* direction,
                          const char* cipher_name,
                          const unsigned char* key, int keylen,
                          const unsigned char* iv,  int ivlen,
                          const unsigned char* tag, int taglen)
{
    if (g_fd < 0) return;

    char line[4096]; size_t off = 0;
    char ts[64]; iso8601_utc(ts, sizeof(ts));
    pid_t pid = getpid(), tid = get_tid();

    off += snprintf(line+off, sizeof(line)-off,
        "{\"ts\":\"%s\",\"pid\":%d,\"tid\":%d,\"surface\":\"", ts, (int)pid, (int)tid);
        json_escape_append(line, sizeof(line), &off, surface ? surface : "");
    off += snprintf(line+off, sizeof(line)-off, "\",\"api\":\"");
        json_escape_append(line, sizeof(line), &off, api ? api : "");
    off += snprintf(line+off, sizeof(line)-off, "\",\"dir\":\"");
    json_escape_append(line, sizeof(line), &off, direction ? direction : "");
    off += snprintf(line+off, sizeof(line)-off, "\"");

    if (cipher_name && *cipher_name) {
        off += snprintf(line+off, sizeof(line)-off, ",\"cipher\":\"");
        json_escape_append(line, sizeof(line), &off, cipher_name);
        off += snprintf(line+off, sizeof(line)-off, "\"");
    }
    if (key && keylen > 0) {
        memcpy(line+off, ",\"key\":\"", 8); off += 8;
        hex_append(line, sizeof(line), &off, key, keylen);
        if (off < sizeof(line)) line[off++] = '"';
        off += snprintf(line+off, sizeof(line)-off, ",\"keylen\":%d", keylen);
    }
    if (iv && ivlen > 0) {
        memcpy(line+off, ",\"iv\":\"", 7); off += 7;
        hex_append(line, sizeof(line), &off, iv, ivlen);
        if (off < sizeof(line)) line[off++] = '"';
    }
    if (tag && taglen > 0) {
        memcpy(line+off, ",\"tag\":\"", 8); off += 8;
        hex_append(line, sizeof(line), &off, tag, taglen);
        if (off < sizeof(line)) line[off++] = '"';
    }

    if (off < sizeof(line)) line[off++] = '}';
    if (off < sizeof(line)) line[off++] = '\n';
    write_full(g_fd, line, off);
}