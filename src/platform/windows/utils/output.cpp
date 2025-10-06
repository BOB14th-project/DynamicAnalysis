// Windows implementation of output.cpp
#include "common/pch.h"
#include "common/output.h"

#include <windows.h>
#include <process.h>
#include <time.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>

static int g_fd = -1;

static inline int get_tid() {
    return GetCurrentThreadId();
}

static void iso8601_utc(char* buf, size_t n) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    _snprintf_s(buf, n, _TRUNCATE, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static void write_full(int fd, const char* p, size_t n) {
    while (n > 0) {
        int w = _write(fd, p, (unsigned int)n);
        if (w > 0) {
            p += w;
            n -= (size_t)w;
        } else {
            break;
        }
    }
}

// JSON escape: ", \, control char
static void json_escape_append(char* dst, size_t cap, size_t* off, const char* s) {
    for (; s && *s && *off + 2 < cap; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '\\' || c == '"') {
            dst[(*off)++] = '\\';
            dst[(*off)++] = c;
        } else if (c >= 0x20) {
            dst[(*off)++] = c;
        } else {
            if (*off + 6 < cap) {
                int n = _snprintf_s(dst + *off, cap - *off, _TRUNCATE, "\\u%04x", c);
                *off += (n > 0 ? n : 0);
            }
        }
    }
}

static void hex_append(char* dst, size_t dst_cap, size_t* off,
                       const unsigned char* p, int n) {
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < n && *off + 2 < dst_cap; ++i) {
        dst[(*off)++] = H[p[i] >> 4];
        dst[(*off)++] = H[p[i] & 0xF];
    }
}

void ndjson_init_from_env(void) {
    char* path = nullptr;
    size_t len = 0;
    if (_dupenv_s(&path, &len, "HOOK_NDJSON") != 0 || !path || !*path) {
        if (path) free(path);
        return;
    }

    int fd = _open(path, _O_CREAT | _O_WRONLY | _O_APPEND | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (fd >= 0) {
        g_fd = fd;
    }
    free(path);
}

void ndjson_close(void) {
    if (g_fd >= 0) {
        _close(g_fd);
        g_fd = -1;
    }
}

void ndjson_log_key_event(const char* surface,
                          const char* api,
                          const char* direction,
                          const char* cipher_name,
                          const unsigned char* key, int keylen,
                          const unsigned char* iv, int ivlen,
                          const unsigned char* tag, int taglen)
{
    if (g_fd < 0) return;

    char line[4096];
    size_t off = 0;
    char ts[64];
    iso8601_utc(ts, sizeof(ts));
    int pid = _getpid();
    int tid = get_tid();

    off += _snprintf_s(line + off, sizeof(line) - off, _TRUNCATE,
        "{\"ts\":\"%s\",\"pid\":%d,\"tid\":%d,\"surface\":\"", ts, pid, tid);
    json_escape_append(line, sizeof(line), &off, surface ? surface : "");
    off += _snprintf_s(line + off, sizeof(line) - off, _TRUNCATE, "\",\"api\":\"");
    json_escape_append(line, sizeof(line), &off, api ? api : "");
    off += _snprintf_s(line + off, sizeof(line) - off, _TRUNCATE, "\",\"dir\":\"");
    json_escape_append(line, sizeof(line), &off, direction ? direction : "");
    off += _snprintf_s(line + off, sizeof(line) - off, _TRUNCATE, "\"");

    if (cipher_name && *cipher_name) {
        off += _snprintf_s(line + off, sizeof(line) - off, _TRUNCATE, ",\"cipher\":\"");
        json_escape_append(line, sizeof(line), &off, cipher_name);
        off += _snprintf_s(line + off, sizeof(line) - off, _TRUNCATE, "\"");
    }
    if (key && keylen > 0) {
        memcpy(line + off, ",\"key\":\"", 8);
        off += 8;
        hex_append(line, sizeof(line), &off, key, keylen);
        if (off < sizeof(line)) line[off++] = '"';
        off += _snprintf_s(line + off, sizeof(line) - off, _TRUNCATE, ",\"keylen\":%d", keylen);
    }
    if (iv && ivlen > 0) {
        memcpy(line + off, ",\"iv\":\"", 7);
        off += 7;
        hex_append(line, sizeof(line), &off, iv, ivlen);
        if (off < sizeof(line)) line[off++] = '"';
    }
    if (tag && taglen > 0) {
        memcpy(line + off, ",\"tag\":\"", 8);
        off += 8;
        hex_append(line, sizeof(line), &off, tag, taglen);
        if (off < sizeof(line)) line[off++] = '"';
    }

    if (off < sizeof(line)) line[off++] = '}';
    if (off < sizeof(line)) line[off++] = '\n';
    write_full(g_fd, line, off);
}
