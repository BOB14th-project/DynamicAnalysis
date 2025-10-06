// socket/bind/setsockopt/sendmsg IV
// hooks/hook_af_alg.cpp
#include "common/pch.h"
#include "common/output.h"
#include "platform/linux/resolver.h"
#include "common/reentry_guard.h"
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

// Extended AF_ALG constants for akcipher/kpp (if not available in kernel headers)
#ifndef ALG_SET_PUBKEY
#define ALG_SET_PUBKEY			6
#endif
#ifndef ALG_SET_PUBKEY_ID
#define ALG_SET_PUBKEY_ID		7
#endif
#ifndef ALG_SET_KEY_ID
#define ALG_SET_KEY_ID			8
#endif

// Extended operations for asymmetric crypto
#ifndef ALG_OP_SIGN
#define ALG_OP_SIGN			2
#endif
#ifndef ALG_OP_VERIFY
#define ALG_OP_VERIFY			3
#endif

#define RESOLVE_SYM(var, name) do{ if(!(var)) (var)=(decltype(var))resolve_next_symbol(name);}while(0)
static constexpr const char* SURFACE = "af_alg";

static int (*real_socket)(int,int,int);
static int (*real_bind)(int,const struct sockaddr*,socklen_t);
static int (*real_setsockopt)(int,int,int,const void*,socklen_t);
static int (*real_accept)(int,struct sockaddr*,socklen_t*);
static int (*real_accept4)(int,struct sockaddr*,socklen_t*,int);
static ssize_t (*real_sendmsg)(int,const struct msghdr*,int);
static int (*real_close)(int);

struct fd_ctx {
  bool is_afalg=false, is_op=false;
  char type[16]{0};   // "skcipher"/"aead"/"hash"/"akcipher"/"kpp"
  char name[64]{0};   // "gcm(aes)"/"rsa"/"ecdh" 등
  unsigned char key[512]; int keylen=0;
  unsigned char iv[64];   int ivlen=0;
  unsigned char pubkey[2048]; int pubkeylen=0;  // Public key for akcipher
  int op_dir=0; // ALG_OP_ENCRYPT=1, DECRYPT=2, SIGN=2, VERIFY=3
  int key_id=0; // For ALG_SET_KEY_ID/ALG_SET_PUBKEY_ID
};
static fd_ctx g_ctx[65536];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static inline fd_ctx* get(int fd){ return (fd>=0 && fd<(int)(sizeof(g_ctx)/sizeof(g_ctx[0]))) ? &g_ctx[fd] : nullptr; }

// Helper function to identify key type from binary data
static const char* identify_key_type(const unsigned char* data, int len) {
  if (!data || len < 10) return "unknown";

  // Check for DER format (starts with 0x30 - SEQUENCE)
  if (data[0] == 0x30) {
    // Look for RSA OID: 1.2.840.113549.1.1.1
    // In DER: 06 09 2A 86 48 86 F7 0D 01 01 01
    for (int i = 0; i < len - 11; i++) {
      if (data[i] == 0x06 && data[i+1] == 0x09 &&
          data[i+2] == 0x2A && data[i+3] == 0x86 && data[i+4] == 0x48 &&
          data[i+5] == 0x86 && data[i+6] == 0xF7 && data[i+7] == 0x0D &&
          data[i+8] == 0x01 && data[i+9] == 0x01 && data[i+10] == 0x01) {
        return "RSA-DER";
      }
    }

    // Look for EC OID: 1.2.840.10045.2.1
    // In DER: 06 07 2A 86 48 CE 3D 02 01
    for (int i = 0; i < len - 9; i++) {
      if (data[i] == 0x06 && data[i+1] == 0x07 &&
          data[i+2] == 0x2A && data[i+3] == 0x86 && data[i+4] == 0x48 &&
          data[i+5] == 0xCE && data[i+6] == 0x3D && data[i+7] == 0x02 && data[i+8] == 0x01) {
        return "ECC-DER";
      }
    }

    return "DER-format";
  }

  // Check for PEM format (starts with "-----BEGIN")
  if (len >= 10 && memcmp(data, "-----BEGIN", 10) == 0) {
    if (len >= 27 && memcmp(data, "-----BEGIN RSA PUBLIC KEY", 26) == 0) {
      return "RSA-PEM";
    } else if (len >= 26 && memcmp(data, "-----BEGIN PUBLIC KEY", 21) == 0) {
      return "PUBLIC-KEY-PEM";
    } else if (len >= 32 && memcmp(data, "-----BEGIN EC PRIVATE KEY", 25) == 0) {
      return "ECC-PRIVATE-PEM";
    }
    return "PEM-format";
  }

  // Raw key material (could be raw RSA modulus or EC point)
  if (len >= 64 && len <= 1024) {
    return "raw-key";
  }

  return "unknown";
}

extern "C" int socket(int domain, int type, int protocol){
  RESOLVE_SYM(real_socket, "socket");
  if (!real_socket) return -1;
  int fd = real_socket(domain, type, protocol);
  if (domain == AF_ALG && fd >= 0) {
    pthread_mutex_lock(&g_mu);
    auto c = get(fd); if (c) { *c = fd_ctx{}; c->is_afalg=true; }
    pthread_mutex_unlock(&g_mu);
  }
  return fd;
}

extern "C" int bind(int sockfd, const struct sockaddr* addr, socklen_t len){
  RESOLVE_SYM(real_bind, "bind");
  if (!real_bind) return -1;
  if (addr && len >= sizeof(sockaddr_alg)) {
    const sockaddr_alg* sa = (const sockaddr_alg*)addr;
    if (sa->salg_family == AF_ALG) {
      pthread_mutex_lock(&g_mu);
      if (auto c = get(sockfd)) {
        c->is_afalg = true;
        size_t type_len = strnlen((const char*)sa->salg_type, sizeof(sa->salg_type));
        if (type_len > sizeof(c->type) - 1) {
            type_len = sizeof(c->type) - 1;
        }
        memcpy(c->type, sa->salg_type, type_len);
        c->type[type_len] = '\0';
        size_t name_len = strnlen((const char*)sa->salg_name, sizeof(sa->salg_name));
        if (name_len > sizeof(c->name) - 1) {
            name_len = sizeof(c->name) - 1;
        }
        memcpy(c->name, sa->salg_name, name_len);
        c->name[name_len] = '\0';
      }
      pthread_mutex_unlock(&g_mu);
    }
  }
  return real_bind(sockfd, addr, len);
}

extern "C" int setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen){
  RESOLVE_SYM(real_setsockopt, "setsockopt");
  if (!real_setsockopt) return -1;

  if (level == SOL_ALG) {
    pthread_mutex_lock(&g_mu);
    auto c = get(fd);
    if (c && c->is_afalg) {
      if (optname == ALG_SET_KEY && optval && optlen > 0) {
        c->keylen = optlen > (socklen_t)sizeof(c->key) ? (int)sizeof(c->key) : (int)optlen;
        memcpy(c->key, optval, c->keylen);
        ndjson_log_key_event(SURFACE, "setsockopt", "ALG_SET_KEY", c->name,
          c->key, c->keylen, nullptr, 0, nullptr, 0);
      } else if (optname == ALG_SET_OP && optval && optlen >= (socklen_t)sizeof(int)) {
        c->op_dir = *(const int*)optval;
        const char* op_name = "ALG_SET_OP_UNKNOWN";
        switch (c->op_dir) {
          case ALG_OP_ENCRYPT: op_name = "ALG_SET_OP_ENCRYPT"; break;
          case ALG_OP_DECRYPT: op_name = "ALG_SET_OP_DECRYPT"; break;
          case ALG_OP_SIGN: op_name = "ALG_SET_OP_SIGN"; break;
          case ALG_OP_VERIFY: op_name = "ALG_SET_OP_VERIFY"; break;
        }
        ndjson_log_key_event(SURFACE, "setsockopt", op_name,
          c->name, nullptr, 0, nullptr, 0, nullptr, 0);
      } else if (optname == ALG_SET_AEAD_ASSOCLEN && optval && optlen >= (socklen_t)sizeof(__u32)) {
        __u32 assoc = *(__u32*)optval;
        ndjson_log_key_event(SURFACE, "setsockopt", "ALG_SET_AEAD_ASSOCLEN",
          c->name, nullptr, 0, (unsigned char*)&assoc, sizeof(assoc), nullptr, 0);
      } else if (optname == ALG_SET_AEAD_AUTHSIZE && optval && optlen >= (socklen_t)sizeof(__u32)) {
        __u32 auth = *(__u32*)optval;
        ndjson_log_key_event(SURFACE, "setsockopt", "ALG_SET_AEAD_AUTHSIZE",
          c->name, nullptr, 0, (unsigned char*)&auth, sizeof(auth), nullptr, 0);
      } else if (optname == ALG_SET_PUBKEY && optval && optlen > 0) {
        // Handle public key setting for akcipher
        c->pubkeylen = optlen > (socklen_t)sizeof(c->pubkey) ? (int)sizeof(c->pubkey) : (int)optlen;
        memcpy(c->pubkey, optval, c->pubkeylen);

        // Identify key type and create enhanced cipher name
        const char* key_type = identify_key_type(c->pubkey, c->pubkeylen);
        char enhanced_name[128];
        snprintf(enhanced_name, sizeof(enhanced_name), "%s(%s)", c->name, key_type);

        ndjson_log_key_event(SURFACE, "setsockopt", "ALG_SET_PUBKEY", enhanced_name,
          c->pubkey, c->pubkeylen, nullptr, 0, nullptr, 0);
      } else if (optname == ALG_SET_KEY_ID && optval && optlen >= (socklen_t)sizeof(int)) {
        // Handle key ID from kernel keyring
        c->key_id = *(const int*)optval;
        ndjson_log_key_event(SURFACE, "setsockopt", "ALG_SET_KEY_ID", c->name,
          (unsigned char*)&c->key_id, sizeof(c->key_id), nullptr, 0, nullptr, 0);
      } else if (optname == ALG_SET_PUBKEY_ID && optval && optlen >= (socklen_t)sizeof(int)) {
        // Handle public key ID from kernel keyring
        c->key_id = *(const int*)optval;
        ndjson_log_key_event(SURFACE, "setsockopt", "ALG_SET_PUBKEY_ID", c->name,
          (unsigned char*)&c->key_id, sizeof(c->key_id), nullptr, 0, nullptr, 0);
      }
    }
    pthread_mutex_unlock(&g_mu);
  }
  return real_setsockopt(fd, level, optname, optval, optlen);
}

extern "C" int accept(int fd, struct sockaddr* addr, socklen_t* alen){
  RESOLVE_SYM(real_accept, "accept");
  if (!real_accept) return -1;
  int nfd = real_accept(fd, addr, alen);
  if (nfd >= 0) {
    pthread_mutex_lock(&g_mu);
    auto p = get(fd), c = get(nfd);
    if (p && p->is_afalg && c) { *c = *p; c->is_op=true; }
    pthread_mutex_unlock(&g_mu);
  }
  return nfd;
}
extern "C" int accept4(int fd, struct sockaddr* addr, socklen_t* alen, int flags){
  RESOLVE_SYM(real_accept4, "accept4");
  if (!real_accept4) return -1;
  int nfd = real_accept4(fd, addr, alen, flags);
  if (nfd >= 0) {
    pthread_mutex_lock(&g_mu);
    auto p = get(fd), c = get(nfd);
    if (p && p->is_afalg && c) { *c = *p; c->is_op=true; }
    pthread_mutex_unlock(&g_mu);
  }
  return nfd;
}

extern "C" ssize_t sendmsg(int fd, const struct msghdr* msg, int flags){
  RESOLVE_SYM(real_sendmsg, "sendmsg");
  if (!real_sendmsg) return -1;

  // cmsg에서 ALG_SET_IV 및 akcipher 데이터 추출
  if (msg) {
    pthread_mutex_lock(&g_mu);
    auto c = get(fd);
    pthread_mutex_unlock(&g_mu);
    if (c && c->is_afalg) {
      for (struct cmsghdr* cm = CMSG_FIRSTHDR((struct msghdr*)msg);
           cm; cm = CMSG_NXTHDR((struct msghdr*)msg, cm)) {
        if (cm->cmsg_level == SOL_ALG && cm->cmsg_type == ALG_SET_IV) {
          struct af_alg_iv* iv = (struct af_alg_iv*)CMSG_DATA(cm);
          int ivlen = (int)iv->ivlen;
          if (ivlen > (int)sizeof(c->iv)) ivlen = (int)sizeof(c->iv);
          memcpy(c->iv, iv->iv, ivlen); c->ivlen = ivlen;
          ndjson_log_key_event(SURFACE, "sendmsg", "ALG_SET_IV", c->name,
            nullptr, 0, c->iv, c->ivlen, nullptr, 0);
        }
      }

      // Log sendmsg data for akcipher/kpp operations (sign/verify data)
      if ((strcmp(c->type, "akcipher") == 0 || strcmp(c->type, "kpp") == 0) && msg->msg_iov && msg->msg_iovlen > 0) {
        const char* op_type = "data";
        if (c->op_dir == ALG_OP_SIGN) op_type = "sign_data";
        else if (c->op_dir == ALG_OP_VERIFY) op_type = "verify_data";
        else if (c->op_dir == ALG_OP_ENCRYPT) op_type = "encrypt_data";
        else if (c->op_dir == ALG_OP_DECRYPT) op_type = "decrypt_data";

        // Log the first iovec buffer (limited size for NDJSON)
        size_t data_len = msg->msg_iov[0].iov_len > 256 ? 256 : msg->msg_iov[0].iov_len;
        ndjson_log_key_event(SURFACE, "sendmsg", op_type, c->name,
          c->pubkeylen > 0 ? c->pubkey : (c->keylen > 0 ? c->key : nullptr),
          c->pubkeylen > 0 ? c->pubkeylen : c->keylen,
          (unsigned char*)msg->msg_iov[0].iov_base, (int)data_len, nullptr, 0);
      }
    }
  }
  return real_sendmsg(fd, msg, flags);
}

extern "C" int close(int fd){
  RESOLVE_SYM(real_close, "close");
  if (!real_close) return -1;
  pthread_mutex_lock(&g_mu);
  if (auto c = get(fd)) { *c = fd_ctx{}; }
  pthread_mutex_unlock(&g_mu);
  return real_close(fd);
}
