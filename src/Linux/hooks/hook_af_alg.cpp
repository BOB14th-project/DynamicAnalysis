// socket/bind/setsockopt/sendmsg IV
// hooks/hook_af_alg.cpp
#include "pch.h"
#include "output.h"
#include "resolver.h"
#include "reentry_guard.h"
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

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
  char type[16]{0};   // "skcipher"/"aead"/"hash"
  char name[64]{0};   // "gcm(aes)" 등
  unsigned char key[64]; int keylen=0;
  unsigned char iv[64];  int ivlen=0;
  int op_dir=0; // ALG_OP_ENCRYPT=1, DECRYPT=2
};
static fd_ctx g_ctx[65536];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static inline fd_ctx* get(int fd){ return (fd>=0 && fd<(int)(sizeof(g_ctx)/sizeof(g_ctx[0]))) ? &g_ctx[fd] : nullptr; }

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
        strncpy(c->type, (const char*)sa->salg_type, sizeof(c->type)-1);
        strncpy(c->name, (const char*)sa->salg_name, sizeof(c->name)-1);
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

  // cmsg에서 ALG_SET_IV 추출
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
