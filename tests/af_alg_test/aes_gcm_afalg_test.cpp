// tests/af_alg_test/aes_gcm_afalg_test.cpp
// 런타임:
//   sudo modprobe algif_aead gcm aes
//   HOOK_NDJSON=./hook.ndjson LD_PRELOAD=./build/libhook.so ./build/aes_gcm_afalg_test
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <array>
#include <vector>
#include <iostream>

static void die(const char* m){ std::perror(m); std::exit(1); }

struct Fd {
    int fd{-1};
    explicit Fd(int f=-1): fd(f) {}
    ~Fd(){ if (fd >= 0) ::close(fd); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& o) noexcept { fd=o.fd; o.fd=-1; }
    Fd& operator=(Fd&& o) noexcept { if(this!=&o){ if(fd>=0) ::close(fd); fd=o.fd; o.fd=-1; } return *this; }
    operator int() const { return fd; }
    bool ok() const { return fd >= 0; }
};

int main() {
    Fd tfm(::socket(AF_ALG, SOCK_SEQPACKET, 0));
    if(!tfm.ok()) die("socket(AF_ALG)");

    sockaddr_alg sa{};
    sa.salg_family = AF_ALG;
    std::strncpy((char*)sa.salg_type, "aead", sizeof(sa.salg_type)-1);   // 또는 "skcipher"
    std::strncpy((char*)sa.salg_name, "gcm(aes)", sizeof(sa.salg_name)-1);

    if(::bind(tfm, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) die("bind");

    // KEY
    std::array<unsigned char, 32> key{};
    for(size_t i=0;i<key.size();++i) key[i]=(unsigned char)i;
    if(::setsockopt(tfm, SOL_ALG, ALG_SET_KEY, key.data(), key.size()) != 0) die("ALG_SET_KEY");

    // op socket
    Fd op(::accept(tfm, nullptr, nullptr));
    if(!op.ok()) die("accept");

    int op_dir = 1; // ENC
    ::setsockopt(op, SOL_ALG, ALG_SET_OP, &op_dir, sizeof(op_dir)); // 실패해도 무시

    // IV via sendmsg CMSG (가변 버퍼 사용)
    const size_t ivlen = 12;
    size_t cbuf_len = CMSG_SPACE(sizeof(af_alg_iv) + ivlen);
    std::vector<unsigned char> cbuf(cbuf_len, 0);

    msghdr msg{};
    msg.msg_control = cbuf.data();
    msg.msg_controllen = cbuf.size();

    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_IV;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(af_alg_iv) + ivlen);

    auto* ivhdr = reinterpret_cast<af_alg_iv*>(CMSG_DATA(cmsg));
    ivhdr->ivlen = ivlen;
    for(size_t i=0;i<ivlen;++i) ivhdr->iv[i] = static_cast<unsigned char>(0xA0+i);

    ssize_t s = ::sendmsg(op, &msg, 0);
    if (s < 0 && errno != EINVAL && errno != EMSGSIZE) die("sendmsg(ALG_SET_IV)");

    std::cout << "ok: AF_ALG key/iv configured for gcm(aes)\n";
    return 0;
}
