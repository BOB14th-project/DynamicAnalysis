// ECIES-like encryption/decryption on OpenSSL 3.x
// ECDH (ephemeral-static) + HKDF-SHA256 (32B) + AES-256-GCM
// NID_X9_62_prime256v1 (secp256r1)
#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <stdexcept>
#include <memory>
#include <iomanip>
#include <random>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>

struct EVP_PKEY_Deleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct EVP_PKEY_CTX_Deleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct EVP_CIPHER_CTX_Deleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };

using up_pkey = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using up_pctx = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;
using up_cctx = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;

[[noreturn]] void ossl_throw(const char* where) {
    char buf[256]; ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    throw std::runtime_error(std::string(where) + ": " + buf);
}

up_pkey create_ec_keypair() {
    up_pctx pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!pctx) ossl_throw("EVP_PKEY_CTX_new_id");
    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) ossl_throw("EVP_PKEY_keygen_init");
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0)
        ossl_throw("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &raw) <= 0) ossl_throw("EVP_PKEY_keygen");
    return up_pkey(raw);
}

// ECDH(shared secret)
std::vector<unsigned char> ecdh_shared_secret(EVP_PKEY* priv, EVP_PKEY* peer_pub) {
    up_pctx dctx(EVP_PKEY_CTX_new(priv, nullptr));
    if (!dctx) ossl_throw("EVP_PKEY_CTX_new");
    if (EVP_PKEY_derive_init(dctx.get()) <= 0) ossl_throw("EVP_PKEY_derive_init");
    if (EVP_PKEY_derive_set_peer(dctx.get(), peer_pub) <= 0) ossl_throw("EVP_PKEY_derive_set_peer");
    size_t len = 0;
    if (EVP_PKEY_derive(dctx.get(), nullptr, &len) <= 0) ossl_throw("EVP_PKEY_derive(size)");
    std::vector<unsigned char> secret(len);
    if (EVP_PKEY_derive(dctx.get(), secret.data(), &len) <= 0) ossl_throw("EVP_PKEY_derive");
    secret.resize(len);
    return secret;
}

// HKDF-SHA256 to 32-byte key
std::vector<unsigned char> hkdf_sha256(const std::vector<unsigned char>& ikm,
                                       std::string_view info,
                                       const std::vector<unsigned char>& salt,
                                       size_t out_len = 32) {
    up_pctx kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!kctx) ossl_throw("EVP_PKEY_CTX_new_id(HKDF)");
    if (EVP_PKEY_derive_init(kctx.get()) <= 0) ossl_throw("HKDF derive_init");
    if (EVP_PKEY_CTX_set_hkdf_md(kctx.get(), EVP_sha256()) <= 0) ossl_throw("HKDF md");
    if (!salt.empty())
        if (EVP_PKEY_CTX_set1_hkdf_salt(kctx.get(), salt.data(), (int)salt.size()) <= 0) ossl_throw("HKDF salt");
    if (EVP_PKEY_CTX_set1_hkdf_key(kctx.get(), ikm.data(), (int)ikm.size()) <= 0) ossl_throw("HKDF key");
    if (!info.empty())
        if (EVP_PKEY_CTX_add1_hkdf_info(kctx.get(), (const unsigned char*)info.data(), (int)info.size()) <= 0)
            ossl_throw("HKDF info");
    std::vector<unsigned char> out(out_len);
    size_t olen = out_len;
    if (EVP_PKEY_derive(kctx.get(), out.data(), &olen) <= 0) ossl_throw("HKDF derive");
    out.resize(olen);
    return out;
}

// AES-256-GCM encrypt
struct AeadOut { std::vector<unsigned char> iv, tag, ct; };
AeadOut aes256gcm_encrypt(const std::vector<unsigned char>& key, std::string_view pt) {
    up_cctx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) ossl_throw("EVP_CIPHER_CTX_new");
    std::vector<unsigned char> iv(12); RAND_bytes(iv.data(), (int)iv.size());
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) ossl_throw("EncryptInit");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) <= 0) ossl_throw("SET_IVLEN");
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) <= 0) ossl_throw("set key/iv");

    std::vector<unsigned char> ct(pt.size());
    int outl = 0, tot = 0;
    if (EVP_EncryptUpdate(ctx.get(), ct.data(), &outl,
                          (const unsigned char*)pt.data(), (int)pt.size()) <= 0) ossl_throw("EncryptUpdate");
    tot += outl;
    if (EVP_EncryptFinal_ex(ctx.get(), ct.data()+tot, &outl) <= 0) ossl_throw("EncryptFinal");
    tot += outl; ct.resize(tot);

    std::vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data()) <= 0) ossl_throw("GET_TAG");
    return {iv, tag, ct};
}

// AES-256-GCM decrypt
std::string aes256gcm_decrypt(const std::vector<unsigned char>& key,
                              const std::vector<unsigned char>& iv,
                              const std::vector<unsigned char>& tag,
                              const std::vector<unsigned char>& ct) {
    up_cctx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) ossl_throw("EVP_CIPHER_CTX_new");
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) ossl_throw("DecryptInit");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) <= 0) ossl_throw("SET_IVLEN");
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) <= 0) ossl_throw("set key/iv");

    std::string out; out.resize(ct.size());
    int outl = 0, tot = 0;
    if (EVP_DecryptUpdate(ctx.get(), (unsigned char*)out.data(), &outl, ct.data(), (int)ct.size()) <= 0)
        ossl_throw("DecryptUpdate");
    tot += outl;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data()) <= 0)
        ossl_throw("SET_TAG");
    // Final은 인증 실패시 0 반환
    if (EVP_DecryptFinal_ex(ctx.get(), (unsigned char*)out.data()+tot, &outl) <= 0) ossl_throw("DecryptFinal");
    tot += outl; out.resize(tot);
    return out;
}

// SPKI DER serialize / parse
std::vector<unsigned char> serialize_pubkey_spki(EVP_PKEY* pkey) {
    int len = i2d_PUBKEY(pkey, nullptr);
    if (len <= 0) ossl_throw("i2d_PUBKEY(len)");
    std::vector<unsigned char> der(len);
    unsigned char* p = der.data();
    if (i2d_PUBKEY(pkey, &p) != len) ossl_throw("i2d_PUBKEY(write)");
    return der;
}
up_pkey parse_pubkey_spki(const unsigned char* der, size_t len) {
    const unsigned char* p = der;
    EVP_PKEY* pk = d2i_PUBKEY(nullptr, &p, (long)len);
    if (!pk) ossl_throw("d2i_PUBKEY");
    return up_pkey(pk);
}

// ECIES-like encrypt: returns package = epk_der || iv || tag || ct
std::vector<unsigned char> ecies_encrypt(EVP_PKEY* receiver_pub, std::string_view plaintext) {
    // 1) ephemeral key
    up_pkey eph = create_ec_keypair();

    // 2) ECDH
    auto secret = ecdh_shared_secret(eph.get(), receiver_pub);

    // 3) HKDF → 32B key (salt: empty, info: "ECIES-P256-GCM")
    auto key = hkdf_sha256(secret, "ECIES-P256-GCM", {}, 32);

    // 4) AEAD
    auto aead = aes256gcm_encrypt(key, plaintext);

    // 5) package
    auto epk_der = serialize_pubkey_spki(eph.get());
    std::vector<unsigned char> pkg;
    pkg.reserve(epk_der.size() + aead.iv.size() + aead.tag.size() + aead.ct.size());
    pkg.insert(pkg.end(), epk_der.begin(), epk_der.end());
    pkg.insert(pkg.end(), aead.iv.begin(), aead.iv.end());
    pkg.insert(pkg.end(), aead.tag.begin(), aead.tag.end());
    pkg.insert(pkg.end(), aead.ct.begin(), aead.ct.end());
    return pkg;
}

// decrypt: parse epk_der from head (SPKI is DER, variable-length)
std::string ecies_decrypt(EVP_PKEY* receiver_priv, const std::vector<unsigned char>& pkg) {
    // 1) pull ephemeral pubkey DER
    //    SPKI는 DER이므로 길이를 알기 위해 d2i_PUBKEY를 한번 시도해보는 방식이 제일 안전.
    //    여기선 간단히: d2i_PUBKEY가 성공하는 최소 길이를 찾는다.
    size_t epk_len = 0;
    {
        // DER은 앞 2~4바이트에서 길이가 나오지만, 구현 단순화를 위해 브루트 확장.
        // 실제에선 별도 DER 파서를 쓰거나 패키지에 epk_len(4B) 프리픽스를 두는 걸 권장.
        for (size_t probe = 64; probe <= 200; ++probe) { // P-256 SPKI는 보통 ~91B
            try {
                (void)parse_pubkey_spki(pkg.data(), probe);
                epk_len = probe; break;
            } catch (...) {}
        }
        if (!epk_len) throw std::runtime_error("Cannot determine ephemeral SPKI length; better prefix the length.");
    }
    up_pkey eph_pub = parse_pubkey_spki(pkg.data(), epk_len);

    // 2) 분해
    const size_t IVLEN = 12, TAGLEN = 16;
    if (pkg.size() < epk_len + IVLEN + TAGLEN) throw std::runtime_error("package too short");

    const unsigned char* ivp  = pkg.data() + epk_len;
    const unsigned char* tagp = ivp + IVLEN;
    const unsigned char* ctp  = tagp + TAGLEN;
    size_t ctlen = pkg.size() - epk_len - IVLEN - TAGLEN;

    std::vector<unsigned char> iv(ivp, ivp + IVLEN);
    std::vector<unsigned char> tag(tagp, tagp + TAGLEN);
    std::vector<unsigned char> ct(ctp, ctp + ctlen);

    // 3) ECDH & HKDF
    auto secret = ecdh_shared_secret(receiver_priv, eph_pub.get());
    auto key = hkdf_sha256(secret, "ECIES-P256-GCM", {}, 32);

    // 4) AEAD decrypt
    return aes256gcm_decrypt(key, iv, tag, ct);
}

void print_hex(std::string_view title, const std::vector<unsigned char>& data) {
    std::cout << title << " (" << data.size() << " bytes):\n";
    std::cout << std::hex << std::setfill('0');
    for (unsigned char b : data) std::cout << std::setw(2) << (int)b;
    std::cout << std::dec << "\n";
}

int main() {
    try {
        OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();

        auto receiver = create_ec_keypair();
        const std::string msg = "This is a secret message for ECIES test in C++.";

        auto pkg = ecies_encrypt(receiver.get(), msg);
        print_hex("pkg", pkg);

        auto dec = ecies_decrypt(receiver.get(), pkg);
        std::cout << "dec: " << dec << "\n";
        std::cout << (dec == msg ? "OK\n" : "MISMATCH\n");
    } catch (const std::exception& e) {
        std::cerr << "ERR: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
