## 동적 분석 수행

정적 분석에서 얻은 환경 정보로 동적 분석 수행

현재 C/C++, OpenSSL 사용했다고 하드코딩하고 동적분석 수행하도록 함

## 사용 방법

```
make help
make
sudo
```

## 예제

```
sudo ./crypto_orchestrator ./aes_lib 
```

```cpp
#include <iostream>
#include <iomanip>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

// AES-256-CBC 암호화 함수
std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& plaintext,
                                       const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

int main() {
    // 32바이트 키와 16바이트 IV 생성
    std::vector<unsigned char> key(32), iv(16);
    RAND_bytes(key.data(), key.size());
    RAND_bytes(iv.data(), iv.size());

    // 암호화할 평문
    std::string plain = "Hello, AES encryption with OpenSSL!";
    std::vector<unsigned char> plaintext(plain.begin(), plain.end());

    // 암호화
    std::vector<unsigned char> ciphertext = aes_encrypt(plaintext, key, iv);

    // 결과 출력
    std::cout << "Ciphertext (hex): ";
    for (unsigned char c : ciphertext)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    std::cout << std::endl;

    return 0;
}
```
aes_lib.cpp

### 테스트 결과

```
{
  "dynamic_analysis" : 
  {
    "captured_operations" : []
  },
  "metadata" : 
  {
    "analysis_timestamp" : 1757607283,
    "version" : "2.0"
  },
  "static_analysis" : 
  {
    "architecture" : "x64",
    "binary_path" : "./aes_lib",
    "detected_libraries" : 
    [
      "OpenSSL"
    ],
    "platform" : "linux",
    "primary_library" : "OpenSSL"
  },
  "summary" : 
  {
    "agents_loaded" : 2,
    "algorithm_usage" : {},
    "category_distribution" : 
    {
      "agent_info" : 1
    },
    "libraries_detected" : 1,
    "total_operations" : 0
  }
}
```
올바른 결과가 나온것으로 보이지만... 이렇게 출력하는것이 맞을까? (수정 예정)