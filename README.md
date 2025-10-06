# 암호 라이브러리 동적 분석 도구

OpenSSL · Linux 커널 AF_ALG · JNI 기반 Java 등 다양한 암호화 실행 경로를 훅킹해 실시간으로 키/IV/태그 정보를 수집하는 크로스 플랫폼 분석 도구입니다. 플랫폼별 주입 방식은 다음과 같습니다.

- **Linux**: `LD_PRELOAD`로 `libhook.so`를 선주입해 암호 API를 가로채고 NDJSON 로그를 생성합니다.
- **Windows**: Microsoft Detours를 사용한 DLL 인젝션으로 OpenSSL API를 후킹하여 동일한 이벤트 스트림을 수집합니다.

`dynamic_analysis_cli`는 대상 프로그램을 자동으로 주입 실행한 뒤 수집된 이벤트를 표준 출력과 로그 파일 모두에 기록합니다.

---

## 구성 요소
- **Linux**: `libhook.so` - LD_PRELOAD 기반 훅킹 라이브러리. OpenSSL EVP/Provider/ECC, AF_ALG, JNI 경로를 감지해 로그를 남깁니다.
- **Windows**: `hook.dll` - Detours 기반 훅킹 라이브러리. 현재 OpenSSL EVP API 후킹을 지원합니다.
- `dynamic_analysis_cli` : 크로스 플랫폼 CLI 도구
  - **Linux**: 대상 실행 파일을 포크/exec로 실행하고 `LD_PRELOAD` 환경을 자동 설정
  - **Windows**: `DetourCreateProcessWithDll()`로 프로세스 생성과 동시에 DLL 주입
- `logs/*.ndjson` : 분석 결과가 쌓이는 NDJSON 라인 로그. 각 이벤트는 `ts/pid/tid/api/cipher/key/...` 필드를 포함합니다.
- `tests/openssl/` : 크로스 플랫폼 OpenSSL 테스트 코드 (AES CBC/GCM, ECC, Provider API 등)

---

## 빌드

### Linux
```bash
cmake -S . -B build-linux
cmake --build build-linux -j
```

### Windows (Visual Studio Generators)
```cmd
cmake -S . -B build-windows -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="C:/dev/detours;C:/vcpkg/installed/x64-windows"
cmake --build build-windows --config Release
```
Detours와 OpenSSL(VCPKG 등) 경로가 다르면 `-DCMAKE_PREFIX_PATH="C:/경로/Detours;C:/경로/OpenSSL"`을 적절히 조정해 주세요.

**주요 산출물:**
- **Linux**: `build-linux/lib/libhook.so`, `build-linux/bin/dynamic_analysis_cli`
- **Windows**: `build-windows/lib/hook.dll`, `build-windows/bin/Release/dynamic_analysis_cli.exe`
- **공통**: 각 빌드 디렉터리의 `bin/*` OpenSSL 테스트 실행 파일들

기본적으로 OpenSSL 1.1/3.0 모두 지원하며, Linux에서는 JNI가 감지되면 Java 관련 훅도 자동 활성화됩니다.

---

## 사용법

### 0. 의존 라이브러리 설치

#### Linux (Ubuntu 24.04 기준)
아래 명령을 한 번에 실행하면 OpenSSL, libsodium, GnuTLS, NSS, mbedTLS까지 필요한 개발 헤더가 설치됩니다.

#### Windows
- **필수**: [Microsoft Detours](https://github.com/microsoft/Detours) 라이브러리
- **필수**: OpenSSL for Windows (vcpkg 또는 직접 빌드)
- **선택**: Visual Studio 2019/2022 또는 MinGW

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake pkg-config \
  libssl-dev libsodium-dev gnutls-dev \
  libnss3-dev libnspr4-dev libp11-kit-dev \
  libmbedtls-dev libwolfssl-dev
# (선택) Java JNI 샘플을 돌리려면 SDKMAN 등의 도구로 JDK 설치 후 JAVA_HOME 설정
# sdkman example: sdk install java 21.0.4-amzn

# (선택) cryptodev 모듈이 필요한 경우 – VM/베어메탈 등 모듈 로드 가능한 환경에서만
# sudo apt-get install -y cryptodev-dkms libcryptodev-dev
# sudo modprobe cryptodev && ls -l /dev/cryptodev
# (선택) BoringSSL 샘플은 소스 빌드가 필요하며, 아래 순서를 참고하세요.
#   1) git clone https://github.com/google/boringssl.git
#   2) cmake -S boringssl -B boringssl/build -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
#   3) ninja -C boringssl/build crypto ssl
#   4) 프로젝트 루트에서 cmake -S . -B build \
#        -DBORINGSSL_ROOT=/절대/경로/boringssl \
#        -UBORINGSSL_CRYPTO_LIBRARY -UBORINGSSL_INCLUDE_DIR
#      (기존 캐시를 무효화해 BoringSSL libcrypto.so를 찾도록 합니다.)
# (선택) PyCryptodome 샘플을 사용하려면 파이썬 가상환경 등을 만들어 pycryptodome을 설치하세요.
#   python3 -m venv .venv && . .venv/bin/activate && pip install pycryptodome
```

※ WSL2 기본 커널은 모듈 로드를 지원하지 않으므로 cryptodev 샘플은 자동 건너뛰기 됩니다. 특정 패키지가 누락되면 해당 샘플만 빌드/실행이 생략되고 나머지 경로는 정상 동작합니다.

### 1. 동적 분석 실행

#### Linux
```bash
# 로그 파일 경로 지정 (선택)
export HOOK_NDJSON="$PWD/logs/analysis.ndjson"

# OpenSSL AES CBC 테스트 실행
./build/bin/dynamic_analysis_cli ./build/bin/openssl_aes_lib_test
```

#### Windows
```cmd
# OpenSSL AES CBC 테스트 실행 (관리자 권한 필요시)
.\build\bin\dynamic_analysis_cli.exe .\build\bin\openssl_aes_lib_test.exe
```
#### 모든 테스트 실행 (Linux만)
```bash
./scripts/run_all_dynamic_tests.sh
```

### 2. 결과 확인
```bash
# Linux/Windows 공통
cat logs/analysis.ndjson
```

동적 분석 CLI는 실행 종료 후 `captured events:` 블록에 기록된 NDJSON 라인을 표준 출력으로 보여 줍니다.

---

## 테스트 코드 개요
각 샘플은 후킹 대상 경로별로 최소한의 재현 환경을 제공합니다. OpenSSL 관련 실행 파일은 CMake에 등록되어 있어 바로 빌드되며, 그 외 라이브러리 예제는 해당 라이브러리를 설치한 뒤 직접 빌드/실행해 동적 분석에 활용할 수 있습니다.

- **OpenSSL (CMake 빌드 대상)**
  - `tests/openssl/symmetric/openssl_aes_lib_test.cpp` : EVP AES-256-CBC 초기화 → 키 추출
  - `tests/openssl/aead/openssl_symm_aes_gcm_test.cpp` : EVP AES-256-GCM → 키/IV/TAG 로깅
  - `tests/openssl/ecc/openssl_ecc_sign_test.cpp` : ECDSA 키 생성·서명 → ECC 개인키/서명 로그
  - `tests/openssl/ecc/openssl_ecc_ecies_test.cpp` : ECDH + HKDF + AES-GCM 복합 시나리오
  - `tests/openssl/provider/openssl_provider_ex2_test.cpp` : OpenSSL 3 `*_ex2` 경로
  - `tests/openssl/provider/openssl_provider_ex2_params_test.cpp` : OSSL_PARAM 기반 설정 값
- **Linux AF_ALG**
  - `tests/af_alg/af_alg_skcipher_aes_cbc_demo.c` : AES-CBC skcipher 키/IV 설정
  - `tests/af_alg/af_alg_aes_gcm_demo.c` : AES-GCM AEAD 키/IV/assoc 설정
  - `tests/af_alg/af_alg_hmac_sha256_demo.c` : HMAC-SHA256 hash 키 설정
- **cryptodev**
  - `tests/cryptodev/ioctl/cryptodev_aes_cbc_demo.c` : `/dev/crypto` ioctl 기반 AES-256-CBC 세션
  - `tests/cryptodev/ioctl/cryptodev_hmac_sha256_demo.c` : HMAC-SHA256 세션 키 설정
  - `tests/cryptodev/ioctl/cryptodev_rsa_demo.c` : RSA 모듈러 연산 (CIOCKEY)
- **libsodium**
  - `tests/libsodium/aead/chacha20_poly1305_demo.c` : `crypto_aead_chacha20poly1305_ietf_*`
  - `tests/libsodium/aead/xchacha20_poly1305_demo.c` : `crypto_aead_xchacha20poly1305_ietf_*`
  - `tests/libsodium/secretbox/libsodium_secretbox_demo.c` : `crypto_secretbox_*`
  - `tests/libsodium/box/libsodium_box_demo.c` : `crypto_box_*`
  - `tests/libsodium/sign/libsodium_sign_demo.c` : `crypto_sign_*`
- **GnuTLS**
  - `tests/GnuTLS/symmetric/gnutls_aes_gcm_demo.c` : `gnutls_cipher_*` AES-256-GCM 호출
- **NSS**
  - `tests/NSS/symmetric/nss_aes_gcm_demo.c` : `PK11_Encrypt` AES-256-GCM
- **boringSSL**
  - `tests/boringSSL/symmetric/boringssl_aes_gcm_demo.cc` : AES-256-GCM 단방향 암호화
  - `tests/boringSSL/symmetric/boringssl_aes_gcm_roundtrip_demo.cc` : AES-256-GCM 암·복호화
  - `tests/boringSSL/symmetric/boringssl_chacha20_poly1305_demo.cc` : ChaCha20-Poly1305 암호화
  - `tests/boringSSL/symmetric/boringssl_xchacha20_poly1305_demo.cc` : XChaCha20-Poly1305 암호화
    - (BoringSSL 빌드에서 XChaCha20이 비활성화된 경우 해당 데모는 "not enabled" 메시지만 출력하고 종료)
- **mbedTLS**
  - `tests/mbedTLS/symmetric/mbedtls_aes_gcm_demo.c` : `mbedtls_gcm_crypt_and_tag`
- **wolfSSL**
  - `tests/wolfSSL/symmetric/wolfssl_aes_gcm_demo.c` : `wc_AesGcmSetKey` / `wc_AesGcmEncrypt`
  - `tests/wolfSSL/symmetric/wolfssl_aes_cbc_demo.c` : `wc_AesSetKey` / `wc_AesCbcEncrypt`
  - `tests/wolfSSL/hash/wolfssl_hmac_sha256_demo.c` : `wc_HmacSetKey` / `wc_HmacFinal`
- **PyCryptodome**
  - `tests/PyCryptodome/symmetric/aes_gcm_demo.py` : Python AES-256-GCM
    - 후킹은 `tests/PyCryptodome/symmetric/run_pycryptodome_aes_gcm_demo.sh` 스크립트를 통해 실행 (가상환경이 있으면 자동 사용)
    - PyCryptodome은 기본적으로 `RTLD_DEEPBIND`를 사용하므로, 스크립트에서 `PYCRYPTODOME_DISABLE_DEEPBIND=1`을 설정해 LD_PRELOAD 후킹이 적용되도록 처리했습니다.
  - `tests/PyCryptodome/symmetric/aes_gcm_aad_demo.py` : AAD 포함 AES-256-GCM / 검증 흐름
  - `tests/PyCryptodome/symmetric/aes_gcm_stream_demo.py` : 다중 `encrypt()` 호출로 스트리밍 암호화
- **Java JNI + OpenSSL**
  - `tests/java_test/JavaNativeSSL.*`, `tests/java_test/complextest` : JNI/네이티브 혼합 암호화
- **Java 프로세스 탐지**
  - `tests/java/linux/java_process_detector.cpp` : JVM 환경에서 후킹 준비 여부 확인 (순수 JCE는 NDJSON에 `java_runtime/jvm_detected` 안내 이벤트만 남음)

---

## 로그 포맷 예시
```json
{"ts":"2025-09-27T17:22:48.929Z","pid":37207,"tid":37207,
 "surface":"openssl","api":"ECDSA_do_sign","dir":"sign",
 "cipher":"secp256k1","key":"...","keylen":32,
 "iv":"388798ee15...","tag":"0965c6e3..."}
```

- `surface` : 어느 훅에서 발생했는지(OpenSSL/AF_ALG/java 등)
- `api` : 가로챈 함수명
- `dir` : 동작 방향(예: `enc`, `dec`, `sign` 등)
- `key`/`iv`/`tag` : 16진수 인코딩된 실제 키 자료

---

## 참고 사항

### 공통
- Pure Java(SunJCE 등) 경로는 키를 잡을 수 없으며, JNI를 통해 OpenSSL을 사용할 때만 후킹됩니다.
- 필요 시 `HOOK_VERBOSE=1`로 설정하면 stderr에 디버그 로그가 함께 출력됩니다.
- 분석 과정에서 기존 `HOOK_NDJSON` 값이 있었다면 CLI가 일시적으로 덮어쓰고 나중에 복구합니다.

### Linux 전용
- 정적 링크 또는 setuid 바이너리에는 LD_PRELOAD가 적용되지 않습니다.
- AF_ALG 샘플은 루트 실행이거나 `setcap cap_net_admin,cap_sys_admin+ep` 등 소켓 권한이 필요합니다.
- cryptodev 샘플은 `/dev/cryptodev` 장치가 있는 환경(예: 모듈 로드 가능한 VM/베어메탈)에서만 실행됩니다.
- BoringSSL 샘플은 별도 소스 빌드가 필요하며, `BUILD_SHARED_LIBS=ON`으로 공유 라이브러리를 만든 뒤 `BORINGSSL_ROOT`를 지정해야 LD_PRELOAD 후킹이 동작합니다.
- OpenSSL 이외의 샘플들(libsodium, GnuTLS, NSS 등)은 기본 빌드에 포함되지 않습니다.

### Windows 전용
- **현재 OpenSSL만 지원**: libsodium, GnuTLS 등 다른 라이브러리는 아직 구현되지 않았습니다.
- **관리자 권한**: DLL 인젝션 시 관리자 권한이 필요할 수 있습니다.
- **Detours 의존성**: Microsoft Detours 라이브러리가 반드시 필요합니다.
- **동적 링크 필요**: 정적 링크된 OpenSSL을 사용하는 프로그램은 후킹되지 않습니다.
