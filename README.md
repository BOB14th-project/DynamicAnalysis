# 🔐 암호 라이브러리 동적 분석 도구

> 🛡️ **크로스 플랫폼 암호화 API 후킹 & 실시간 키 추출 프레임워크**

OpenSSL, Linux 커널 AF_ALG, JNI 기반 Java 등 다양한 암호화 실행 경로를 훅킹해 실시간으로 키/IV/태그 정보를 수집하는 크로스 플랫폼 분석 도구입니다.

## 🎯 주요 기능

- **🐧 Linux**: `LD_PRELOAD`로 `libhook.so`를 선주입해 암호 API를 가로채고 NDJSON 로그 생성
- **🪟 Windows**: Microsoft Detours를 사용한 DLL 인젝션으로 OpenSSL API 후킹
- **📊 실시간 분석**: 대상 프로그램을 자동으로 주입 실행한 뒤 수집된 이벤트를 표준 출력과 로그 파일에 기록
- **🔧 다중 라이브러리 지원**: OpenSSL, BoringSSL, libsodium, GnuTLS, NSS, mbedTLS, wolfSSL 등

---

## 📦 구성 요소

### 핵심 라이브러리
- **🐧 Linux**: `libhook.so` - LD_PRELOAD 기반 훅킹 라이브러리
  - OpenSSL EVP/Provider/ECC 경로
  - Linux 커널 AF_ALG 소켓
  - JNI 기반 Java 암호화 경로
  - cryptodev ioctl 인터페이스

- **🪟 Windows**: `hook.dll` - Detours 기반 훅킹 라이브러리
  - OpenSSL EVP API 후킹 지원

### CLI 도구
- **`dynamic_analysis_cli`** : 크로스 플랫폼 분석 자동화 도구
  - **Linux**: 대상 실행 파일을 포크/exec로 실행하고 `LD_PRELOAD` 환경 자동 설정
  - **Windows**: `DetourCreateProcessWithDll()`로 프로세스 생성과 동시에 DLL 주입

### 로그 및 테스트
- **`logs/*.ndjson`** : 분석 결과 NDJSON 라인 로그 (타임스탬프, PID, TID, API, cipher, key 등)
- **`tests/`** : 각 암호화 라이브러리별 테스트 코드 모음

---

## 🔨 빌드

### Linux
```bash
cmake -S . -B build-linux
cmake --build build-linux -j
```

### Windows (Visual Studio)
```cmd
cmake -S . -B build-windows `
  -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="C:/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows `
  -DCMAKE_PREFIX_PATH="C:/dev/detours"

cmake --build build-windows --config Release
```

> ⚠️ **Windows 빌드 전제 조건**
> - vcpkg 툴체인이 설정되어 있어야 합니다
> - Detours 경로가 다르면 `-DCMAKE_PREFIX_PATH` 값을 조정하세요

### 📁 주요 산출물

| 플랫폼 | 훅킹 라이브러리 | CLI 도구 | 테스트 바이너리 |
|--------|----------------|----------|----------------|
| **Linux** | `build-linux/lib/libhook.so` | `build-linux/bin/dynamic_analysis_cli` | `build-linux/bin/*_test` |
| **Windows** | `build-windows/lib/hook.dll` | `build-windows/bin/Release/dynamic_analysis_cli.exe` | `build-windows/bin/Release/*_test.exe` |

---

## 🚀 사용법

### 0️⃣ 의존 라이브러리 설치

#### Linux (Ubuntu 24.04 기준)

**필수 개발 도구**
```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake pkg-config \
  libssl-dev
```

**암호화 라이브러리 (선택)**
```bash
sudo apt-get install -y \
  libsodium-dev gnutls-dev \
  libnss3-dev libnspr4-dev libp11-kit-dev \
  libmbedtls-dev libwolfssl-dev
```

**Java JNI 지원 (선택)**
```bash
# SDKMAN 등의 도구로 JDK 설치 후 JAVA_HOME 설정
sdk install java 21.0.4-amzn
```

**cryptodev 모듈 (선택, VM/베어메탈 환경)**
```bash
sudo apt-get install -y cryptodev-dkms libcryptodev-dev
sudo modprobe cryptodev && ls -l /dev/cryptodev
```

**BoringSSL (선택, 소스 빌드 필요)**
```bash
# 1) BoringSSL 클론
git clone https://github.com/google/boringssl.git

# 2) 공유 라이브러리로 빌드
cmake -S boringssl -B boringssl/build \
  -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
ninja -C boringssl/build crypto ssl

# 3) 프로젝트 빌드 시 경로 지정
cmake -S . -B build \
  -DBORINGSSL_ROOT=/절대/경로/boringssl \
  -UBORINGSSL_CRYPTO_LIBRARY -UBORINGSSL_INCLUDE_DIR
```

**PyCryptodome (선택)**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome
```

> 💡 WSL2 기본 커널은 모듈 로드를 지원하지 않으므로 cryptodev 샘플은 자동 건너뛰기됩니다.

#### Windows

| 구분 | 패키지 | 설치 방법 |
|------|--------|-----------|
| **필수** | Microsoft Detours | [GitHub 릴리스](https://github.com/microsoft/Detours) |
| **필수** | OpenSSL for Windows | vcpkg 또는 직접 빌드 |
| **필수** | Visual Studio 2019/2022 | 또는 MinGW |

---

### 1️⃣ 동적 분석 실행

#### Linux
```bash
# 로그 파일 경로 지정 (선택)
export HOOK_NDJSON="$PWD/logs/analysis.ndjson"

# OpenSSL AES CBC 테스트 실행
./build-linux/bin/dynamic_analysis_cli ./build-linux/bin/openssl_aes_lib_test
```

#### Windows
```cmd
# OpenSSL AES CBC 테스트 실행 (관리자 권한 필요시)
.\build-windows\bin\Release\dynamic_analysis_cli.exe .\build-windows\bin\Release\openssl_aes_lib_test.exe
```

#### 모든 테스트 일괄 실행 (Linux만)
```bash
./scripts/run_all_dynamic_tests.sh
```

---

### 2️⃣ 결과 확인

```bash
# Linux/Windows 공통
cat logs/analysis.ndjson
```

동적 분석 CLI는 실행 종료 후 `captured events:` 블록에 기록된 NDJSON 라인을 표준 출력으로 보여줍니다.

---

## 🧪 테스트 코드 개요

각 샘플은 후킹 대상 경로별로 최소한의 재현 환경을 제공합니다.

### 📌 OpenSSL (CMake 빌드 대상)

| 테스트 파일 | 설명 |
|------------|------|
| `openssl_aes_lib_test.cpp` | EVP AES-256-CBC 초기화 → 키 추출 |
| `openssl_symm_aes_gcm_test.cpp` | EVP AES-256-GCM → 키/IV/TAG 로깅 |
| `openssl_ecc_sign_test.cpp` | ECDSA 키 생성·서명 → ECC 개인키/서명 로그 |
| `openssl_ecc_ecies_test.cpp` | ECDH + HKDF + AES-GCM 복합 시나리오 |
| `openssl_provider_ex2_test.cpp` | OpenSSL 3 `*_ex2` 경로 |
| `openssl_provider_ex2_params_test.cpp` | OSSL_PARAM 기반 설정 값 |

### 📌 Linux AF_ALG

| 테스트 파일 | 설명 |
|------------|------|
| `af_alg_skcipher_aes_cbc_demo.c` | AES-CBC skcipher 키/IV 설정 |
| `af_alg_aes_gcm_demo.c` | AES-GCM AEAD 키/IV/assoc 설정 |
| `af_alg_hmac_sha256_demo.c` | HMAC-SHA256 hash 키 설정 |
| `af_alg_akcipher_demo.c` | 비대칭키 암호 연산 |

### 📌 cryptodev

| 테스트 파일 | 설명 |
|------------|------|
| `cryptodev_aes_cbc_demo.c` | `/dev/crypto` ioctl 기반 AES-256-CBC 세션 |
| `cryptodev_hmac_sha256_demo.c` | HMAC-SHA256 세션 키 설정 |
| `cryptodev_rsa_demo.c` | RSA 모듈러 연산 (CIOCKEY) |

### 📌 libsodium

| 테스트 파일 | 설명 |
|------------|------|
| `chacha20_poly1305_demo.c` | `crypto_aead_chacha20poly1305_ietf_*` |
| `xchacha20_poly1305_demo.c` | `crypto_aead_xchacha20poly1305_ietf_*` |
| `libsodium_secretbox_demo.c` | `crypto_secretbox_*` |
| `libsodium_box_demo.c` | `crypto_box_*` |
| `libsodium_sign_demo.c` | `crypto_sign_*` |

### 📌 GnuTLS

| 테스트 파일 | 설명 |
|------------|------|
| `gnutls_aes_gcm_demo.c` | `gnutls_cipher_*` AES-256-GCM |
| `gnutls_aes_gcm_roundtrip_demo.c` | AES-256-GCM 암·복호화 |
| `gnutls_aes_cbc_demo.c` | AES-256-CBC |

### 📌 NSS

| 테스트 파일 | 설명 |
|------------|------|
| `nss_aes_gcm_demo.c` | `PK11_Encrypt` AES-256-GCM |
| `nss_aes_gcm_roundtrip_demo.c` | AES-256-GCM 암·복호화 |
| `nss_aes_cbc_demo.c` | AES-256-CBC |

### 📌 BoringSSL

| 테스트 파일 | 설명 |
|------------|------|
| `boringssl_aes_gcm_demo.cc` | AES-256-GCM 단방향 암호화 |
| `boringssl_aes_gcm_roundtrip_demo.cc` | AES-256-GCM 암·복호화 |
| `boringssl_chacha20_poly1305_demo.cc` | ChaCha20-Poly1305 암호화 |
| `boringssl_xchacha20_poly1305_demo.cc` | XChaCha20-Poly1305 암호화 |

> ⚠️ BoringSSL 빌드에서 XChaCha20이 비활성화된 경우 해당 데모는 "not enabled" 메시지 출력 후 종료

### 📌 mbedTLS

| 테스트 파일 | 설명 |
|------------|------|
| `mbedtls_aes_gcm_demo.c` | `mbedtls_gcm_crypt_and_tag` |
| `mbedtls_hmac_sha256_demo.c` | HMAC-SHA256 |
| `mbedtls_ecdsa_demo.c` | ECDSA 서명 |
| `mbedtls_rsa_demo.c` | RSA 암호화 |

### 📌 wolfSSL

| 테스트 파일 | 설명 |
|------------|------|
| `wolfssl_aes_gcm_demo.c` | `wc_AesGcmSetKey` / `wc_AesGcmEncrypt` |
| `wolfssl_aes_cbc_demo.c` | `wc_AesSetKey` / `wc_AesCbcEncrypt` |
| `wolfssl_hmac_sha256_demo.c` | `wc_HmacSetKey` / `wc_HmacFinal` |

### 📌 PyCryptodome

| 테스트 파일 | 설명 |
|------------|------|
| `aes_gcm_demo.py` | Python AES-256-GCM |
| `aes_gcm_aad_demo.py` | AAD 포함 AES-256-GCM / 검증 흐름 |
| `aes_gcm_stream_demo.py` | 다중 `encrypt()` 호출로 스트리밍 암호화 |

> 💡 PyCryptodome은 기본적으로 `RTLD_DEEPBIND`를 사용하므로, `run_pycryptodome_aes_gcm_demo.sh` 스크립트에서 `PYCRYPTODOME_DISABLE_DEEPBIND=1`을 설정해 LD_PRELOAD 후킹을 활성화합니다.

### 📌 Java JNI + OpenSSL

| 테스트 파일 | 설명 |
|------------|------|
| `JavaNativeSSL.*` | JNI/네이티브 혼합 암호화 |
| `java_process_detector.cpp` | JVM 환경에서 후킹 준비 여부 확인 |

> 💡 순수 JCE는 NDJSON에 `java_runtime/jvm_detected` 안내 이벤트만 남습니다.

---

## 📄 로그 포맷 예시

```json
{
  "ts": "2025-09-27T17:22:48.929Z",
  "pid": 37207,
  "tid": 37207,
  "surface": "openssl",
  "api": "ECDSA_do_sign",
  "dir": "sign",
  "cipher": "secp256k1",
  "key": "...",
  "keylen": 32,
  "iv": "388798ee15...",
  "tag": "0965c6e3..."
}
```

### 필드 설명

| 필드 | 설명 |
|------|------|
| `ts` | 이벤트 타임스탬프 (ISO 8601) |
| `pid` | 프로세스 ID |
| `tid` | 스레드 ID |
| `surface` | 훅 소스 (openssl, af_alg, java 등) |
| `api` | 가로챈 함수명 |
| `dir` | 동작 방향 (`enc`, `dec`, `sign` 등) |
| `cipher` | 암호 알고리즘/곡선 이름 |
| `key` | 16진수 인코딩된 키 |
| `iv` | 초기화 벡터 (해당 시) |
| `tag` | 인증 태그 (AEAD 암호화 시) |

---

## ⚙️ 환경 변수

| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `HOOK_NDJSON` | 로그 파일 경로 지정 | `logs/{binary_name}_{timestamp}.ndjson` |
| `HOOK_VERBOSE` | 상세 디버그 로그 출력 (stderr) | `0` (비활성화) |
| `HOOK_LIBRARY_PATH` | 훅 라이브러리 경로 수동 지정 (Linux) | 자동 탐지 |
| `PYCRYPTODOME_DISABLE_DEEPBIND` | PyCryptodome RTLD_DEEPBIND 비활성화 | `0` |

---

## 📌 참고 사항

### 공통
- ✅ Pure Java (SunJCE 등) 경로는 키를 잡을 수 없으며, JNI를 통해 OpenSSL을 사용할 때만 후킹됩니다
- ✅ `HOOK_VERBOSE=1`로 설정하면 stderr에 디버그 로그가 함께 출력됩니다
- ✅ 분석 과정에서 기존 `HOOK_NDJSON` 값이 있었다면 CLI가 일시적으로 덮어쓰고 나중에 복구합니다

### Linux 전용
- ⚠️ 정적 링크 또는 setuid 바이너리에는 LD_PRELOAD가 적용되지 않습니다
- ⚠️ AF_ALG 샘플은 루트 실행이거나 `setcap cap_net_admin,cap_sys_admin+ep` 등 소켓 권한이 필요합니다
- ⚠️ cryptodev 샘플은 `/dev/cryptodev` 장치가 있는 환경(모듈 로드 가능한 VM/베어메탈)에서만 실행됩니다
- ⚠️ BoringSSL 샘플은 별도 소스 빌드가 필요하며, `BUILD_SHARED_LIBS=ON`으로 공유 라이브러리를 만든 뒤 `BORINGSSL_ROOT`를 지정해야 LD_PRELOAD 후킹이 동작합니다
- ⚠️ OpenSSL 이외의 샘플들(libsodium, GnuTLS, NSS 등)은 기본 빌드에 포함되지 않습니다

### Windows 전용
- ⚠️ **현재 OpenSSL만 지원**: Detours 기반으로 OpenSSL EVP 경로를 후킹합니다. 기타 라이브러리는 추후 확장 예정입니다
- ⚠️ **관리자 권한**: DLL 인젝션 시 관리자 권한이 필요할 수 있습니다
- ⚠️ **Detours 의존성**: Microsoft Detours 라이브러리가 반드시 필요합니다
- ⚠️ **동적 링크 필요**: 정적 링크된 OpenSSL을 사용하는 프로그램은 후킹되지 않습니다


