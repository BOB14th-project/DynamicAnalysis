# LD_PRELOAD 암호화 동적 분석 도구

OpenSSL · Linux 커널 AF_ALG · JNI 기반 Java 등에서 수행되는 암호화 연산을 `LD_PRELOAD`로 훅킹하여 실시간으로 키/IV/태그 정보를 캡처하는 도구입니다. 바이너리 앞에 공유 라이브러리(`libhook.so`)를 선주입하면, OpenSSL API 호출이 가로채져 NDJSON 로그로 떨어집니다. `dynamic_analysis_cli` 실행 파일을 이용하면 대상 프로그램을 자동으로 LD_PRELOAD 주입해 분석한 뒤, 수집된 이벤트를 즉시 출력까지 해 줍니다.

---

## 구성 요소
- `libhook.so` : 메인 훅킹 라이브러리. OpenSSL EVP/Provider/ECC, AF_ALG, JNI 경로를 감지해 로그를 남깁니다.
- `dynamic_analysis_cli` : `dynamic_analysis(<dir>, <binary>)`를 호출하는 CLI. Linux에서 대상 실행 파일을 포크/exec로 실행하고 `LD_PRELOAD`/`HOOK_VERBOSE`/`HOOK_NDJSON` 환경을 자동 설정합니다.
- `logs/*.ndjson` : 분석 결과가 쌓이는 NDJSON 라인 로그. 각 이벤트는 `ts/pid/tid/api/cipher/key/...` 필드를 포함합니다.
- `tests/` : 지원되는 모든 훅 경로를 다루는 샘플 프로그램 모음 (OpenSSL CBC/GCM/ECC/Provider, AF_ALG, JNI 등).

---

## 빌드
```bash
cmake -S . -B build
cmake --build build -j
```

- 주요 산출물: `build/lib/libhook.so`, `build/bin/dynamic_analysis_cli`, `build/bin/*` 테스트 실행 파일들
- 기본적으로 OpenSSL 1.1/3.0 모두 지원하며, JNI가 감지되면 Java 관련 훅도 자동 활성화됩니다.

---

## 사용법
1. 로그 파일 경로 지정 (선택)
   ```bash
   export HOOK_NDJSON="$PWD/logs/analysis.ndjson"
   ```
2. 동적 분석 실행 (예: OpenSSL AES CBC 테스트)
   ```bash
   ./build/bin/dynamic_analysis_cli ./build/bin/openssl_aes_lib_test
   ```
   모든 샘플을 한 번에 돌려보고 싶다면 다음 스크립트를 사용할 수 있습니다.
   ```bash
   ./scripts/run_all_dynamic_tests.sh
   ```
3. 결과 확인
   ```bash
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
  - `tests/af_alg/af_alg_aes_gcm_demo.c` : 소켓 기반 커널 AES skcipher 키 설정
- **cryptodev**
  - `tests/cryptodev/ioctl/cryptodev_aes_cbc_demo.c` : `/dev/crypto` ioctl 기반 AES-256-CBC 세션
- **libsodium**
  - `tests/libsodium/aead/chacha20_poly1305_demo.c` : `crypto_aead_chacha20poly1305_ietf_*`
  - `tests/libsodium/aead/xchacha20_poly1305_demo.c` : `crypto_aead_xchacha20poly1305_ietf_*`
  - `tests/libsodium/secretbox/libsodium_secretbox_demo.c` : `crypto_secretbox_*`
  - `tests/libsodium/box/libsodium_box_demo.c` : `crypto_box_*`
- **GnuTLS**
  - `tests/GnuTLS/symmetric/gnutls_aes_gcm_demo.c` : `gnutls_cipher_*` AES-256-GCM 호출
- **NSS**
  - `tests/NSS/symmetric/nss_aes_gcm_demo.c` : `PK11_Encrypt` AES-256-GCM
- **boringSSL**
  - `tests/boringSSL/symmetric/boringssl_aes_gcm_demo.cc` : `EVP_AEAD_CTX_seal` AES-256-GCM
- **mbedTLS**
  - `tests/mbedTLS/symmetric/mbedtls_aes_gcm_demo.c` : `mbedtls_gcm_crypt_and_tag`
- **wolfSSL**
  - `tests/wolfSSL/symmetric/wolfssl_aes_gcm_demo.c` : `wc_AesGcmEncrypt`
- **PyCryptodome**
  - `tests/PyCryptodome/symmetric/aes_gcm_demo.py` : Python AES-256-GCM (CPython + LD_PRELOAD 경우)
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
- 정적 링크 또는 setuid 바이너리에는 LD_PRELOAD가 적용되지 않습니다.
- Pure Java(SunJCE 등) 경로는 키를 잡을 수 없으며, JNI를 통해 OpenSSL을 사용할 때만 후킹됩니다.
- OpenSSL 이외의 샘플들은 기본 빌드에 포함되지 않습니다. 필요 시 각 라이브러리를 설치한 뒤 개별 명령으로 빌드하여 `dynamic_analysis_cli`와 함께 사용하세요.
- 필요 시 `HOOK_VERBOSE=1`로 설정하면 stderr에 디버그 로그가 함께 출력됩니다.
- 분석 과정에서 기존 `HOOK_NDJSON` 값이 있었다면 CLI가 일시적으로 덮어쓰고 나중에 복구합니다.
