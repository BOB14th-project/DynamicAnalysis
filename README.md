## LD_PRELOAD Hook Library
LD_PRELOAD 이용, OpenSSL 호출 hook 사용하여 암호화 키, 알고리즘 실시간 탐지

## 🚀 빠른 시작 (Quick Start)

```bash
# 1. 빌드
rm -rf build && cmake -S . -B build && cmake --build build -j

# 2. 환경 설정
export HOOK_NDJSON="$PWD/logs/hook.ndjson"

# 3. 테스트 (C++ OpenSSL)
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/lib/libhook.so ./build/bin/aes_lib_test

# 4. 결과 확인
cat logs/hook.ndjson | head -1
```

**즉시 확인할 수 있는 결과:**
```json
{"ts":"2025-09-27T04:29:55.358Z","pid":58247,"api":"EVP_EncryptInit_ex","dir":"enc","cipher":"AES-256-CBC","key":"f57845caf...","keylen":32}
```

## 요구사항
```
# Ubuntu/Debian 예시
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev

# Java 지원을 위한 JDK (선택적)
sudo apt-get install -y default-jdk

# 또는 OpenJDK 특정 버전
# sudo apt-get install -y openjdk-11-jdk openjdk-11-jdk-headless
```

## 빌드
```
rm -rf build
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build -j

```

**빌드 산출물**
- `build/libhook.so` - **메인 후킹 라이브러리** ⭐
- `build/java_process_detector` - **Java 프로세스 탐지 도구**
- `build/java_aes_test` - **JNI 암호화 테스트** (Java 지원시)
- `build/aes_lib_test`, `build/ecc_sign_test` - **C++ OpenSSL 테스트들**
- `JavaNativeSSL.java`, `JavaNativeSSL.c` - **Java+OpenSSL 예시 코드**

## 실행
1. hook 없이 일반 실행
```
./build/aes_lib_test
```

2. hook 주입

### 2-1. 준비 단계
```bash
# 1단계: 로그 파일 경로 설정 (결과가 저장될 NDJSON 파일)
export HOOK_NDJSON="$PWD/hook.ndjson"

# 2단계: 이전 로그 삭제 (선택적)
rm -f hook.ndjson
```

### 2-2. OpenSSL 프로그램 후킹 (C/C++ 프로그램)
```bash
# 기본 후킹 (verbose 모드로 디버그 정보 출력)
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so ./build/aes_lib_test

# 다른 테스트 프로그램들도 동일한 방식
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so ./build/ecc_sign_test
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so ./build/symm_aes_gcm_test
```

### 2-3. 추가 테스트 프로그램들

#### A. 기본 테스트 프로그램
```bash
# 기본 데모 (간단한 암호화 없음)
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/lib/libhook.so ./build/bin/demo_target

# 복합 OpenSSL 테스트 (RSA, AES, HMAC, PBKDF2, ECDH, TLS 모두 포함)
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/lib/libhook.so ./examples/complextest

# Java 프로세스 탐지 테스트
./build/bin/java_process_detector
```

#### B. Java + OpenSSL 네이티브 라이브러리 (완전 지원 ✅)
```bash
# 1. JNI 라이브러리 컴파일 (한 번만 실행)
cd examples/
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
javac JavaNativeSSL.java
gcc -shared -fPIC -I$JAVA_HOME/include -I$JAVA_HOME/include/linux JavaNativeSSL.c -lssl -lcrypto -o libjavanativessl.so

# 2. 후킹 실행
export LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/../build/lib/libhook.so java JavaNativeSSL
```

### 2-4. 결과 확인
```bash
# 로그 파일 존재 확인
ls -l "$HOOK_NDJSON"

# 로그 내용 확인 (jq가 설치된 경우)
tail -n 10 logs/hook.ndjson | jq .

# jq가 없는 경우 직접 확인
cat logs/hook.ndjson

# 실시간 모니터링 (새로운 터미널에서)
tail -f logs/hook.ndjson
```

## 결과
```
➜  Hooking_linux_LD_PRELOAD ./build/bin/aes_lib_test                                                                                                     
Ciphertext (hex): 2a4c00a5fb6794ba09cdfd43c4e556988960c1816b37021c9551a3ab20953f53607547c7dad91958e0cb963854382643
➜  Hooking_linux_LD_PRELOAD HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/lib/libhook.so ./build/bin/aes_lib_test                                                     

[hook] runtime init (verbose=1)
[HOOK] key: 38ba23b4dad4db8980ec64bf7f346e5d815fa25d671970186b7fbd637e464f8f
Ciphertext (hex): f60bb73e6035df69d9eecae41a09ad09a7dec952cd77600aa2de25cc61cf20a2b92e9fccec6634e1f5cf3acb25583aba
```

## LD_PRELOAD 후킹 원리 설명

### 1. LD_PRELOAD란?
- Linux에서 프로그램 실행 시 **특정 라이브러리를 우선 로드**하는 환경변수
- 원본 함수 대신 **우리가 만든 후킹 함수가 먼저 호출됨**
- 프로그램 소스코드 수정 없이 **런타임에 함수 동작을 가로채기** 가능

### 2. 명령어 구성 요소 설명
```bash
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so ./build/aes_lib_test
```

- **`HOOK_VERBOSE=1`**: 후킹 과정에서 디버그 메시지 출력 (0=끔, 1=켜짐)
- **`LD_PRELOAD=$PWD/build/libhook.so`**: 후킹 라이브러리를 우선 로드
- **`./build/aes_lib_test`**: 분석하려는 대상 프로그램

### 3. 후킹 동작 과정
1. 프로그램이 `EVP_EncryptInit_ex()` 호출
2. LD_PRELOAD에 의해 **우리 후킹 함수가 먼저 실행됨**
3. 후킹 함수에서 **키, 알고리즘 정보 추출 및 로깅**
4. 원본 OpenSSL 함수 호출하여 **정상적인 암호화 수행**
5. 결과를 NDJSON 파일에 저장

## 환경변수
| 변수             | 값       | 설명                            |
| -------------- | ------- | ----------------------------- |
| `HOOK_VERBOSE` | `0`/`1` | 1이면 훅/로거가 진단 메시지를 출력합니다.      |
| `HOOK_LOGFILE` | 파일경로    | 지정 시 stderr 대신 파일에 로그를 기록합니다. |
| `HOOK_NDJSON`  | 파일경로    | 탐지된 암호화 정보를 저장할 NDJSON 파일 경로 |


## Java 지원

### 🎯 지원 범위
| 유형 | 지원 상태 | 설명 |
|------|----------|------|
| **Java + JNI + OpenSSL** | ✅ **완전 지원** | JNI를 통해 OpenSSL을 호출하는 Java 프로그램 |
| **Java 순수 암호화** | ⚠️ **제한적** | SunJCE 등 순수 Java 구현은 OpenSSL 미사용 |
| **Java ELF 실행파일** | ✅ **탐지 가능** | GraalVM Native Image 등 |
| **JAR 파일** | ✅ **프로세스 탐지** | JVM 환경 및 라이브러리 탐지 |

### 🔧 Java 암호화 후킹 방법

#### 1. **네이티브 라이브러리 방식 (추천)**
```java
// JavaNativeSSL.java - JNI를 통한 OpenSSL 직접 호출
public native byte[] nativeAESEncrypt(byte[] key, byte[] data);
```
- ✅ **완전한 키 추출**: OpenSSL EVP 함수 직접 후킹
- ✅ **실시간 탐지**: 암호화 순간 즉시 캡처
- ✅ **상세 정보**: 키, 알고리즘, 키길이, 타임스탬프

#### 2. **하이브리드 애플리케이션**
- Spring Boot + JNI 암호화 모듈
- Bouncy Castle + OpenSSL Provider
- 암호화 전용 네이티브 라이브러리 사용

### 🔍 Java 탐지 기술
1. **ELF 분석**: Java 바이너리 시그니처 (`java`, `openjdk` 등)
2. **프로세스 메모리**: `/proc/self/maps`에서 JVM 라이브러리 스캔
3. **환경 변수**: `JAVA_HOME`, `CLASSPATH` 확인
4. **동적 라이브러리**: `libjvm.so`, `libhotspot.so` 탐지

## 사용 예시

### 1. Java 프로세스 탐지
```bash
# Java 프로세스 분석 도구 실행
./build/java_process_detector

# 특정 ELF 파일 분석
./build/java_process_detector /usr/bin/java /path/to/some_binary
```

### 2. Java 애플리케이션 후킹 (완전 동작 예시)

#### 🎯 완전 동작하는 Java+OpenSSL 예시
```bash
# 1. 준비 (한 번만 실행)
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
javac JavaNativeSSL.java  
gcc -shared -fPIC -I$JAVA_HOME/include -I$JAVA_HOME/include/linux \
    JavaNativeSSL.c -lssl -lcrypto -o libjavanativessl.so

# 2. 실행 & 후킹
export LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so java JavaNativeSSL

# 3. 결과 - 6개의 암호화 이벤트 캡처됨! 
cat hook.ndjson | wc -l  # 출력: 6
```

#### 📁 기타 Java 프로그램 후킹
```bash
# 일반 JAR 파일 (OpenSSL 사용하는 경우만 탐지)
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so java -jar app.jar

# 클래스패스 지정
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so java -cp classes MyApp

# GraalVM Native Image
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so ./native-app
```

### 3. 실제 테스트 결과

#### C/C++ OpenSSL 프로그램
```bash
$ HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so ./build/aes_lib_test
[ELF] Java detection initialized
[hook] runtime init (verbose=1)
[HOOK] EVP_EncryptInit_ex enc keylen: 256 bits
[HOOK] key: 28a41d142ebe0d3ae9a8c17d2020f95184cdc69723fedaada7bfaaf74fa28e93
Ciphertext (hex): 5b7d21b6346edf618479096789fc7c0d...

$ cat hook.ndjson
{"ts":"2025-09-27T04:29:55.358Z","pid":58247,"tid":58247,"api":"EVP_EncryptInit_ex","dir":"enc","cipher":"AES-256-CBC","key":"f57845caf767bdb61bda08598df95d5bb8f0ebde...","keylen":32}
```

#### Java + OpenSSL 네이티브 라이브러리
```bash
$ HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so java JavaNativeSSL
[ELF] Running inside JVM process
[JAVA-OPENSSL] EVP_EncryptInit_ex enc keylen: 256 bits
[JAVA-OPENSSL] key: 0d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6
Encryption successful!

$ cat hook.ndjson
{"ts":"2025-09-27T04:42:41.497Z","pid":61180,"tid":61181,"api":"java_openssl","dir":"java","cipher":"AES-256-CBC","key":"0d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6","keylen":32}
```

#### Java 프로세스 탐지
```bash
$ ./build/java_process_detector
=== Java Process Analysis ===
✓ Running inside JVM process
✓ JAVA_HOME: /usr/lib/jvm/java-11-openjdk-amd64
✓ Valid ELF file
✓ Appears to be Java-related executable
```

## ❗ 문제 해결 (Troubleshooting)

### Q1: hook.ndjson 파일이 비어있어요
```bash
# 원인: Java가 순수 SunJCE를 사용 (OpenSSL 미사용)
# 해결: JNI+OpenSSL 버전 사용
javac JavaNativeSSL.java
gcc -shared -fPIC -I$JAVA_HOME/include -I$JAVA_HOME/include/linux JavaNativeSSL.c -lssl -lcrypto -o libjavanativessl.so
export LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so java JavaNativeSSL
```

### Q2: "Failed to load native library" 에러
```bash
# 원인: JNI 라이브러리 경로 문제
# 해결: LD_LIBRARY_PATH 설정
export LD_LIBRARY_PATH=$PWD:$LD_LIBRARY_PATH
ls -la libjavanativessl.so  # 파일 존재 확인
```

### Q3: Java 프로세스 탐지는 되는데 키가 안 잡혀요
```bash
# 정상: Java 환경 탐지 성공
[ELF] Running inside JVM process ✅

# 원인: 해당 Java 프로그램이 OpenSSL을 사용하지 않음
# 해결: strace로 확인
strace -f java YourApp 2>&1 | grep -i ssl
```

### Q4: 빌드 에러 "JNI not found"
```bash
# 해결: JDK 설치
sudo apt-get install default-jdk
# 또는 수동으로 JAVA_HOME 설정
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
```

## 📋 제한사항 및 주의사항
- ❌ **정적 링크 바이너리**: LD_PRELOAD 미적용
- ❌ **setuid 바이너리**: 보안상 LD_PRELOAD 무시
- ⚠️ **순수 Java 암호화**: SunJCE, Bouncy Castle 등은 OpenSSL 미사용
- ✅ **하이브리드 앱**: Java + JNI + OpenSSL 조합은 완전 지원
- 🔧 **초기 바인딩 문제**: `LD_BIND_NOW=1` 사용 고려

## 출력 구조

### OpenSSL 후킹 결과
```json
{
  "ts": "2025-09-26T11:45:18.882Z",
  "pid": 5191,
  "tid": 5191,
  "api": "EVP_EncryptInit_ex",
  "dir": "enc",
  "cipher": "AES-256-CBC",
  "key": "ae9eb3be65da2aa4a8f723c483ba2f4e0b4a941748de5659a20f2305f88aeaa0",
  "keylen": 32
}
```

### Java+OpenSSL 후킹 결과 (실제 출력)
```json
{
  "ts": "2025-09-27T04:42:41.497Z",
  "pid": 61180,
  "tid": 61181,
  "api": "java_openssl",
  "dir": "java", 
  "cipher": "AES-256-CBC",
  "key": "0d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6",
  "keylen": 32
}
```

### 기능 비교표
| 항목 | C/C++ OpenSSL | Java+OpenSSL | 순수 Java |
|------|--------------|-------------|-----------|
| **키 추출** | ✅ 완벽 | ✅ 완벽 | ❌ 불가능 |
| **실시간 탐지** | ✅ 즉시 | ✅ 즉시 | ❌ 해당없음 |
| **알고리즘 식별** | ✅ 상세 | ✅ 상세 | ⚠️ 제한적 |
| **적용 범위** | 모든 OpenSSL 프로그램 | JNI 사용 Java | 프로세스 탐지만 |