## LD_PRELOAD Hook Library
LD_PRELOAD 이용, Openssl 호출 hook 사용하여 key length, key 확인

## 요구사항
```
# Ubuntu/Debian 예시
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev
```

## 빌드
```
rm -rf build
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build -j

```

산출물
- build/libhook.so (LD_PRELOAD 훅 라이브러리)
- build/aes_lib_test, build/demo_target, build/ecc_sign_test, build/ecc_ECIES_test

## 실행
1. hook 없이 일반 실행
```
./build/aes_lib_test
```

2. hook 주입
```
# NDJSON 경로 지정 + 후킹 주입
# open은 부모경로를 만들어주지 않는다 필요시 폴더 미리 만들고 경로지정
export HOOK_NDJSON="$PWD/hook.ndjson"
HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so ./build/aes_lib_test

# 확인
ls -l "$HOOK_NDJSON"
tail -n 10 hook.ndjson | jq .
# 또는 파싱
jq . hook.ndjson
```

## 결과
```
➜  Hooking_linux_LD_PRELOAD ./build/aes_lib_test                                                                                                     
Ciphertext (hex): 2a4c00a5fb6794ba09cdfd43c4e556988960c1816b37021c9551a3ab20953f53607547c7dad91958e0cb963854382643
➜  Hooking_linux_LD_PRELOAD HOOK_VERBOSE=1 LD_PRELOAD=$PWD/build/libhook.so ./build/aes_lib_test                                                     

[hook] runtime init (verbose=1)
[HOOK] key: 38ba23b4dad4db8980ec64bf7f346e5d815fa25d671970186b7fbd637e464f8f
Ciphertext (hex): f60bb73e6035df69d9eecae41a09ad09a7dec952cd77600aa2de25cc61cf20a2b92e9fccec6634e1f5cf3acb25583aba
```

## 환경변수
| 변수             | 값       | 설명                            |
| -------------- | ------- | ----------------------------- |
| `HOOK_VERBOSE` | `0`/`1` | 1이면 훅/로거가 진단 메시지를 출력합니다.      |
| `HOOK_LOGFILE` | 파일경로    | 지정 시 stderr 대신 파일에 로그를 기록합니다. |


## 기타
- 정적 링크 바이너리, setuid 바이너리에는 LD_PRELOAD 미적용
- 초기 바인딩 문제를 피하려면:
```
LD_BIND_NOW=1 HOOK_VERBOSE=1 LD_PRELOAD=... ./your_program
```
- 훅 함수는 반드시 extern "C"(C 링크)를 유지해야 합니다(이름 맹글링 방지)
- 로깅은 printf 대신 write(2) 기반을 사용하여 훅 재귀 위험 줄임

## 출력 구조
```
{
  "ts": "2025-09-26T11:45:18.882Z",
  "pid": 5191,
  "tid": 5191,
  "api": "EVP_EncryptInit_ex",
  "dir": "enc",
  "cipher": "AES-256-CBC",
  "key": "ae9eb3be65da2aa4a8f723c483ba2f4e0b4a941748de5659a20f2305f889ea8a",
  "keylen": 32
}
```