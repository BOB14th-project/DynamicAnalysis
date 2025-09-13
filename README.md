## 동적 분석 수행

정적 분석에서 얻은 환경 정보로 동적 분석 수행해야 할 것으로 판단

agent.js 파일에서 필터링을 하지 않으면 모든 함수에 후킹

## 작동 방식, Frida-core 원리

추가 예정...

## 사용 방법

예제 실행파일 aes_lib (test_code 활용)

```
uv run python3 main.py aes_lib
python3 print_params.py analysis_result_aes_lib.json 

# 1. 동적 분석 실행
uv run python3 main.py aes_lib

# 2. 상세 파라미터 확인 (선택)
python3 print_params.py analysis_result_aes_lib.json

# 3. EVP API CSV 추출 (주요 결과물)
python3 extract_evp.py analysis_result_aes_lib.json

# 4. 필터링된 요약 보기 (선택)
python3 filter_trace.py analysis_result_aes_lib.json
```


### 테스트 결과

#### 상세 파라미터 출력 결과 (TXT)
![파라미터 TXT 결과](images/params_txt.png)

#### EVP API 추출 결과 (CSV)
![EVP CSV 결과](images/evp_csv.png)



