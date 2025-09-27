#pragma once

// 키/IV/태그를 hex로 넣는 전용 로거
void ndjson_init_from_env(void);
void ndjson_log_key_event(const char* surface,
                          const char* api,
                          const char* direction,         // "enc"/"dec" 또는 NULL
                          const char* cipher_name,       // NULL 허용
                          const uint8_t* key, int keylen,
                          const uint8_t* iv,  int ivlen,
                          const uint8_t* tag, int taglen);

