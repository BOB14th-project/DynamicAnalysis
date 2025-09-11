// mbedTLS 전용 암호화 후킹 에이전트
// 대상: libmbedtls.so, libmbedcrypto.so, libmbedx509.so (IoT/임베디드)

class MbedTLSAgent {
    constructor() {
        this.operationId = 0;
        this.startTime = Date.now();
        this.mbedtls = null;
        this.mbedcrypto = null;
        this.mbedx509 = null;
        this.mbedtlsVersion = null;
        this.contexts = new Map(); // 컨텍스트 추적
    }

    log(category, data) {
        send({
            type: 'mbedtls_capture',
            category: category,
            timestamp: Date.now() - this.startTime,
            agent: 'mbedtls',
            data: data
        });
    }

    // 메모리 덤프
    dumpMemory(ptr, size, label) {
        try {
            if (ptr.isNull() || size <= 0) return null;
            
            const data = Memory.readByteArray(ptr, size);
            const bytes = new Uint8Array(data);
            const hex = Array.from(bytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            
            this.log('memory_dump', {
                label: label,
                address: ptr.toString(),
                size: size,
                hex: hex.substring(0, 512),
                entropy: this.calculateEntropy(bytes)
            });
            
            return hex;
        } catch (e) {
            console.log(`[!] 메모리 덤프 실패 (${label}): ${e.message}`);
            return null;
        }
    }

    calculateEntropy(data) {
        const freq = new Map();
        for (let byte of data) {
            freq.set(byte, (freq.get(byte) || 0) + 1);
        }
        
        let entropy = 0;
        const len = data.length;
        for (let count of freq.values()) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    // mbedTLS 에러 코드 해석
    mbedErrorToString(error) {
        const errorMap = {
            0x0000: "SUCCESS",
            0x2700: "AES_INVALID_KEY_LENGTH",
            0x2800: "AES_INVALID_INPUT_LENGTH", 
            0x3080: "BASE64_BUFFER_TOO_SMALL",
            0x4400: "BIGNUM_ALLOC_FAILED",
            0x4500: "BIGNUM_INVALID_CHARACTER",
            0x6000: "CTR_DRBG_ENTROPY_SOURCE_FAILED",
            0x7200: "CIPHER_FEATURE_UNAVAILABLE",
            0x7280: "CIPHER_BAD_INPUT_DATA",
            0x7300: "CIPHER_ALLOC_FAILED",
            0x7380: "CIPHER_INVALID_PADDING",
            0x7400: "CIPHER_FULL_BLOCK_EXPECTED",
            0x7480: "CIPHER_AUTH_FAILED"
        };
        
        const absError = Math.abs(error);
        return errorMap[absError] || `MBEDTLS_ERROR_0x${absError.toString(16).toUpperCase()}`;
    }

    // mbedTLS 라이브러리 초기화
    initializeMbedTLS() {
        console.log("[+] mbedTLS 라이브러리 탐지 중...");

        // 다양한 mbedTLS 라이브러리 이름 시도
        const mbedtlsNames = [
            "libmbedtls.so", "libmbedtls.so.13", "libmbedtls.so.12",
            "mbedtls.dll", "libmbedtls.a"
        ];
        
        const mbedcryptoNames = [
            "libmbedcrypto.so", "libmbedcrypto.so.7", "libmbedcrypto.so.6",
            "mbedcrypto.dll"
        ];

        const mbedx509Names = [
            "libmbedx509.so", "libmbedx509.so.1", "libmbedx509.so.0",
            "mbedx509.dll"
        ];

        // 라이브러리 탐지
        for (let name of mbedtlsNames) {
            this.mbedtls = Process.findModuleByName(name);
            if (this.mbedtls) {
                console.log(`[+] mbedTLS 발견: ${name} @ ${this.mbedtls.base}`);
                break;
            }
        }

        for (let name of mbedcryptoNames) {
            this.mbedcrypto = Process.findModuleByName(name);
            if (this.mbedcrypto) {
                console.log(`[+] mbedcrypto 발견: ${name} @ ${this.mbedcrypto.base}`);
                break;
            }
        }

        for (let name of mbedx509Names) {
            this.mbedx509 = Process.findModuleByName(name);
            if (this.mbedx509) {
                console.log(`[+] mbedx509 발견: ${name} @ ${this.mbedx509.base}`);
                break;
            }
        }

        if (!this.mbedtls && !this.mbedcrypto) {
            throw new Error("mbedTLS 라이브러리를 찾을 수 없습니다");
        }

        this.detectMbedTLSVersion();
    }

    detectMbedTLSVersion() {
        try {
            // mbedTLS 버전 문자열 탐지 시도
            const versionFunc = Module.findExportByName(
                this.mbedtls?.name || this.mbedcrypto?.name, 
                "mbedtls_version_get_string"
            );
            
            if (versionFunc) {
                const getString = new NativeFunction(versionFunc, 'pointer', []);
                const versionPtr = getString();
                this.mbedtlsVersion = Memory.readUtf8String(versionPtr);
                console.log(`[+] mbedTLS 버전: ${this.mbedtlsVersion}`);
            }
        } catch (e) {
            console.log(`[!] mbedTLS 버전 탐지 실패: ${e.message}`);
        }
    }

    // AES 암호화 후킹
    hookAESOperations() {
        console.log("[+] AES 암호화 함수 후킹...");

        // mbedtls_aes_setkey_enc - AES 암호화 키 설정
        this.hookFunction("mbedtls_aes_setkey_enc", {
            args: ['pointer', 'pointer', 'uint'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.key = args[1];
                this.keybits = args[2].toInt32();

                // 키 데이터 캡처
                const keyBytes = this.keybits / 8;
                if (!this.key.isNull() && keyBytes > 0) {
                    agent.dumpMemory(this.key, keyBytes, `mbedtls_aes_key_enc_${this.opId}`);
                }

                // 컨텍스트 저장
                agent.contexts.set(this.ctx.toString(), {
                    opId: this.opId,
                    type: 'aes_encrypt',
                    keySize: this.keybits
                });

                agent.log('aes_key_setup', {
                    operation_id: this.opId,
                    function: 'mbedtls_aes_setkey_enc',
                    key_size_bits: this.keybits,
                    key_size_bytes: keyBytes
                });
            },
            onLeave: function(retval) {
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_aes_setkey_enc',
                    result: retval.toInt32(),
                    error: agent.mbedErrorToString(retval.toInt32()),
                    success: retval.toInt32() === 0
                });
            }
        });

        // mbedtls_aes_setkey_dec - AES 복호화 키 설정
        this.hookFunction("mbedtls_aes_setkey_dec", {
            args: ['pointer', 'pointer', 'uint'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.key = args[1];
                this.keybits = args[2].toInt32();

                const keyBytes = this.keybits / 8;
                if (!this.key.isNull() && keyBytes > 0) {
                    agent.dumpMemory(this.key, keyBytes, `mbedtls_aes_key_dec_${this.opId}`);
                }

                agent.contexts.set(this.ctx.toString(), {
                    opId: this.opId,
                    type: 'aes_decrypt',
                    keySize: this.keybits
                });

                agent.log('aes_key_setup', {
                    operation_id: this.opId,
                    function: 'mbedtls_aes_setkey_dec',
                    key_size_bits: this.keybits,
                    key_size_bytes: keyBytes
                });
            }
        });

        // mbedtls_aes_crypt_cbc - AES CBC 모드
        this.hookFunction("mbedtls_aes_crypt_cbc", {
            args: ['pointer', 'int', 'size_t', 'pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.mode = args[1].toInt32(); // 1=encrypt, 0=decrypt
                this.length = args[2].toInt32();
                this.iv = args[3];
                this.input = args[4];
                this.output = args[5];

                const ctxInfo = agent.contexts.get(this.ctx.toString());
                const modeStr = this.mode === 1 ? "ENCRYPT" : "DECRYPT";

                // IV 캡처
                if (!this.iv.isNull()) {
                    agent.dumpMemory(this.iv, 16, `mbedtls_aes_cbc_iv_${this.opId}`);
                }

                // 입력 데이터 캡처
                if (!this.input.isNull() && this.length > 0) {
                    agent.dumpMemory(this.input, Math.min(this.length, 1024), 
                        `mbedtls_aes_cbc_${modeStr.toLowerCase()}_input_${this.opId}`);
                }

                agent.log('aes_cbc_operation', {
                    operation_id: this.opId,
                    function: 'mbedtls_aes_crypt_cbc',
                    mode: modeStr,
                    length: this.length,
                    key_size: ctxInfo ? ctxInfo.keySize : "unknown"
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                
                // 성공한 경우 출력 데이터 캡처
                if (result === 0 && !this.output.isNull() && this.length > 0) {
                    const modeStr = this.mode === 1 ? "encrypt" : "decrypt";
                    agent.dumpMemory(this.output, Math.min(this.length, 1024), 
                        `mbedtls_aes_cbc_${modeStr}_output_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_aes_crypt_cbc',
                    result: result,
                    error: agent.mbedErrorToString(result),
                    success: result === 0
                });
            }
        });

        // mbedtls_aes_crypt_gcm - AES GCM 모드 (인증 암호화)
        this.hookFunction("mbedtls_gcm_crypt_and_tag", {
            args: ['pointer', 'int', 'size_t', 'pointer', 'size_t', 'pointer', 'size_t', 'pointer', 'pointer', 'size_t', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.mode = args[1].toInt32();
                this.length = args[2].toInt32();
                this.iv = args[3];
                this.iv_len = args[4].toInt32();
                this.add = args[5];
                this.add_len = args[6].toInt32();
                this.input = args[7];
                this.output = args[8];
                this.tag_len = args[9].toInt32();
                this.tag = args[10];

                const modeStr = this.mode === 1 ? "ENCRYPT" : "DECRYPT";

                // IV/논스 캡처
                if (!this.iv.isNull() && this.iv_len > 0) {
                    agent.dumpMemory(this.iv, this.iv_len, `mbedtls_gcm_iv_${this.opId}`);
                }

                // 추가 인증 데이터 캡처
                if (!this.add.isNull() && this.add_len > 0) {
                    agent.dumpMemory(this.add, Math.min(this.add_len, 256), `mbedtls_gcm_aad_${this.opId}`);
                }

                // 입력 데이터 캡처
                if (!this.input.isNull() && this.length > 0) {
                    agent.dumpMemory(this.input, Math.min(this.length, 1024), 
                        `mbedtls_gcm_${modeStr.toLowerCase()}_input_${this.opId}`);
                }

                agent.log('aes_gcm_operation', {
                    operation_id: this.opId,
                    function: 'mbedtls_gcm_crypt_and_tag',
                    mode: modeStr,
                    length: this.length,
                    iv_length: this.iv_len,
                    aad_length: this.add_len,
                    tag_length: this.tag_len
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                
                if (result === 0) {
                    // 출력 데이터 캡처
                    if (!this.output.isNull() && this.length > 0) {
                        const modeStr = this.mode === 1 ? "encrypt" : "decrypt";
                        agent.dumpMemory(this.output, Math.min(this.length, 1024), 
                            `mbedtls_gcm_${modeStr}_output_${this.opId}`);
                    }

                    // 인증 태그 캡처
                    if (!this.tag.isNull() && this.tag_len > 0) {
                        agent.dumpMemory(this.tag, this.tag_len, `mbedtls_gcm_tag_${this.opId}`);
                    }
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_gcm_crypt_and_tag',
                    result: result,
                    error: agent.mbedErrorToString(result),
                    success: result === 0
                });
            }
        });
    }

    // RSA 비대칭키 암호화 후킹
    hookRSAOperations() {
        console.log("[+] RSA 비대칭키 함수 후킹...");

        // mbedtls_rsa_gen_key - RSA 키 생성
        this.hookFunction("mbedtls_rsa_gen_key", {
            args: ['pointer', 'pointer', 'pointer', 'uint', 'int'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.f_rng = args[1];
                this.p_rng = args[2];
                this.nbits = args[3].toInt32();
                this.exponent = args[4].toInt32();

                agent.log('rsa_key_generation', {
                    operation_id: this.opId,
                    function: 'mbedtls_rsa_gen_key',
                    key_size_bits: this.nbits,
                    exponent: this.exponent
                });
            },
            onLeave: function(retval) {
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_rsa_gen_key',
                    result: retval.toInt32(),
                    error: agent.mbedErrorToString(retval.toInt32()),
                    success: retval.toInt32() === 0
                });
            }
        });

        // mbedtls_rsa_public - RSA 공개키 연산
        this.hookFunction("mbedtls_rsa_public", {
            args: ['pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.input = args[1];
                this.output = args[2];

                // RSA 입력 데이터 캡처 (일반적으로 256바이트)
                if (!this.input.isNull()) {
                    agent.dumpMemory(this.input, 256, `mbedtls_rsa_public_input_${this.opId}`);
                }

                agent.log('rsa_public_operation', {
                    operation_id: this.opId,
                    function: 'mbedtls_rsa_public'
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                
                if (result === 0 && !this.output.isNull()) {
                    agent.dumpMemory(this.output, 256, `mbedtls_rsa_public_output_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_rsa_public',
                    result: result,
                    error: agent.mbedErrorToString(result),
                    success: result === 0
                });
            }
        });

        // mbedtls_rsa_private - RSA 개인키 연산
        this.hookFunction("mbedtls_rsa_private", {
            args: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.f_rng = args[1];
                this.p_rng = args[2];
                this.input = args[3];
                this.output = args[4];

                if (!this.input.isNull()) {
                    agent.dumpMemory(this.input, 256, `mbedtls_rsa_private_input_${this.opId}`);
                }

                agent.log('rsa_private_operation', {
                    operation_id: this.opId,
                    function: 'mbedtls_rsa_private'
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                
                if (result === 0 && !this.output.isNull()) {
                    agent.dumpMemory(this.output, 256, `mbedtls_rsa_private_output_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_rsa_private',
                    result: result,
                    error: agent.mbedErrorToString(result),
                    success: result === 0
                });
            }
        });
    }

    // 해시 함수 후킹
    hookHashOperations() {
        console.log("[+] 해시 함수 후킹...");

        // mbedtls_sha256 - SHA-256 해시 (원샷)
        this.hookFunction("mbedtls_sha256", {
            args: ['pointer', 'size_t', 'pointer', 'int'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.input = args[0];
                this.ilen = args[1].toInt32();
                this.output = args[2];
                this.is224 = args[3].toInt32();

                const hashType = this.is224 ? "SHA-224" : "SHA-256";

                // 입력 데이터 캡처
                if (!this.input.isNull() && this.ilen > 0) {
                    agent.dumpMemory(this.input, Math.min(this.ilen, 512), 
                        `mbedtls_sha256_input_${this.opId}`);
                }

                agent.log('hash_operation', {
                    operation_id: this.opId,
                    function: 'mbedtls_sha256',
                    algorithm: hashType,
                    input_size: this.ilen
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                
                if (result === 0 && !this.output.isNull()) {
                    const hashSize = this.is224 ? 28 : 32;
                    agent.dumpMemory(this.output, hashSize, `mbedtls_sha256_output_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_sha256',
                    result: result,
                    error: agent.mbedErrorToString(result),
                    success: result === 0
                });
            }
        });

        // mbedtls_md5 - MD5 해시
        this.hookFunction("mbedtls_md5", {
            args: ['pointer', 'size_t', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.input = args[0];
                this.ilen = args[1].toInt32();
                this.output = args[2];

                if (!this.input.isNull() && this.ilen > 0) {
                    agent.dumpMemory(this.input, Math.min(this.ilen, 512), 
                        `mbedtls_md5_input_${this.opId}`);
                }

                agent.log('hash_operation', {
                    operation_id: this.opId,
                    function: 'mbedtls_md5',
                    algorithm: "MD5",
                    input_size: this.ilen
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                
                if (result === 0 && !this.output.isNull()) {
                    agent.dumpMemory(this.output, 16, `mbedtls_md5_output_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_md5',
                    result: result,
                    error: agent.mbedErrorToString(result),
                    success: result === 0
                });
            }
        });
    }

    // TLS/SSL 관련 후킹
    hookTLSOperations() {
        console.log("[+] TLS/SSL 함수 후킹...");

        // mbedtls_ssl_handshake - TLS 핸드셰이크
        this.hookFunction("mbedtls_ssl_handshake", {
            args: ['pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ssl = args[0];

                agent.log('tls_handshake', {
                    operation_id: this.opId,
                    function: 'mbedtls_ssl_handshake',
                    ssl_context: this.ssl.toString()
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_ssl_handshake',
                    result: result,
                    error: agent.mbedErrorToString(result),
                    success: result === 0
                });
            }
        });

        // mbedtls_ssl_read - TLS 데이터 읽기
        this.hookFunction("mbedtls_ssl_read", {
            args: ['pointer', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.len = args[2].toInt32();
                this.opId = ++agent.operationId;

                agent.log('tls_read', {
                    operation_id: this.opId,
                    function: 'mbedtls_ssl_read',
                    buffer_size: this.len
                });
            },
            onLeave: function(retval) {
                const bytesRead = retval.toInt32();
                
                if (bytesRead > 0 && !this.buf.isNull()) {
                    agent.dumpMemory(this.buf, Math.min(bytesRead, 1024), 
                        `mbedtls_ssl_read_data_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_ssl_read',
                    bytes_read: bytesRead,
                    success: bytesRead > 0
                });
            }
        });

        // mbedtls_ssl_write - TLS 데이터 쓰기
        this.hookFunction("mbedtls_ssl_write", {
            args: ['pointer', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.len = args[2].toInt32();
                this.opId = ++agent.operationId;

                if (!this.buf.isNull() && this.len > 0) {
                    agent.dumpMemory(this.buf, Math.min(this.len, 1024), 
                        `mbedtls_ssl_write_data_${this.opId}`);
                }

                agent.log('tls_write', {
                    operation_id: this.opId,
                    function: 'mbedtls_ssl_write',
                    data_size: this.len
                });
            },
            onLeave: function(retval) {
                const bytesWritten = retval.toInt32();
                
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_ssl_write',
                    bytes_written: bytesWritten,
                    success: bytesWritten > 0
                });
            }
        });
    }

    // 난수 생성 후킹
    hookRandomGeneration() {
        console.log("[+] 난수 생성 함수 후킹...");

        // mbedtls_ctr_drbg_random - CTR DRBG 난수 생성
        this.hookFunction("mbedtls_ctr_drbg_random", {
            args: ['pointer', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.ctx = args[0];
                this.output = args[1];
                this.output_len = args[2].toInt32();
                this.opId = ++agent.operationId;

                agent.log('random_generation', {
                    operation_id: this.opId,
                    function: 'mbedtls_ctr_drbg_random',
                    requested_bytes: this.output_len
                });
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                
                if (result === 0 && !this.output.isNull() && this.output_len > 0) {
                    agent.dumpMemory(this.output, Math.min(this.output_len, 256), 
                        `mbedtls_random_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'mbedtls_ctr_drbg_random',
                    result: result,
                    error: agent.mbedErrorToString(result),
                    success: result === 0
                });
            }
        });
    }

    // 범용 함수 후킹 헬퍼
    hookFunction(funcName, config) {
        try {
            const funcAddr = Module.findExportByName(this.mbedtls?.name, funcName) ||
                           Module.findExportByName(this.mbedcrypto?.name, funcName) ||
                           Module.findExportByName(this.mbedx509?.name, funcName);
            
            if (!funcAddr) {
                console.log(`[-] ${funcName} 함수를 찾을 수 없음`);
                return false;
            }

            console.log(`[+] ${funcName} 후킹 성공 @ ${funcAddr}`);

            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    this.startTime = Date.now();
                    this.threadId = Process.getCurrentThreadId();
                    
                    if (config.onEnter) {
                        config.onEnter.call(this, args);
                    }
                },
                onLeave: function(retval) {
                    const duration = Date.now() - this.startTime;
                    
                    agent.log('timing', {
                        function: funcName,
                        duration_ms: duration,
                        thread_id: this.threadId,
                        operation_id: this.opId
                    });

                    if (config.onLeave) {
                        config.onLeave.call(this, retval);
                    }
                }
            });

            return true;
        } catch (e) {
            console.log(`[-] ${funcName} 후킹 실패: ${e.message}`);
            return false;
        }
    }

    // 메인 초기화
    initialize() {
        console.log("[+] mbedTLS 전용 에이전트 시작");
        
        try {
            this.initializeMbedTLS();
            
            // 함수별 후킹 시작
            this.hookAESOperations();
            this.hookRSAOperations();
            this.hookHashOperations();
            this.hookTLSOperations();
            this.hookRandomGeneration();
            
            // 프로세스 정보 전송
            this.log('agent_info', {
                agent_type: 'mbedtls',
                mbedtls_version: this.mbedtlsVersion,
                process_id: Process.id,
                platform: Process.platform,
                arch: Process.arch,
                mbedtls_available: !!this.mbedtls,
                mbedcrypto_available: !!this.mbedcrypto,
                mbedx509_available: !!this.mbedx509,
                mbedtls_base: this.mbedtls?.base.toString(),
                mbedcrypto_base: this.mbedcrypto?.base.toString()
            });

            console.log("[+] mbedTLS 에이전트 초기화 완료");
            return true;
            
        } catch (e) {
            console.log(`[-] mbedTLS 에이전트 초기화 실패: ${e.message}`);
            return false;
        }
    }
}

// 에이전트 인스턴스 생성 및 초기화
const agent = new MbedTLSAgent();
const success = agent.initialize();

if (success) {
    console.log("[+] mbedTLS 암호화 작업 모니터링 시작...");
} else {
    console.log("[-] 에이전트 초기화 실패. 종료합니다.");
}

// RPC 인터페이스
rpc.exports = {
    getStats: function() {
        return {
            agent_type: 'mbedtls',
            operations_count: agent.operationId,
            uptime_ms: Date.now() - agent.startTime,
            contexts_active: agent.contexts.size,
            mbedtls_version: agent.mbedtlsVersion
        };
    },
    
    getActiveContexts: function() {
        return Array.from(agent.contexts.entries()).map(([ctx, info]) => ({
            context: ctx,
            ...info
        }));
    }
};