// C/C++ 암호화 라이브러리 후킹 에이전트
// 대상: OpenSSL, Windows CNG, mbedTLS, libgcrypt

class CryptoCaptureAgent {
    constructor() {
        this.capturedData = {
            keys: [],
            operations: [],
            algorithms: [],
            flows: [],
            memory: [],
            timing: []
        };
        this.operationId = 0;
        this.startTime = Date.now();
    }

    log(category, data) {
        const timestamp = Date.now() - this.startTime;
        send({
            type: 'crypto_capture',
            category: category,
            timestamp: timestamp,
            data: data
        });
    }

    // 메모리 덤프 유틸리티
    dumpMemory(ptr, size, label) {
        try {
            const data = Memory.readByteArray(ptr, size);
            const hex = Array.from(new Uint8Array(data))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            
            this.log('memory', {
                label: label,
                address: ptr.toString(),
                size: size,
                hex: hex.substring(0, 512), // 최대 256바이트만
                entropy: this.calculateEntropy(new Uint8Array(data))
            });
            
            return hex;
        } catch (e) {
            console.log(`메모리 덤프 실패 (${label}): ${e.message}`);
            return null;
        }
    }

    // 엔트로피 계산
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

    // OpenSSL 후킹
    hookOpenSSL() {
        console.log("[+] OpenSSL 후킹 시작...");

        // libcrypto 라이브러리 찾기
        const libcrypto = Process.findModuleByName("libcrypto.so") || 
                         Process.findModuleByName("libcrypto.so.1.1") ||
                         Process.findModuleByName("libcrypto.so.3");

        if (!libcrypto) {
            console.log("[-] OpenSSL libcrypto 라이브러리를 찾을 수 없음");
            return;
        }

        console.log(`[+] libcrypto 발견: ${libcrypto.base}`);

        // EVP_EncryptInit_ex 후킹 (대칭키 암호화 초기화)
        this.hookFunction(libcrypto, "EVP_EncryptInit_ex", {
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.cipher = args[1];
                this.key = args[3];
                this.iv = args[4];

                if (!this.cipher.isNull()) {
                    const cipherName = Memory.readUtf8String(
                        Module.findExportByName(libcrypto.name, "EVP_CIPHER_name")
                            ? new NativeFunction(
                                Module.findExportByName(libcrypto.name, "EVP_CIPHER_name"), 
                                'pointer', ['pointer']
                              )(this.cipher)
                            : ptr(0)
                    );

                    agent.log('algorithm', {
                        operation_id: this.opId,
                        function: 'EVP_EncryptInit_ex',
                        cipher: cipherName || 'unknown',
                        has_key: !this.key.isNull(),
                        has_iv: !this.iv.isNull()
                    });
                }

                // 키 캡처
                if (!this.key.isNull()) {
                    // 키 크기 추정 (cipher에 따라 다름)
                    let keySize = 32; // 기본값 (AES-256)
                    agent.dumpMemory(this.key, keySize, `encrypt_key_op${this.opId}`);
                }

                // IV 캡처
                if (!this.iv.isNull()) {
                    let ivSize = 16; // 기본값 (AES block size)
                    agent.dumpMemory(this.iv, ivSize, `encrypt_iv_op${this.opId}`);
                }
            },
            onLeave: function(retval) {
                agent.log('operation', {
                    operation_id: this.opId,
                    function: 'EVP_EncryptInit_ex',
                    result: retval.toInt32(),
                    success: retval.toInt32() === 1
                });
            }
        });

        // EVP_EncryptUpdate 후킹 (실제 암호화 수행)
        this.hookFunction(libcrypto, "EVP_EncryptUpdate", {
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.out = args[1];
                this.outl = args[2];
                this.in = args[3];
                this.inl = args[4].toInt32();

                // 평문 데이터 캡처
                if (!this.in.isNull() && this.inl > 0) {
                    agent.dumpMemory(this.in, Math.min(this.inl, 1024), `plaintext_op${this.opId}`);
                }

                agent.log('flow', {
                    operation_id: this.opId,
                    function: 'EVP_EncryptUpdate',
                    input_size: this.inl
                });
            },
            onLeave: function(retval) {
                // 암호문 데이터 캡처
                if (retval.toInt32() === 1 && !this.out.isNull()) {
                    const outLen = Memory.readInt(this.outl);
                    if (outLen > 0) {
                        agent.dumpMemory(this.out, Math.min(outLen, 1024), `ciphertext_op${this.opId}`);
                    }
                }

                agent.log('operation', {
                    operation_id: this.opId,
                    function: 'EVP_EncryptUpdate',
                    result: retval.toInt32(),
                    success: retval.toInt32() === 1
                });
            }
        });

        // RSA 키 생성 후킹
        this.hookFunction(libcrypto, "RSA_generate_key_ex", {
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.rsa = args[0];
                this.bits = args[1].toInt32();
                this.e = args[2];

                agent.log('key_generation', {
                    operation_id: this.opId,
                    function: 'RSA_generate_key_ex',
                    key_size: this.bits,
                    algorithm: 'RSA'
                });
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 1) {
                    // RSA 키 컴포넌트 추출 시도
                    try {
                        // 이는 복잡한 구조체 파싱이 필요함 - 실제 구현시 OpenSSL 버전별로 다름
                        agent.log('key_generated', {
                            operation_id: this.opId,
                            function: 'RSA_generate_key_ex',
                            success: true
                        });
                    } catch (e) {
                        console.log(`RSA 키 추출 실패: ${e.message}`);
                    }
                }
            }
        });

        // 해시 함수 후킹
        this.hookFunction(libcrypto, "EVP_DigestInit_ex", {
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.type = args[1];

                const digestName = Memory.readUtf8String(
                    Module.findExportByName(libcrypto.name, "EVP_MD_name")
                        ? new NativeFunction(
                            Module.findExportByName(libcrypto.name, "EVP_MD_name"), 
                            'pointer', ['pointer']
                          )(this.type)
                        : ptr(0)
                );

                agent.log('hash', {
                    operation_id: this.opId,
                    function: 'EVP_DigestInit_ex',
                    algorithm: digestName || 'unknown'
                });
            }
        });
    }

    // Windows CNG API 후킹
    hookWindowsCNG() {
        console.log("[+] Windows CNG 후킹 시작...");

        const bcrypt = Process.findModuleByName("bcrypt.dll");
        if (!bcrypt) {
            console.log("[-] bcrypt.dll을 찾을 수 없음");
            return;
        }

        // BCryptEncrypt 후킹
        this.hookFunction(bcrypt, "BCryptEncrypt", {
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hKey = args[0];
                this.pbInput = args[1];
                this.cbInput = args[2].toInt32();
                this.pPaddingInfo = args[3];
                this.pbIV = args[4];
                this.cbIV = args[5].toInt32();
                this.pbOutput = args[6];
                this.cbOutput = args[7].toInt32();

                // 평문 데이터 캡처
                if (!this.pbInput.isNull() && this.cbInput > 0) {
                    agent.dumpMemory(this.pbInput, Math.min(this.cbInput, 1024), `cng_plaintext_op${this.opId}`);
                }

                // IV 캡처
                if (!this.pbIV.isNull() && this.cbIV > 0) {
                    agent.dumpMemory(this.pbIV, this.cbIV, `cng_iv_op${this.opId}`);
                }

                agent.log('flow', {
                    operation_id: this.opId,
                    function: 'BCryptEncrypt',
                    input_size: this.cbInput,
                    iv_size: this.cbIV,
                    api: 'Windows CNG'
                });
            },
            onLeave: function(retval) {
                const status = retval.toInt32();
                
                // 성공한 경우 암호문 캡처
                if (status === 0 && !this.pbOutput.isNull()) { // STATUS_SUCCESS = 0
                    agent.dumpMemory(this.pbOutput, Math.min(this.cbOutput, 1024), `cng_ciphertext_op${this.opId}`);
                }

                agent.log('operation', {
                    operation_id: this.opId,
                    function: 'BCryptEncrypt',
                    ntstatus: status,
                    success: status === 0
                });
            }
        });

        // BCryptGenerateSymmetricKey 후킹
        this.hookFunction(bcrypt, "BCryptGenerateSymmetricKey", {
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hAlgorithm = args[0];
                this.phKey = args[1];
                this.pbKeyObject = args[2];
                this.cbKeyObject = args[3].toInt32();
                this.pbSecret = args[4];
                this.cbSecret = args[5].toInt32();

                // 키 데이터 캡처
                if (!this.pbSecret.isNull() && this.cbSecret > 0) {
                    agent.dumpMemory(this.pbSecret, this.cbSecret, `cng_key_op${this.opId}`);
                }

                agent.log('key_generation', {
                    operation_id: this.opId,
                    function: 'BCryptGenerateSymmetricKey',
                    key_size: this.cbSecret * 8, // 비트 단위
                    api: 'Windows CNG'
                });
            }
        });
    }

    // mbedTLS 후킹 (IoT/임베디드에서 많이 사용)
    hookMbedTLS() {
        console.log("[+] mbedTLS 후킹 시작...");

        const mbedtls = Process.findModuleByName("libmbedtls.so") ||
                       Process.findModuleByName("mbedtls.dll");
        
        if (!mbedtls) {
            console.log("[-] mbedTLS 라이브러리를 찾을 수 없음");
            return;
        }

        // mbedtls_aes_crypt_cbc 후킹
        this.hookFunction(mbedtls, "mbedtls_aes_crypt_cbc", {
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.mode = args[1].toInt32();
                this.length = args[2].toInt32();
                this.iv = args[3];
                this.input = args[4];
                this.output = args[5];

                const modeStr = this.mode === 1 ? "ENCRYPT" : "DECRYPT";

                // IV 캡처
                agent.dumpMemory(this.iv, 16, `mbedtls_iv_op${this.opId}`);
                
                // 입력 데이터 캡처
                if (this.length > 0) {
                    agent.dumpMemory(this.input, Math.min(this.length, 1024), 
                        `mbedtls_${modeStr.toLowerCase()}_in_op${this.opId}`);
                }

                agent.log('flow', {
                    operation_id: this.opId,
                    function: 'mbedtls_aes_crypt_cbc',
                    mode: modeStr,
                    length: this.length,
                    api: 'mbedTLS'
                });
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.length > 0) { // 0 = success
                    const modeStr = this.mode === 1 ? "encrypt" : "decrypt";
                    agent.dumpMemory(this.output, Math.min(this.length, 1024), 
                        `mbedtls_${modeStr}_out_op${this.opId}`);
                }

                agent.log('operation', {
                    operation_id: this.opId,
                    function: 'mbedtls_aes_crypt_cbc',
                    result: retval.toInt32(),
                    success: retval.toInt32() === 0
                });
            }
        });
    }

    // 함수 후킹 헬퍼
    hookFunction(module, functionName, callbacks) {
        try {
            const funcAddr = Module.findExportByName(module.name, functionName);
            if (!funcAddr) {
                console.log(`[-] ${functionName} 함수를 찾을 수 없음 (${module.name})`);
                return;
            }

            console.log(`[+] ${functionName} 후킹 성공 @ ${funcAddr}`);

            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    this.startTime = Date.now();
                    if (callbacks.onEnter) {
                        callbacks.onEnter.call(this, args);
                    }
                },
                onLeave: function(retval) {
                    this.endTime = Date.now();
                    
                    // 타이밍 정보 로깅
                    agent.log('timing', {
                        function: functionName,
                        duration_ms: this.endTime - this.startTime,
                        thread_id: Process.getCurrentThreadId()
                    });

                    if (callbacks.onLeave) {
                        callbacks.onLeave.call(this, retval);
                    }
                }
            });
        } catch (e) {
            console.log(`[-] ${functionName} 후킹 실패: ${e.message}`);
        }
    }

    // 메인 초기화
    initialize() {
        console.log("[+] C/C++ 암호화 에이전트 시작");
        console.log(`[+] 타겟 프로세스: ${Process.id}`);
        
        // 운영체제별 후킹
        if (Process.platform === 'linux') {
            this.hookOpenSSL();
            this.hookMbedTLS();
        } else if (Process.platform === 'windows') {
            this.hookWindowsCNG();
            this.hookOpenSSL(); // Windows에서도 OpenSSL 사용 가능
        }

        // 프로세스 정보 전송
        this.log('process_info', {
            pid: Process.id,
            platform: Process.platform,
            arch: Process.arch,
            modules: Process.enumerateModules().map(m => ({
                name: m.name,
                base: m.base.toString(),
                size: m.size
            })).filter(m => 
                m.name.includes('crypto') || 
                m.name.includes('ssl') || 
                m.name.includes('bcrypt') ||
                m.name.includes('mbedtls')
            )
        });

        console.log("[+] 모든 후킹 완료. 암호화 작업 모니터링 중...");
    }
}

// 에이전트 인스턴스 생성 및 초기화
const agent = new CryptoCaptureAgent();
agent.initialize();

// 메시지 핸들러
rpc.exports = {
    // 실시간 통계 요청
    getStats: function() {
        return {
            operations_count: agent.operationId,
            uptime_ms: Date.now() - agent.startTime,
            captured_keys: agent.capturedData.keys.length,
            captured_flows: agent.capturedData.flows.length
        };
    },
    
    // 특정 연산 ID의 상세 정보 요청
    getOperationDetails: function(operationId) {
        return agent.capturedData.operations.filter(op => op.operation_id === operationId);
    }
};