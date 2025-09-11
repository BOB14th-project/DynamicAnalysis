// OpenSSL 전용 암호화 후킹 에이전트
// 대상: libssl.so, libcrypto.so (OpenSSL 1.0.x ~ 3.x)

class OpenSSLAgent {
    constructor() {
        this.operationId = 0;
        this.startTime = Date.now();
        this.opensslVersion = null;
        this.libcrypto = null;
        this.libssl = null;
        this.contexts = new Map(); // EVP_CIPHER_CTX 추적
    }

    log(category, data) {
        send({
            type: 'openssl_capture',
            category: category,
            timestamp: Date.now() - this.startTime,
            agent: 'openssl',
            data: data
        });
    }

    // 메모리 덤프 및 엔트로피 계산
    dumpMemory(ptr, size, label) {
        try {
            if (ptr.isNull() || size <= 0) return null;
            
            const data = Memory.readByteArray(ptr, size);
            const bytes = new Uint8Array(data);
            const hex = Array.from(bytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            
            // 엔트로피 계산
            const entropy = this.calculateEntropy(bytes);
            
            this.log('memory_dump', {
                label: label,
                address: ptr.toString(),
                size: size,
                hex: hex.substring(0, 512), // 최대 256바이트만 전송
                entropy: entropy,
                appears_random: entropy > 7.0 // 높은 엔트로피 = 암호화된/랜덤 데이터
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

    // OpenSSL 라이브러리 초기화
    initializeOpenSSL() {
        console.log("[+] OpenSSL 라이브러리 탐지 중...");

        // 다양한 OpenSSL 라이브러리 이름 시도
        const cryptoNames = [
            "libcrypto.so", "libcrypto.so.3", "libcrypto.so.1.1", 
            "libcrypto.so.1.0.0", "libcrypto.so.10"
        ];
        
        const sslNames = [
            "libssl.so", "libssl.so.3", "libssl.so.1.1",
            "libssl.so.1.0.0", "libssl.so.10"
        ];

        for (let name of cryptoNames) {
            this.libcrypto = Process.findModuleByName(name);
            if (this.libcrypto) {
                console.log(`[+] libcrypto 발견: ${name} @ ${this.libcrypto.base}`);
                break;
            }
        }

        for (let name of sslNames) {
            this.libssl = Process.findModuleByName(name);
            if (this.libssl) {
                console.log(`[+] libssl 발견: ${name} @ ${this.libssl.base}`);
                break;
            }
        }

        if (!this.libcrypto && !this.libssl) {
            throw new Error("OpenSSL 라이브러리를 찾을 수 없습니다");
        }

        // OpenSSL 버전 탐지
        this.detectOpenSSLVersion();
    }

    detectOpenSSLVersion() {
        try {
            const versionFunc = Module.findExportByName(this.libcrypto?.name || this.libssl?.name, "OpenSSL_version");
            if (versionFunc) {
                const getVersion = new NativeFunction(versionFunc, 'pointer', ['int']);
                const versionPtr = getVersion(0); // OPENSSL_VERSION
                this.opensslVersion = Memory.readUtf8String(versionPtr);
                console.log(`[+] OpenSSL 버전: ${this.opensslVersion}`);
            }
        } catch (e) {
            console.log(`[!] OpenSSL 버전 탐지 실패: ${e.message}`);
        }
    }

    // 대칭키 암호화 후킹
    hookSymmetricEncryption() {
        console.log("[+] 대칭키 암호화 함수 후킹...");

        // EVP_EncryptInit_ex - 암호화 초기화
        this.hookFunction("EVP_EncryptInit_ex", {
            args: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.cipher = args[1];
                this.impl = args[2];
                this.key = args[3];
                this.iv = args[4];

                // 컨텍스트 저장
                agent.contexts.set(this.ctx.toString(), {
                    opId: this.opId,
                    type: 'encrypt',
                    startTime: Date.now()
                });

                // 암호화 알고리즘 정보
                let cipherName = "unknown";
                if (!this.cipher.isNull()) {
                    try {
                        const nameFunc = Module.findExportByName(agent.libcrypto.name, "EVP_CIPHER_name");
                        if (nameFunc) {
                            const getName = new NativeFunction(nameFunc, 'pointer', ['pointer']);
                            const namePtr = getName(this.cipher);
                            cipherName = Memory.readUtf8String(namePtr);
                        }
                    } catch (e) {
                        console.log(`[!] 암호화 알고리즘 이름 추출 실패: ${e.message}`);
                    }
                }

                agent.log('cipher_init', {
                    operation_id: this.opId,
                    function: 'EVP_EncryptInit_ex',
                    cipher: cipherName,
                    has_key: !this.key.isNull(),
                    has_iv: !this.iv.isNull()
                });

                // 키 캡처 (크기 추정)
                if (!this.key.isNull()) {
                    let keySize = 32; // 기본값 AES-256
                    if (cipherName.includes("AES-128")) keySize = 16;
                    else if (cipherName.includes("AES-192")) keySize = 24;
                    else if (cipherName.includes("AES-256")) keySize = 32;
                    else if (cipherName.includes("DES")) keySize = 8;
                    else if (cipherName.includes("3DES")) keySize = 24;

                    agent.dumpMemory(this.key, keySize, `openssl_encrypt_key_${this.opId}`);
                }

                // IV 캡처
                if (!this.iv.isNull()) {
                    let ivSize = 16; // 기본값 AES 블록 크기
                    if (cipherName.includes("DES")) ivSize = 8;
                    
                    agent.dumpMemory(this.iv, ivSize, `openssl_encrypt_iv_${this.opId}`);
                }
            },
            onLeave: function(retval) {
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'EVP_EncryptInit_ex',
                    result: retval.toInt32(),
                    success: retval.toInt32() === 1
                });
            }
        });

        // EVP_EncryptUpdate - 실제 암호화
        this.hookFunction("EVP_EncryptUpdate", {
            args: ['pointer', 'pointer', 'pointer', 'pointer', 'int'],
            onEnter: function(args) {
                this.ctx = args[0];
                this.out = args[1];
                this.outl = args[2];
                this.in = args[3];
                this.inl = args[4].toInt32();

                // 컨텍스트에서 operation ID 가져오기
                const ctxInfo = agent.contexts.get(this.ctx.toString());
                this.opId = ctxInfo ? ctxInfo.opId : ++agent.operationId;

                // 평문 데이터 캡처
                if (!this.in.isNull() && this.inl > 0) {
                    agent.dumpMemory(this.in, Math.min(this.inl, 1024), 
                        `openssl_plaintext_${this.opId}`);
                }

                agent.log('encrypt_update', {
                    operation_id: this.opId,
                    function: 'EVP_EncryptUpdate',
                    input_size: this.inl
                });
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 1 && !this.out.isNull()) {
                    // 출력 길이 읽기
                    const outLen = Memory.readInt(this.outl);
                    if (outLen > 0) {
                        agent.dumpMemory(this.out, Math.min(outLen, 1024), 
                            `openssl_ciphertext_${this.opId}`);
                    }
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'EVP_EncryptUpdate',
                    result: retval.toInt32(),
                    success: retval.toInt32() === 1
                });
            }
        });

        // EVP_EncryptFinal_ex - 암호화 완료
        this.hookFunction("EVP_EncryptFinal_ex", {
            args: ['pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.ctx = args[0];
                const ctxInfo = agent.contexts.get(this.ctx.toString());
                this.opId = ctxInfo ? ctxInfo.opId : ++agent.operationId;
            },
            onLeave: function(retval) {
                // 컨텍스트 정리
                agent.contexts.delete(this.ctx.toString());
                
                agent.log('encrypt_final', {
                    operation_id: this.opId,
                    function: 'EVP_EncryptFinal_ex',
                    result: retval.toInt32(),
                    success: retval.toInt32() === 1
                });
            }
        });
    }

    // 비대칭키 암호화 후킹
    hookAsymmetricEncryption() {
        console.log("[+] 비대칭키 암호화 함수 후킹...");

        // RSA 키 생성
        this.hookFunction("RSA_generate_key_ex", {
            args: ['pointer', 'int', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.rsa = args[0];
                this.bits = args[1].toInt32();
                this.e = args[2];
                this.cb = args[3];

                agent.log('rsa_keygen', {
                    operation_id: this.opId,
                    function: 'RSA_generate_key_ex',
                    key_size_bits: this.bits,
                    algorithm: 'RSA'
                });
            },
            onLeave: function(retval) {
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'RSA_generate_key_ex',
                    result: retval.toInt32(),
                    success: retval.toInt32() === 1
                });
            }
        });

        // RSA 암호화
        this.hookFunction("RSA_public_encrypt", {
            args: ['int', 'pointer', 'pointer', 'pointer', 'int'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.flen = args[0].toInt32();
                this.from = args[1];
                this.to = args[2];
                this.rsa = args[3];
                this.padding = args[4].toInt32();

                // 평문 캡처
                if (!this.from.isNull() && this.flen > 0) {
                    agent.dumpMemory(this.from, this.flen, `openssl_rsa_plaintext_${this.opId}`);
                }

                agent.log('rsa_encrypt', {
                    operation_id: this.opId,
                    function: 'RSA_public_encrypt',
                    input_size: this.flen,
                    padding: this.padding
                });
            },
            onLeave: function(retval) {
                const outputSize = retval.toInt32();
                if (outputSize > 0 && !this.to.isNull()) {
                    agent.dumpMemory(this.to, outputSize, `openssl_rsa_ciphertext_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'RSA_public_encrypt',
                    output_size: outputSize,
                    success: outputSize > 0
                });
            }
        });
    }

    // 해시 함수 후킹
    hookHashFunctions() {
        console.log("[+] 해시 함수 후킹...");

        // EVP_DigestInit_ex
        this.hookFunction("EVP_DigestInit_ex", {
            args: ['pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.ctx = args[0];
                this.type = args[1];
                this.impl = args[2];

                let digestName = "unknown";
                if (!this.type.isNull()) {
                    try {
                        const nameFunc = Module.findExportByName(agent.libcrypto.name, "EVP_MD_name");
                        if (nameFunc) {
                            const getName = new NativeFunction(nameFunc, 'pointer', ['pointer']);
                            const namePtr = getName(this.type);
                            digestName = Memory.readUtf8String(namePtr);
                        }
                    } catch (e) {
                        console.log(`[!] 해시 알고리즘 이름 추출 실패: ${e.message}`);
                    }
                }

                agent.log('hash_init', {
                    operation_id: this.opId,
                    function: 'EVP_DigestInit_ex',
                    algorithm: digestName
                });
            }
        });

        // EVP_DigestUpdate
        this.hookFunction("EVP_DigestUpdate", {
            args: ['pointer', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.ctx = args[0];
                this.data = args[1];
                this.count = args[2].toInt32();

                const ctxInfo = agent.contexts.get(this.ctx.toString());
                this.opId = ctxInfo ? ctxInfo.opId : ++agent.operationId;

                // 해시 입력 데이터 캡처
                if (!this.data.isNull() && this.count > 0) {
                    agent.dumpMemory(this.data, Math.min(this.count, 512), 
                        `openssl_hash_input_${this.opId}`);
                }

                agent.log('hash_update', {
                    operation_id: this.opId,
                    function: 'EVP_DigestUpdate',
                    data_size: this.count
                });
            }
        });

        // EVP_DigestFinal_ex
        this.hookFunction("EVP_DigestFinal_ex", {
            args: ['pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.ctx = args[0];
                this.md = args[1];
                this.s = args[2];

                const ctxInfo = agent.contexts.get(this.ctx.toString());
                this.opId = ctxInfo ? ctxInfo.opId : ++agent.operationId;
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 1 && !this.md.isNull()) {
                    // 해시 결과 크기 읽기
                    const hashSize = this.s.isNull() ? 32 : Memory.readU32(this.s);
                    agent.dumpMemory(this.md, Math.min(hashSize, 64), 
                        `openssl_hash_result_${this.opId}`);
                }

                agent.log('hash_final', {
                    operation_id: this.opId,
                    function: 'EVP_DigestFinal_ex',
                    result: retval.toInt32(),
                    success: retval.toInt32() === 1
                });
            }
        });
    }

    // 범용 함수 후킹 헬퍼
    hookFunction(funcName, config) {
        try {
            const funcAddr = Module.findExportByName(this.libcrypto?.name, funcName) ||
                           Module.findExportByName(this.libssl?.name, funcName);
            
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
                    
                    // 타이밍 정보
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
        console.log("[+] OpenSSL 전용 에이전트 시작");
        
        try {
            this.initializeOpenSSL();
            
            // 함수별 후킹 시작
            this.hookSymmetricEncryption();
            this.hookAsymmetricEncryption();
            this.hookHashFunctions();
            
            // 프로세스 정보 전송
            this.log('agent_info', {
                agent_type: 'openssl',
                openssl_version: this.opensslVersion,
                process_id: Process.id,
                platform: Process.platform,
                arch: Process.arch,
                libcrypto_base: this.libcrypto?.base.toString(),
                libssl_base: this.libssl?.base.toString()
            });

            console.log("[+] OpenSSL 에이전트 초기화 완료");
            return true;
            
        } catch (e) {
            console.log(`[-] OpenSSL 에이전트 초기화 실패: ${e.message}`);
            return false;
        }
    }
}

// 에이전트 인스턴스 생성 및 초기화
const agent = new OpenSSLAgent();
const success = agent.initialize();

if (success) {
    console.log("[+] OpenSSL 암호화 작업 모니터링 시작...");
} else {
    console.log("[-] 에이전트 초기화 실패. 종료합니다.");
}

// RPC 인터페이스
rpc.exports = {
    getStats: function() {
        return {
            agent_type: 'openssl',
            operations_count: agent.operationId,
            uptime_ms: Date.now() - agent.startTime,
            contexts_active: agent.contexts.size,
            openssl_version: agent.opensslVersion
        };
    },
    
    getActiveContexts: function() {
        return Array.from(agent.contexts.entries()).map(([ctx, info]) => ({
            context: ctx,
            ...info
        }));
    }
};