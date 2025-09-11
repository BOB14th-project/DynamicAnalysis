// Windows CNG (Cryptography Next Generation) 전용 에이전트
// 대상: bcrypt.dll, ncrypt.dll, crypt32.dll

class WindowsCNGAgent {
    constructor() {
        this.operationId = 0;
        this.startTime = Date.now();
        this.bcrypt = null;
        this.ncrypt = null;
        this.crypt32 = null;
        this.algorithms = new Map(); // 알고리즘 핸들 추적
        this.keys = new Map(); // 키 핸들 추적
    }

    log(category, data) {
        send({
            type: 'cng_capture',
            category: category,
            timestamp: Date.now() - this.startTime,
            agent: 'windows_cng',
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

    // NTSTATUS 코드 해석
    ntStatusToString(status) {
        const statusMap = {
            0x00000000: "STATUS_SUCCESS",
            0xC0000001: "STATUS_UNSUCCESSFUL", 
            0xC000000D: "STATUS_INVALID_PARAMETER",
            0xC0000017: "STATUS_NO_MEMORY",
            0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
            0xC0000225: "STATUS_NOT_FOUND",
            0xC0000008: "STATUS_INVALID_HANDLE"
        };
        
        return statusMap[status & 0xFFFFFFFF] || `NTSTATUS_0x${(status & 0xFFFFFFFF).toString(16).toUpperCase()}`;
    }

    // CNG 라이브러리 초기화
    initializeCNG() {
        console.log("[+] Windows CNG 라이브러리 탐지 중...");

        this.bcrypt = Process.findModuleByName("bcrypt.dll");
        this.ncrypt = Process.findModuleByName("ncrypt.dll");
        this.crypt32 = Process.findModuleByName("crypt32.dll");

        if (!this.bcrypt && !this.ncrypt && !this.crypt32) {
            throw new Error("Windows CNG 라이브러리를 찾을 수 없습니다");
        }

        if (this.bcrypt) {
            console.log(`[+] bcrypt.dll 발견 @ ${this.bcrypt.base}`);
        }
        if (this.ncrypt) {
            console.log(`[+] ncrypt.dll 발견 @ ${this.ncrypt.base}`);
        }
        if (this.crypt32) {
            console.log(`[+] crypt32.dll 발견 @ ${this.crypt32.base}`);
        }
    }

    // BCrypt 알고리즘 공급자 후킹
    hookBCryptAlgorithmProvider() {
        console.log("[+] BCrypt 알고리즘 공급자 함수 후킹...");

        // BCryptOpenAlgorithmProvider
        this.hookFunction(this.bcrypt, "BCryptOpenAlgorithmProvider", {
            args: ['pointer', 'pointer', 'pointer', 'uint32'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.phAlgorithm = args[0];
                this.pszAlgId = args[1];
                this.pszImplementation = args[2];
                this.dwFlags = args[3].toInt32();

                // 알고리즘 ID 읽기
                this.algId = this.pszAlgId.isNull() ? "NULL" : Memory.readUtf16String(this.pszAlgId);
                this.implementation = this.pszImplementation.isNull() ? "NULL" : Memory.readUtf16String(this.pszImplementation);

                agent.log('algorithm_open', {
                    operation_id: this.opId,
                    function: 'BCryptOpenAlgorithmProvider',
                    algorithm_id: this.algId,
                    implementation: this.implementation,
                    flags: `0x${this.dwFlags.toString(16)}`
                });
            },
            onLeave: function(retval) {
                const status = retval.toInt32();
                
                if (status === 0 && !this.phAlgorithm.isNull()) { // STATUS_SUCCESS
                    const hAlgorithm = Memory.readPointer(this.phAlgorithm);
                    agent.algorithms.set(hAlgorithm.toString(), {
                        opId: this.opId,
                        algorithm: this.algId,
                        implementation: this.implementation
                    });
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'BCryptOpenAlgorithmProvider',
                    ntstatus: agent.ntStatusToString(status),
                    success: status === 0
                });
            }
        });

        // BCryptCloseAlgorithmProvider
        this.hookFunction(this.bcrypt, "BCryptCloseAlgorithmProvider", {
            args: ['pointer', 'uint32'],
            onEnter: function(args) {
                this.hAlgorithm = args[0];
                const algInfo = agent.algorithms.get(this.hAlgorithm.toString());
                
                agent.log('algorithm_close', {
                    algorithm_handle: this.hAlgorithm.toString(),
                    algorithm: algInfo ? algInfo.algorithm : "unknown"
                });
            },
            onLeave: function(retval) {
                agent.algorithms.delete(this.hAlgorithm.toString());
            }
        });
    }

    // BCrypt 키 관리 후킹
    hookBCryptKeyManagement() {
        console.log("[+] BCrypt 키 관리 함수 후킹...");

        // BCryptGenerateSymmetricKey
        this.hookFunction(this.bcrypt, "BCryptGenerateSymmetricKey", {
            args: ['pointer', 'pointer', 'pointer', 'uint32', 'pointer', 'uint32', 'uint32'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hAlgorithm = args[0];
                this.phKey = args[1];
                this.pbKeyObject = args[2];
                this.cbKeyObject = args[3].toInt32();
                this.pbSecret = args[4];
                this.cbSecret = args[5].toInt32();
                this.dwFlags = args[6].toInt32();

                const algInfo = agent.algorithms.get(this.hAlgorithm.toString());

                // 키 데이터 캡처
                if (!this.pbSecret.isNull() && this.cbSecret > 0) {
                    agent.dumpMemory(this.pbSecret, this.cbSecret, `cng_symmetric_key_${this.opId}`);
                }

                agent.log('key_generation', {
                    operation_id: this.opId,
                    function: 'BCryptGenerateSymmetricKey',
                    algorithm: algInfo ? algInfo.algorithm : "unknown",
                    key_size_bytes: this.cbSecret,
                    key_size_bits: this.cbSecret * 8,
                    flags: `0x${this.dwFlags.toString(16)}`
                });
            },
            onLeave: function(retval) {
                const status = retval.toInt32();
                
                if (status === 0 && !this.phKey.isNull()) {
                    const hKey = Memory.readPointer(this.phKey);
                    const algInfo = agent.algorithms.get(this.hAlgorithm.toString());
                    
                    agent.keys.set(hKey.toString(), {
                        opId: this.opId,
                        algorithm: algInfo ? algInfo.algorithm : "unknown",
                        keySize: this.cbSecret,
                        type: "symmetric"
                    });
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'BCryptGenerateSymmetricKey',
                    ntstatus: agent.ntStatusToString(status),
                    success: status === 0
                });
            }
        });

        // BCryptImportKey
        this.hookFunction(this.bcrypt, "BCryptImportKey", {
            args: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'uint32', 'pointer', 'uint32', 'uint32'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hAlgorithm = args[0];
                this.hImportKey = args[1];
                this.pszBlobType = args[2];
                this.phKey = args[3];
                this.pbKeyObject = args[4];
                this.cbKeyObject = args[5].toInt32();
                this.pbInput = args[6];
                this.cbInput = args[7].toInt32();
                this.dwFlags = args[8].toInt32();

                const blobType = this.pszBlobType.isNull() ? "NULL" : Memory.readUtf16String(this.pszBlobType);
                const algInfo = agent.algorithms.get(this.hAlgorithm.toString());

                // 키 블롭 데이터 캡처
                if (!this.pbInput.isNull() && this.cbInput > 0) {
                    agent.dumpMemory(this.pbInput, Math.min(this.cbInput, 1024), `cng_import_key_${this.opId}`);
                }

                agent.log('key_import', {
                    operation_id: this.opId,
                    function: 'BCryptImportKey',
                    algorithm: algInfo ? algInfo.algorithm : "unknown",
                    blob_type: blobType,
                    input_size: this.cbInput
                });
            }
        });

        // BCryptDestroyKey
        this.hookFunction(this.bcrypt, "BCryptDestroyKey", {
            args: ['pointer'],
            onEnter: function(args) {
                this.hKey = args[0];
                const keyInfo = agent.keys.get(this.hKey.toString());
                
                agent.log('key_destroy', {
                    key_handle: this.hKey.toString(),
                    algorithm: keyInfo ? keyInfo.algorithm : "unknown",
                    type: keyInfo ? keyInfo.type : "unknown"
                });
            },
            onLeave: function(retval) {
                agent.keys.delete(this.hKey.toString());
            }
        });
    }

    // BCrypt 암호화/복호화 후킹
    hookBCryptEncryption() {
        console.log("[+] BCrypt 암호화/복호화 함수 후킹...");

        // BCryptEncrypt
        this.hookFunction(this.bcrypt, "BCryptEncrypt", {
            args: ['pointer', 'pointer', 'uint32', 'pointer', 'pointer', 'uint32', 'pointer', 'uint32', 'pointer', 'uint32'],
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
                this.pcbResult = args[8];
                this.dwFlags = args[9].toInt32();

                const keyInfo = agent.keys.get(this.hKey.toString());

                // 평문 데이터 캡처
                if (!this.pbInput.isNull() && this.cbInput > 0) {
                    agent.dumpMemory(this.pbInput, Math.min(this.cbInput, 1024), `cng_encrypt_plaintext_${this.opId}`);
                }

                // IV 캡처
                if (!this.pbIV.isNull() && this.cbIV > 0) {
                    agent.dumpMemory(this.pbIV, this.cbIV, `cng_encrypt_iv_${this.opId}`);
                }

                agent.log('encrypt_operation', {
                    operation_id: this.opId,
                    function: 'BCryptEncrypt',
                    algorithm: keyInfo ? keyInfo.algorithm : "unknown",
                    input_size: this.cbInput,
                    iv_size: this.cbIV,
                    output_buffer_size: this.cbOutput,
                    flags: `0x${this.dwFlags.toString(16)}`
                });
            },
            onLeave: function(retval) {
                const status = retval.toInt32();
                
                // 성공한 경우 암호문 캡처
                if (status === 0 && !this.pbOutput.isNull() && this.cbOutput > 0) {
                    // 실제 출력 크기 읽기
                    const actualSize = this.pcbResult.isNull() ? this.cbOutput : Memory.readU32(this.pcbResult);
                    agent.dumpMemory(this.pbOutput, Math.min(actualSize, 1024), `cng_encrypt_ciphertext_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'BCryptEncrypt',
                    ntstatus: agent.ntStatusToString(status),
                    success: status === 0,
                    output_size: this.pcbResult.isNull() ? this.cbOutput : Memory.readU32(this.pcbResult)
                });
            }
        });

        // BCryptDecrypt
        this.hookFunction(this.bcrypt, "BCryptDecrypt", {
            args: ['pointer', 'pointer', 'uint32', 'pointer', 'pointer', 'uint32', 'pointer', 'uint32', 'pointer', 'uint32'],
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
                this.pcbResult = args[8];
                this.dwFlags = args[9].toInt32();

                const keyInfo = agent.keys.get(this.hKey.toString());

                // 암호문 데이터 캡처
                if (!this.pbInput.isNull() && this.cbInput > 0) {
                    agent.dumpMemory(this.pbInput, Math.min(this.cbInput, 1024), `cng_decrypt_ciphertext_${this.opId}`);
                }

                // IV 캡처
                if (!this.pbIV.isNull() && this.cbIV > 0) {
                    agent.dumpMemory(this.pbIV, this.cbIV, `cng_decrypt_iv_${this.opId}`);
                }

                agent.log('decrypt_operation', {
                    operation_id: this.opId,
                    function: 'BCryptDecrypt',
                    algorithm: keyInfo ? keyInfo.algorithm : "unknown",
                    input_size: this.cbInput,
                    iv_size: this.cbIV
                });
            },
            onLeave: function(retval) {
                const status = retval.toInt32();
                
                // 성공한 경우 평문 캡처
                if (status === 0 && !this.pbOutput.isNull() && this.cbOutput > 0) {
                    const actualSize = this.pcbResult.isNull() ? this.cbOutput : Memory.readU32(this.pcbResult);
                    agent.dumpMemory(this.pbOutput, Math.min(actualSize, 1024), `cng_decrypt_plaintext_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'BCryptDecrypt',
                    ntstatus: agent.ntStatusToString(status),
                    success: status === 0
                });
            }
        });
    }

    // BCrypt 해시 함수 후킹
    hookBCryptHashing() {
        console.log("[+] BCrypt 해시 함수 후킹...");

        // BCryptCreateHash
        this.hookFunction(this.bcrypt, "BCryptCreateHash", {
            args: ['pointer', 'pointer', 'pointer', 'uint32', 'pointer', 'uint32', 'uint32'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hAlgorithm = args[0];
                this.phHash = args[1];
                this.pbHashObject = args[2];
                this.cbHashObject = args[3].toInt32();
                this.pbSecret = args[4];
                this.cbSecret = args[5].toInt32();
                this.dwFlags = args[6].toInt32();

                const algInfo = agent.algorithms.get(this.hAlgorithm.toString());

                // HMAC 키 캡처
                if (!this.pbSecret.isNull() && this.cbSecret > 0) {
                    agent.dumpMemory(this.pbSecret, this.cbSecret, `cng_hmac_key_${this.opId}`);
                }

                agent.log('hash_create', {
                    operation_id: this.opId,
                    function: 'BCryptCreateHash',
                    algorithm: algInfo ? algInfo.algorithm : "unknown",
                    has_secret: this.cbSecret > 0,
                    secret_size: this.cbSecret
                });
            }
        });

        // BCryptHashData
        this.hookFunction(this.bcrypt, "BCryptHashData", {
            args: ['pointer', 'pointer', 'uint32', 'uint32'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hHash = args[0];
                this.pbInput = args[1];
                this.cbInput = args[2].toInt32();
                this.dwFlags = args[3].toInt32();

                // 해시 입력 데이터 캡처
                if (!this.pbInput.isNull() && this.cbInput > 0) {
                    agent.dumpMemory(this.pbInput, Math.min(this.cbInput, 512), `cng_hash_input_${this.opId}`);
                }

                agent.log('hash_data', {
                    operation_id: this.opId,
                    function: 'BCryptHashData',
                    input_size: this.cbInput
                });
            }
        });

        // BCryptFinishHash
        this.hookFunction(this.bcrypt, "BCryptFinishHash", {
            args: ['pointer', 'pointer', 'uint32', 'uint32'],
            onEnter: function(args) {
                this.hHash = args[0];
                this.pbOutput = args[1];
                this.cbOutput = args[2].toInt32();
                this.dwFlags = args[3].toInt32();
                this.opId = ++agent.operationId;
            },
            onLeave: function(retval) {
                const status = retval.toInt32();
                
                // 성공한 경우 해시 결과 캡처
                if (status === 0 && !this.pbOutput.isNull() && this.cbOutput > 0) {
                    agent.dumpMemory(this.pbOutput, this.cbOutput, `cng_hash_result_${this.opId}`);
                }

                agent.log('hash_finish', {
                    operation_id: this.opId,
                    function: 'BCryptFinishHash',
                    ntstatus: agent.ntStatusToString(status),
                    success: status === 0,
                    hash_size: this.cbOutput
                });
            }
        });
    }

    // NCrypt (비대칭키) 후킹
    hookNCryptOperations() {
        if (!this.ncrypt) return;
        
        console.log("[+] NCrypt 비대칭키 함수 후킹...");

        // NCryptCreatePersistedKey
        this.hookFunction(this.ncrypt, "NCryptCreatePersistedKey", {
            args: ['pointer', 'pointer', 'pointer', 'pointer', 'uint32', 'uint32'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hProvider = args[0];
                this.phKey = args[1];
                this.pszAlgId = args[2];
                this.pszKeyName = args[3];
                this.dwLegacyKeySpec = args[4].toInt32();
                this.dwFlags = args[5].toInt32();

                const algId = this.pszAlgId.isNull() ? "NULL" : Memory.readUtf16String(this.pszAlgId);
                const keyName = this.pszKeyName.isNull() ? "NULL" : Memory.readUtf16String(this.pszKeyName);

                agent.log('ncrypt_key_create', {
                    operation_id: this.opId,
                    function: 'NCryptCreatePersistedKey',
                    algorithm: algId,
                    key_name: keyName,
                    flags: `0x${this.dwFlags.toString(16)}`
                });
            }
        });

        // NCryptEncrypt
        this.hookFunction(this.ncrypt, "NCryptEncrypt", {
            args: ['pointer', 'pointer', 'uint32', 'pointer', 'pointer', 'uint32', 'pointer', 'uint32'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hKey = args[0];
                this.pbInput = args[1];
                this.cbInput = args[2].toInt32();
                this.pPaddingInfo = args[3];
                this.pbOutput = args[4];
                this.cbOutput = args[5].toInt32();
                this.pcbResult = args[6];
                this.dwFlags = args[7].toInt32();

                // 평문 캡처
                if (!this.pbInput.isNull() && this.cbInput > 0) {
                    agent.dumpMemory(this.pbInput, this.cbInput, `ncrypt_encrypt_plaintext_${this.opId}`);
                }

                agent.log('ncrypt_encrypt', {
                    operation_id: this.opId,
                    function: 'NCryptEncrypt',
                    input_size: this.cbInput,
                    output_buffer_size: this.cbOutput
                });
            },
            onLeave: function(retval) {
                const status = retval.toInt32();
                
                if (status === 0 && !this.pbOutput.isNull()) {
                    const actualSize = this.pcbResult.isNull() ? this.cbOutput : Memory.readU32(this.pcbResult);
                    agent.dumpMemory(this.pbOutput, actualSize, `ncrypt_encrypt_ciphertext_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'NCryptEncrypt',
                    ntstatus: agent.ntStatusToString(status),
                    success: status === 0
                });
            }
        });
    }

    // 범용 함수 후킹 헬퍼
    hookFunction(module, funcName, config) {
        if (!module) return false;
        
        try {
            const funcAddr = Module.findExportByName(module.name, funcName);
            if (!funcAddr) {
                console.log(`[-] ${funcName} 함수를 찾을 수 없음 (${module.name})`);
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
        console.log("[+] Windows CNG 전용 에이전트 시작");
        
        if (Process.platform !== 'windows') {
            throw new Error("이 에이전트는 Windows 전용입니다");
        }
        
        try {
            this.initializeCNG();
            
            // 함수별 후킹 시작
            if (this.bcrypt) {
                this.hookBCryptAlgorithmProvider();
                this.hookBCryptKeyManagement();
                this.hookBCryptEncryption();
                this.hookBCryptHashing();
            }
            
            if (this.ncrypt) {
                this.hookNCryptOperations();
            }
            
            // 프로세스 정보 전송
            this.log('agent_info', {
                agent_type: 'windows_cng',
                process_id: Process.id,
                platform: Process.platform,
                arch: Process.arch,
                bcrypt_available: !!this.bcrypt,
                ncrypt_available: !!this.ncrypt,
                crypt32_available: !!this.crypt32,
                bcrypt_base: this.bcrypt?.base.toString(),
                ncrypt_base: this.ncrypt?.base.toString()
            });

            console.log("[+] Windows CNG 에이전트 초기화 완료");
            return true;
            
        } catch (e) {
            console.log(`[-] Windows CNG 에이전트 초기화 실패: ${e.message}`);
            return false;
        }
    }
}

// 에이전트 인스턴스 생성 및 초기화
const agent = new WindowsCNGAgent();
const success = agent.initialize();

if (success) {
    console.log("[+] Windows CNG 암호화 작업 모니터링 시작...");
} else {
    console.log("[-] 에이전트 초기화 실패. 종료합니다.");
}

// RPC 인터페이스
rpc.exports = {
    getStats: function() {
        return {
            agent_type: 'windows_cng',
            operations_count: agent.operationId,
            uptime_ms: Date.now() - agent.startTime,
            algorithms_active: agent.algorithms.size,
            keys_active: agent.keys.size,
            platform: Process.platform
        };
    },
    
    getActiveAlgorithms: function() {
        return Array.from(agent.algorithms.entries()).map(([handle, info]) => ({
            handle: handle,
            ...info
        }));
    },
    
    getActiveKeys: function() {
        return Array.from(agent.keys.entries()).map(([handle, info]) => ({
            handle: handle,
            ...info
        }));
    }
};