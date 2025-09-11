// 암호화 알고리즘 ID를 문자열로 변환
    cipherAlgoToString(algo) {
        const algoMap = {
            0: "NONE",
            1: "IDEA",
            2: "3DES",
            3: "CAST5",
            4: "BLOWFISH",
            7: "AES",
            8: "AES192",
            9: "AES256",
            10: "TWOFISH",
            11: "CAMELLIA128",
            12: "CAMELLIA192", 
            13: "CAMELLIA256",
            301: "ARCFOUR",
            302: "DES",
            303: "TWOFISH128",
            304: "SERPENT128",
            305: "SERPENT192",
            306: "SERPENT256",
            307: "RFC2268_40",
            308: "RFC2268_128",
            309: "SEED",
            310: "CHACHA20"
        };
        
        return algoMap[algo] || `UNKNOWN_CIPHER_${algo}`;
    }

    // 해시 알고리즘 ID를 문자열로 변환
    digestAlgoToString(algo) {
        const algoMap = {
            0: "NONE",
            1: "MD5",
            2: "SHA1",
            3: "RMD160",
            6: "TIGER",
            7: "HAVAL",
            8: "SHA256",
            9: "SHA384",
            10: "SHA512",
            11: "SHA224",
            301: "MD2",
            302: "TIGER1",
            303: "TIGER2",
            307: "WHIRLPOOL",
            308: "SHA3_224",
            309: "SHA3_256",
            310: "SHA3_384",
            311: "SHA3_512",
            312: "BLAKE2B_512",
            313: "BLAKE2B_384",
            314: "BLAKE2B_256",
            315: "BLAKE2B_160",
            316: "BLAKE2S_256",
            317: "BLAKE2S_224",
            318: "BLAKE2S_160",
            319: "BLAKE2S_128"
        };
        
        return algoMap[algo] || `UNKNOWN_DIGEST_${algo}`;
    }

    // libgcrypt 라이브러리 초기화
    initializeLibgcrypt() {
        console.log("[+] libgcrypt 라이브러리 탐지 중...");

        const gcryptNames = [
            "libgcrypt.so", "libgcrypt.so.20", "libgcrypt.so.11",
            "libgcrypt.dll", "gcrypt.dll"
        ];

        for (let name of gcryptNames) {
            this.libgcrypt = Process.findModuleByName(name);
            if (this.libgcrypt) {
                console.log(`[+] libgcrypt 발견: ${name} @ ${this.libgcrypt.base}`);
                break;
            }
        }

        if (!this.libgcrypt) {
            throw new Error("libgcrypt 라이브러리를 찾을 수 없습니다");
        }

        this.detectGcryptVersion();
    }

    detectGcryptVersion() {
        try {
            const versionFunc = Module.findExportByName(this.libgcrypt.name, "gcry_check_version");
            if (versionFunc) {
                const checkVersion = new NativeFunction(versionFunc, 'pointer', ['pointer']);
                const versionPtr = checkVersion(ptr(0)); // NULL을 전달하면 현재 버전 반환
                if (!versionPtr.isNull()) {
                    this.gcryptVersion = Memory.readUtf8String(versionPtr);
                    console.log(`[+] libgcrypt 버전: ${this.gcryptVersion}`);
                }
            }
        } catch (e) {
            console.log(`[!] libgcrypt 버전 탐지 실패: ${e.message}`);
        }
    }

    // 대칭키 암호화 후킹
    hookSymmetricCrypto() {
        console.log("[+] 대칭키 암호화 함수 후킹...");

        // gcry_cipher_open - 암호화 핸들 생성
        this.hookFunction("gcry_cipher_open", {
            args: ['pointer', 'int', 'int', 'uint'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.handle = args[0];
                this.algo = args[1].toInt32();
                this.mode = args[2].toInt32();
                this.flags = args[3].toInt32();

                const algoName = agent.cipherAlgoToString(this.algo);
                const modeMap = {
                    0: "NONE",
                    1: "ECB",
                    2: "CFB",
                    3: "CBC",
                    4: "STREAM",
                    5: "OFB",
                    6: "CTR",
                    7: "AESWRAP",
                    8: "CCM",
                    9: "GCM",
                    10: "POLY1305",
                    11: "OCB",
                    12: "XTS"
                };
                const modeName = modeMap[this.mode] || `MODE_${this.mode}`;

                agent.log('cipher_open', {
                    operation_id: this.opId,
                    function: 'gcry_cipher_open',
                    algorithm: algoName,
                    mode: modeName,
                    flags: `0x${this.flags.toString(16)}`
                });
            },
            onLeave: function(retval) {
                const error = retval.toInt32();
                
                if (error === 0 && !this.handle.isNull()) {
                    const cipherHandle = Memory.readPointer(this.handle);
                    agent.cipherHandles.set(cipherHandle.toString(), {
                        opId: this.opId,
                        algorithm: agent.cipherAlgoToString(this.algo),
                        mode: this.mode
                    });
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_cipher_open',
                    error_code: error,
                    error: agent.gcryptErrorToString(error),
                    success: error === 0
                });
            }
        });

        // gcry_cipher_setkey - 키 설정
        this.hookFunction("gcry_cipher_setkey", {
            args: ['pointer', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hd = args[0];
                this.key = args[1];
                this.keylen = args[2].toInt32();

                const handleInfo = agent.cipherHandles.get(this.hd.toString());

                // 키 데이터 캡처
                if (!this.key.isNull() && this.keylen > 0) {
                    agent.dumpMemory(this.key, this.keylen, `gcrypt_cipher_key_${this.opId}`);
                }

                agent.log('cipher_setkey', {
                    operation_id: this.opId,
                    function: 'gcry_cipher_setkey',
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown",
                    key_length_bytes: this.keylen,
                    key_length_bits: this.keylen * 8
                });
            },
            onLeave: function(retval) {
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_cipher_setkey',
                    error_code: retval.toInt32(),
                    error: agent.gcryptErrorToString(retval.toInt32()),
                    success: retval.toInt32() === 0
                });
            }
        });

        // gcry_cipher_setiv - IV 설정
        this.hookFunction("gcry_cipher_setiv", {
            args: ['pointer', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hd = args[0];
                this.iv = args[1];
                this.ivlen = args[2].toInt32();

                const handleInfo = agent.cipherHandles.get(this.hd.toString());

                // IV 데이터 캡처
                if (!this.iv.isNull() && this.ivlen > 0) {
                    agent.dumpMemory(this.iv, this.ivlen, `gcrypt_cipher_iv_${this.opId}`);
                }

                agent.log('cipher_setiv', {
                    operation_id: this.opId,
                    function: 'gcry_cipher_setiv',
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown",
                    iv_length: this.ivlen
                });
            }
        });

        // gcry_cipher_encrypt - 암호화
        this.hookFunction("gcry_cipher_encrypt", {
            args: ['pointer', 'pointer', 'size_t', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hd = args[0];
                this.out = args[1];
                this.outsize = args[2].toInt32();
                this.in = args[3];
                this.inlen = args[4].toInt32();

                const handleInfo = agent.cipherHandles.get(this.hd.toString());

                // 평문 데이터 캡처
                if (!this.in.isNull() && this.inlen > 0) {
                    agent.dumpMemory(this.in, Math.min(this.inlen, 1024), 
                        `gcrypt_encrypt_plaintext_${this.opId}`);
                }

                agent.log('cipher_encrypt', {
                    operation_id: this.opId,
                    function: 'gcry_cipher_encrypt',
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown",
                    input_size: this.inlen,
                    output_buffer_size: this.outsize
                });
            },
            onLeave: function(retval) {
                const error = retval.toInt32();
                
                // 성공한 경우 암호문 캡처
                if (error === 0 && !this.out.isNull() && this.inlen > 0) {
                    agent.dumpMemory(this.out, Math.min(this.inlen, 1024), 
                        `gcrypt_encrypt_ciphertext_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_cipher_encrypt',
                    error_code: error,
                    error: agent.gcryptErrorToString(error),
                    success: error === 0
                });
            }
        });

        // gcry_cipher_decrypt - 복호화
        this.hookFunction("gcry_cipher_decrypt", {
            args: ['pointer', 'pointer', 'size_t', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hd = args[0];
                this.out = args[1];
                this.outsize = args[2].toInt32();
                this.in = args[3];
                this.inlen = args[4].toInt32();

                const handleInfo = agent.cipherHandles.get(this.hd.toString());

                // 암호문 데이터 캡처
                if (!this.in.isNull() && this.inlen > 0) {
                    agent.dumpMemory(this.in, Math.min(this.inlen, 1024), 
                        `gcrypt_decrypt_ciphertext_${this.opId}`);
                }

                agent.log('cipher_decrypt', {
                    operation_id: this.opId,
                    function: 'gcry_cipher_decrypt',
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown",
                    input_size: this.inlen
                });
            },
            onLeave: function(retval) {
                const error = retval.toInt32();
                
                // 성공한 경우 평문 캡처
                if (error === 0 && !this.out.isNull() && this.inlen > 0) {
                    agent.dumpMemory(this.out, Math.min(this.inlen, 1024), 
                        `gcrypt_decrypt_plaintext_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_cipher_decrypt',
                    error_code: error,
                    error: agent.gcryptErrorToString(error),
                    success: error === 0
                });
            }
        });

        // gcry_cipher_close - 암호화 핸들 종료
        this.hookFunction("gcry_cipher_close", {
            args: ['pointer'],
            onEnter: function(args) {
                this.hd = args[0];
                const handleInfo = agent.cipherHandles.get(this.hd.toString());
                
                agent.log('cipher_close', {
                    cipher_handle: this.hd.toString(),
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown"
                });
            },
            onLeave: function(retval) {
                agent.cipherHandles.delete(this.hd.toString());
            }
        });
    }

    // 해시 함수 후킹
    hookDigestOperations() {
        console.log("[+] 해시 함수 후킹...");

        // gcry_md_open - 해시 핸들 생성
        this.hookFunction("gcry_md_open", {
            args: ['pointer', 'int', 'uint'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.md = args[0];
                this.algo = args[1].toInt32();
                this.flags = args[2].toInt32();

                const algoName = agent.digestAlgoToString(this.algo);

                agent.log('md_open', {
                    operation_id: this.opId,
                    function: 'gcry_md_open',
                    algorithm: algoName,
                    flags: `0x${this.flags.toString(16)}`
                });
            },
            onLeave: function(retval) {
                const error = retval.toInt32();
                
                if (error === 0 && !this.md.isNull()) {
                    const mdHandle = Memory.readPointer(this.md);
                    agent.hashHandles.set(mdHandle.toString(), {
                        opId: this.opId,
                        algorithm: agent.digestAlgoToString(this.algo)
                    });
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_md_open',
                    error_code: error,
                    error: agent.gcryptErrorToString(error),
                    success: error === 0
                });
            }
        });

        // gcry_md_write - 해시 데이터 입력
        this.hookFunction("gcry_md_write", {
            args: ['pointer', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hd = args[0];
                this.buffer = args[1];
                this.length = args[2].toInt32();

                const handleInfo = agent.hashHandles.get(this.hd.toString());

                // 해시 입력 데이터 캡처
                if (!this.buffer.isNull() && this.length > 0) {
                    agent.dumpMemory(this.buffer, Math.min(this.length, 512), 
                        `gcrypt_hash_input_${this.opId}`);
                }

                agent.log('md_write', {
                    operation_id: this.opId,
                    function: 'gcry_md_write',
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown",
                    data_length: this.length
                });
            }
        });

        // gcry_md_final - 해시 완료
        this.hookFunction("gcry_md_final", {
            args: ['pointer'],
            onEnter: function(args) {
                this.hd = args[0];
                const handleInfo = agent.hashHandles.get(this.hd.toString());
                this.opId = ++agent.operationId;

                agent.log('md_final', {
                    operation_id: this.opId,
                    function: 'gcry_md_final',
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown"
                });
            }
        });

        // gcry_md_read - 해시 결과 읽기
        this.hookFunction("gcry_md_read", {
            args: ['pointer', 'int'],
            onEnter: function(args) {
                this.hd = args[0];
                this.algo = args[1].toInt32();
                const handleInfo = agent.hashHandles.get(this.hd.toString());
                this.opId = ++agent.operationId;

                agent.log('md_read', {
                    operation_id: this.opId,
                    function: 'gcry_md_read',
                    algorithm: agent.digestAlgoToString(this.algo)
                });
            },
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    // 해시 결과 크기 계산
                    let hashSize = 32; // 기본값 SHA-256
                    switch(this.algo) {
                        case 1: hashSize = 16; break; // MD5
                        case 2: hashSize = 20; break; // SHA1
                        case 8: hashSize = 32; break; // SHA256
                        case 9: hashSize = 48; break; // SHA384
                        case 10: hashSize = 64; break; // SHA512
                        case 11: hashSize = 28; break; // SHA224
                    }
                    
                    agent.dumpMemory(retval, hashSize, `gcrypt_hash_result_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_md_read',
                    algorithm: agent.digestAlgoToString(this.algo),
                    success: !retval.isNull()
                });
            }
        });
    }

    // 공개키 암호화 후킹
    hookPublicKeyCrypto() {
        console.log("[+] 공개키 암호화 함수 후킹...");

        // gcry_pk_encrypt - 공개키 암호화
        this.hookFunction("gcry_pk_encrypt", {
            args: ['pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.result = args[0];
                this.data = args[1];
                this.pkey = args[2];

                agent.log('pk_encrypt', {
                    operation_id: this.opId,
                    function: 'gcry_pk_encrypt'
                });
            },
            onLeave: function(retval) {
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_pk_encrypt',
                    error_code: retval.toInt32(),
                    error: agent.gcryptErrorToString(retval.toInt32()),
                    success: retval.toInt32() === 0
                });
            }
        });

        // gcry_pk_decrypt - 공개키 복호화
        this.hookFunction("gcry_pk_decrypt", {
            args: ['pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.result = args[0];
                this.data = args[1];
                this.skey = args[2];

                agent.log('pk_decrypt', {
                    operation_id: this.opId,
                    function: 'gcry_pk_decrypt'
                });
            },
            onLeave: function(retval) {
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_pk_decrypt',
                    error_code: retval.toInt32(),
                    error: agent.gcryptErrorToString(retval.toInt32()),
                    success: retval.toInt32() === 0
                });
            }
        });

        // gcry_pk_sign - 디지털 서명
        this.hookFunction("gcry_pk_sign", {
            args: ['pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.result = args[0];
                this.data = args[1];
                this.skey = args[2];

                agent.log('pk_sign', {
                    operation_id: this.opId,
                    function: 'gcry_pk_sign'
                });
            },
            onLeave: function(retval) {
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_pk_sign',
                    error_code: retval.toInt32(),
                    error: agent.gcryptErrorToString(retval.toInt32()),
                    success: retval.toInt32() === 0
                });
            }
        });

        // gcry_pk_verify - 서명 검증
        this.hookFunction("gcry_pk_verify", {
            args: ['pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.sigval = args[0];
                this.data = args[1];
                this.pkey = args[2];

                agent.log('pk_verify', {
                    operation_id: this.opId,
                    function: 'gcry_pk_verify'
                });
            },
            onLeave: function(retval) {
                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_pk_verify',
                    error_code: retval.toInt32(),
                    error: agent.gcryptErrorToString(retval.toInt32()),
                    success: retval.toInt32() === 0
                });
            }
        });
    }

    // MAC (Message Authentication Code) 후킹
    hookMACOperations() {
        console.log("[+] MAC 함수 후킹...");

        // gcry_mac_open - MAC 핸들 생성
        this.hookFunction("gcry_mac_open", {
            args: ['pointer', 'int', 'uint', 'pointer'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.handle = args[0];
                this.algo = args[1].toInt32();
                this.flags = args[2].toInt32();
                this.ctx = args[3];

                const macAlgoMap = {
                    101: "HMAC_SHA1",
                    102: "HMAC_SHA224",
                    103: "HMAC_SHA256",
                    104: "HMAC_SHA384",
                    105: "HMAC_SHA512",
                    106: "HMAC_MD5",
                    201: "CMAC_AES",
                    301: "GMAC_AES"
                };
                
                const algoName = macAlgoMap[this.algo] || `MAC_${this.algo}`;

                agent.log('mac_open', {
                    operation_id: this.opId,
                    function: 'gcry_mac_open',
                    algorithm: algoName,
                    flags: `0x${this.flags.toString(16)}`
                });
            },
            onLeave: function(retval) {
                const error = retval.toInt32();
                
                if (error === 0 && !this.handle.isNull()) {
                    const macHandle = Memory.readPointer(this.handle);
                    agent.macHandles.set(macHandle.toString(), {
                        opId: this.opId,
                        algorithm: this.algo
                    });
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_mac_open',
                    error_code: error,
                    error: agent.gcryptErrorToString(error),
                    success: error === 0
                });
            }
        });

        // gcry_mac_setkey - MAC 키 설정
        this.hookFunction("gcry_mac_setkey", {
            args: ['pointer', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hd = args[0];
                this.key = args[1];
                this.keylen = args[2].toInt32();

                const handleInfo = agent.macHandles.get(this.hd.toString());

                // MAC 키 캡처
                if (!this.key.isNull() && this.keylen > 0) {
                    agent.dumpMemory(this.key, this.keylen, `gcrypt_mac_key_${this.opId}`);
                }

                agent.log('mac_setkey', {
                    operation_id: this.opId,
                    function: 'gcry_mac_setkey',
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown",
                    key_length: this.keylen
                });
            }
        });

        // gcry_mac_write - MAC 데이터 입력
        this.hookFunction("gcry_mac_write", {
            args: ['pointer', 'pointer', 'size_t'],
            onEnter: function(args) {
                this.opId = ++agent.operationId;
                this.hd = args[0];
                this.buffer = args[1];
                this.length = args[2].toInt32();

                const handleInfo = agent.macHandles.get(this.hd.toString());

                // MAC 입력 데이터 캡처
                if (!this.buffer.isNull() && this.length > 0) {
                    agent.dumpMemory(this.buffer, Math.min(this.length, 512), 
                        `gcrypt_mac_input_${this.opId}`);
                }

                agent.log('mac_write', {
                    operation_id: this.opId,
                    function: 'gcry_mac_write',
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown",
                    data_length: this.length
                });
            }
        });

        // gcry_mac_read - MAC 결과 읽기
        this.hookFunction("gcry_mac_read", {
            args: ['pointer', 'pointer', 'pointer'],
            onEnter: function(args) {
                this.hd = args[0];
                this.buffer = args[1];
                this.buflen = args[2];
                const handleInfo = agent.macHandles.get(this.hd.toString());
                this.opId = ++agent.operationId;

                agent.log('mac_read', {
                    operation_id: this.opId,
                    function: 'gcry_mac_read',
                    algorithm: handleInfo ? handleInfo.algorithm : "unknown"
                });
            },
            onLeave: function(retval) {
                const error = retval.toInt32();
                
                if (error === 0 && !this.buffer.isNull() && !this.buflen.isNull()) {
                    const macLen = Memory.readULong(this.buflen);
                    agent.dumpMemory(this.buffer, macLen, `gcrypt_mac_result_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_mac_read',
                    error_code: error,
                    error: agent.gcryptErrorToString(error),
                    success: error === 0
                });
            }
        });
    }

    // 난수 생성 후킹
    hookRandomGeneration() {
        console.log("[+] 난수 생성 함수 후킹...");

        // gcry_randomize - 난수 생성
        this.hookFunction("gcry_randomize", {
            args: ['pointer', 'size_t', 'int'],
            onEnter: function(args) {
                this.buffer = args[0];
                this.length = args[1].toInt32();
                this.level = args[2].toInt32();
                this.opId = ++agent.operationId;

                const levelMap = {
                    0: "WEAK",
                    1: "STRONG", 
                    2: "VERY_STRONG"
                };
                const levelName = levelMap[this.level] || `LEVEL_${this.level}`;

                agent.log('random_generation', {
                    operation_id: this.opId,
                    function: 'gcry_randomize',
                    length: this.length,
                    level: levelName
                });
            },
            onLeave: function(retval) {
                // 난수 데이터 캡처
                if (!this.buffer.isNull() && this.length > 0) {
                    agent.dumpMemory(this.buffer, Math.min(this.length, 256), 
                        `gcrypt_random_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_randomize',
                    success: true // gcry_randomize는 void 함수
                });
            }
        });

        // gcry_create_nonce - 논스 생성
        this.hookFunction("gcry_create_nonce", {
            args: ['pointer', 'size_t'],
            onEnter: function(args) {
                this.buffer = args[0];
                this.length = args[1].toInt32();
                this.opId = ++agent.operationId;

                agent.log('nonce_generation', {
                    operation_id: this.opId,
                    function: 'gcry_create_nonce',
                    length: this.length
                });
            },
            onLeave: function(retval) {
                // 논스 데이터 캡처
                if (!this.buffer.isNull() && this.length > 0) {
                    agent.dumpMemory(this.buffer, Math.min(this.length, 256), 
                        `gcrypt_nonce_${this.opId}`);
                }

                agent.log('operation_result', {
                    operation_id: this.opId,
                    function: 'gcry_create_nonce',
                    success: true // gcry_create_nonce는 void 함수
                });
            }
        });
    }

    // 범용 함수 후킹 헬퍼
    hookFunction(funcName, config) {
        try {
            const funcAddr = Module.findExportByName(this.libgcrypt.name, funcName);
            
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
        console.log("[+] libgcrypt 전용 에이전트 시작");
        
        try {
            this.initializeLibgcrypt();
            
            // 함수별 후킹 시작
            this.hookSymmetricCrypto();
            this.hookDigestOperations();
            this.hookPublicKeyCrypto();
            this.hookMACOperations();
            this.hookRandomGeneration();
            
            // 프로세스 정보 전송
            this.log('agent_info', {
                agent_type: 'libgcrypt',
                libgcrypt_version: this.gcryptVersion,
                process_id: Process.id,
                platform: Process.platform,
                arch: Process.arch,
                libgcrypt_base: this.libgcrypt.base.toString()
            });

            console.log("[+] libgcrypt 에이전트 초기화 완료");
            return true;
            
        } catch (e) {
            console.log(`[-] libgcrypt 에이전트 초기화 실패: ${e.message}`);
            return false;
        }
    }
}

// 에이전트 인스턴스 생성 및 초기화
const agent = new LibgcryptAgent();
const success = agent.initialize();

if (success) {
    console.log("[+] libgcrypt 암호화 작업 모니터링 시작...");
} else {
    console.log("[-] 에이전트 초기화 실패. 종료합니다.");
}

// RPC 인터페이스
rpc.exports = {
    getStats: function() {
        return {
            agent_type: 'libgcrypt',
            operations_count: agent.operationId,
            uptime_ms: Date.now() - agent.startTime,
            cipher_handles_active: agent.cipherHandles.size,
            hash_handles_active: agent.hashHandles.size,
            mac_handles_active: agent.macHandles.size,
            libgcrypt_version: agent.gcryptVersion
        };
    },
    
    getActiveCipherHandles: function() {
        return Array.from(agent.cipherHandles.entries()).map(([handle, info]) => ({
            handle: handle,
            ...info
        }));
    },
    
    getActiveHashHandles: function() {
        return Array.from(agent.hashHandles.entries()).map(([handle, info]) => ({
            handle: handle,
            ...info
        }));
    },
    
    getActiveMacHandles: function() {
        return Array.from(agent.macHandles.entries()).map(([handle, info]) => ({
            handle: handle,
            ...info
        }));
    }
};
                // libgcrypt 전용 암호화 후킹 에이전트
// 대상: libgcrypt.so (GNU Privacy Guard, GnuPG에서 사용)

class LibgcryptAgent {
    constructor() {
        this.operationId = 0;
        this.startTime = Date.now();
        this.libgcrypt = null;
        this.gcryptVersion = null;
        this.cipherHandles = new Map(); // 암호화 핸들 추적
        this.hashHandles = new Map(); // 해시 핸들 추적
        this.macHandles = new Map(); // MAC 핸들 추적
    }

    log(category, data) {
        send({
            type: 'libgcrypt_capture',
            category: category,
            timestamp: Date.now() - this.startTime,
            agent: 'libgcrypt',
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

    // libgcrypt 에러 코드 해석
    gcryptErrorToString(error) {
        const errorMap = {
            0: "GPG_ERR_NO_ERROR",
            1: "GPG_ERR_GENERAL",
            2: "GPG_ERR_UNKNOWN_PACKET",
            3: "GPG_ERR_UNKNOWN_VERSION", 
            4: "GPG_ERR_PUBKEY_ALGO",
            5: "GPG_ERR_DIGEST_ALGO",
            6: "GPG_ERR_BAD_PUBKEY",
            7: "GPG_ERR_BAD_SECKEY",
            8: "GPG_ERR_BAD_SIGNATURE",
            9: "GPG_ERR_NO_PUBKEY",
            10: "GPG_ERR_CHECKSUM",
            11: "GPG_ERR_BAD_PASSPHRASE",
            12: "GPG_ERR_CIPHER_ALGO",
            45: "GPG_ERR_INV_KEYRING",
            50: "GPG_ERR_WEAK_KEY",
            52: "GPG_ERR_INVALID_LENGTH",
            58: "GPG_ERR_TOO_SHORT",
            67: "GPG_ERR_BUFFER_TOO_SHORT"
        };
        
        return errorMap[error] || `GPG_ERR_${error}`;
    }

    // 암호화 알고리즘 ID를 문자열로 변환
    cipherAlgoToString(algo) {
        const algoMap = {
            0: "NONE",
            1: "IDEA",
            2: "3DES",
            3: "CAST5",
            4: "BLOWFISH",
            7: "AES",
            8: "AES192",
            9: "AES256",
            10: "TWOFISH",
            11: "CAMELLIA128",
            12: "CAMELLIA192", 
            13: "CAMELLIA256",
            301: "ARCFOUR",
            302: "DES",
            303: "TWOFISH128",
            304: "SERPENT128",
            305: "SERPENT192",
            306: "SERPENT256",
            307: "RFC2268_