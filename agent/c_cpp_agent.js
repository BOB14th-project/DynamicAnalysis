/*
 * Advanced Generic Tracer (v12 - Universal, Typed, Flat send)
 * - Hooks exported functions (optionally filtered)
 * - classifies args/return as code_ptr/data_ptr/scalar
 * - supports signatureOverrides (argc/ret) to kill noise
 * - OpenSSL EVP introspection (Encrypt/Decrypt/Cipher Init/Update/Final)
 *
 * NOTE: stableSend() now FLATTENS messages:
 *   send({ event: 'function_call', moduleName, functionName, ... })
 * No nested "payload" anymore.
 */

'use strict';

/* ======================= config ======================= */

let config = {
  main_module: null,
  target_modules: [],
  dumpSize: 64,
  maxArgs: 8,
  captureBacktrace: false,
  hookDynamicLoads: true,

  includePatterns: [
    '^EVP_', '^RSA_', '^EC_', '^ED25519', '^X25519', '^BN_', '^DH_', '^DSA_',
    '^HMAC_', '^CMAC_', 'HKDF', 'PBKDF2', '^RAND_',
    '^AES_', '^ChaCha20', '^Poly1305',
    '^SHA(?:1|224|256|384|512)(?:_.*)?$',
    '^MD(?:4|5)(?:_.*)?$',
    '^SSL_', '^TLS_'
  ],

  // 이름이 정확히 `_free` 로 끝나는 모든 함수 제외 (예: EVP_PKEY_free)
  excludePatterns: [
    '_free$',
    '^CRYPTO_(malloc|zalloc|realloc|free)$',
    '^OPENSSL_(malloc|free|cleanse)$',
    '^mem(?:cpy|set|move|cmp)$', '^bzero$', '^str.*$'
  ],

  // 함수별 인자 수/반환 타입 강제 지정 (노이즈 제거용)
  // ret: 'void' | 'pointer' | 'scalar'
  signatureOverrides: {
    'EVP_PBE_cleanup':       { argc: 0, ret: 'void' },
    'EVP_rc4_hmac_md5':      { argc: 0, ret: 'pointer' },
    'EVP_sha256':            { argc: 0, ret: 'pointer' },
    'EVP_aes_128_gcm':       { argc: 0, ret: 'pointer' },

    'OBJ_NAME_do_all':       { argc: 3, ret: 'void' },
    'OPENSSL_LH_doall_arg':  { argc: 3, ret: 'void' },

    // EVP* 시그니처 고정
    'EVP_CipherInit_ex':     { argc: 6, ret: 'scalar' },   // (ctx,type,impl,key,iv,enc)
    'EVP_CipherUpdate':      { argc: 5, ret: 'scalar' },   // (ctx,out,outl,in,inl)
    'EVP_CipherFinal_ex':    { argc: 3, ret: 'scalar' },   // (ctx,out,outl)

    'EVP_EncryptInit_ex':    { argc: 5, ret: 'scalar' },   // (ctx,type,impl,key,iv)
    'EVP_EncryptUpdate':     { argc: 5, ret: 'scalar' },
    'EVP_EncryptFinal_ex':   { argc: 3, ret: 'scalar' },

    'EVP_DecryptInit_ex':    { argc: 5, ret: 'scalar' },
    'EVP_DecryptUpdate':     { argc: 5, ret: 'scalar' },
    'EVP_DecryptFinal_ex':   { argc: 3, ret: 'scalar' },
  }
};

const hookedModules = new Set();
const hookedFunctions = new Set();

/* ======================= utils ======================= */

function matchesAny(name, patterns) {
  if (!patterns || patterns.length === 0) return true;
  return patterns.some(p => { try { return new RegExp(p).test(name); } catch { return false; } });
}

function matchesNone(name, patterns) {
  if (!patterns || patterns.length === 0) return true;
  return !patterns.some(p => { try { return new RegExp(p).test(name); } catch { return false; } });
}

// FLAT send: no nested payload
function stableSend(event, obj) {
  try { send({ event, ...(obj || {}) }); } catch (_) {}
}

function safeHexdump(p, length) {
  try { return hexdump(p, { length }); } catch (_) { return null; }
}

function safeReadUtf8(p) {
  try { return Memory.readUtf8String(p); } catch (_) { return null; }
}

function safeRead(p) {
  try {
    if (!p || p.isNull()) return null;
    const len = Math.max(0, Math.min(config.dumpSize || 64, 4096));
    return { hex: safeHexdump(p, len), str: safeReadUtf8(p) };
  } catch (_) { return null; }
}

function tryBacktrace(ctx) {
  if (!config.captureBacktrace) return null;
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(addr => DebugSymbol.fromAddress(addr).toString());
  } catch (_) { return null; }
}

// classify pointer vs scalar vs code
function classifyVal(v) {
  try {
    const p = ptr(v);
    const r = Process.findRangeByAddress(p);
    if (!r) return { kind: 'scalar' };
    const prot = (r.protection || '').toLowerCase();
    if (prot.includes('x')) return { kind: 'code_ptr', range: r.base.toString(), prot: r.protection };
    return { kind: 'data_ptr', range: r.base.toString(), prot: r.protection };
  } catch (_) { return { kind: 'scalar' }; }
}

// Optional ASCII preview for buffers
function toAsciiPreview(p, n, max = 128) {
  try {
    if (!p || p.isNull() || n <= 0) return null;
    const len = Math.min(n, max);
    const bytes = Memory.readByteArray(p, len);
    const arr = new Uint8Array(bytes);
    let s = '';
    for (let b of arr) s += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
    return s;
  } catch (_) { return null; }
}

function hexdumpMax(p, n, cap) {
  try {
    if (!p || p.isNull() || n <= 0) return null;
    return hexdump(p, { length: Math.min(n, cap | 0 || 128) });
  } catch (_) { return null; }
}

/* ======================= core hooking ======================= */

function hookExportFunction(moduleName, exp) {
  const key = `${moduleName}!${exp.name}`;
  if (hookedFunctions.has(key)) return;
  hookedFunctions.add(key);

  try {
    Interceptor.attach(exp.address, {
      onEnter(args) {
        this.__ctx = null;
        try {
          const ov  = (config.signatureOverrides || {})[exp.name];
          const argc = Number.isInteger(ov?.argc) ? ov.argc : (config.maxArgs || 8);

          const argList = [];
          for (let i = 0; i < argc; i++) {
            const a = args[i];
            if (a === undefined) break;
            const valStr = a ? a.toString() : "0";
            const meta = classifyVal(valStr);
            argList.push({
              index: i,
              value: valStr,
              kind: meta.kind,
              memory: (meta.kind !== 'scalar' && a) ? safeRead(a) : null
            });
          }

          this.__ctx = {
            moduleName,
            functionName: exp.name,
            args: argList,
            backtrace: tryBacktrace(this.context)
          };
        } catch (e) {
          this.__ctx = { moduleName, functionName: exp.name, error: `arg-parse: ${e.message}` };
        }
      },

      onLeave(retval) {
        if (!this.__ctx) return;
        try {
          const ov = (config.signatureOverrides || {})[this.__ctx.functionName];
          const retIsVoid = ov?.ret === 'void';

          if (!this.__ctx.error && !retIsVoid) {
            const valStr = retval ? retval.toString() : "0";
            const meta = classifyVal(valStr);
            this.__ctx.returnValue = {
              value: valStr,
              kind: meta.kind,
              memory: (meta.kind !== 'scalar' && retval) ? safeRead(retval) : null
            };
          }
          stableSend('function_call', this.__ctx);
        } catch (_) {}
      }
    });
  } catch (_) {
    // ignore attach failure
  }
}

function hookModuleExports(moduleName) {
  if (!moduleName) return;
  if (hookedModules.has(moduleName)) return;

  const m = Process.findModuleByName(moduleName);
  if (!m) return;

  console.log(`[+] Hooking exports of ${moduleName} (${m.base}-${ptr(m.base).add(m.size)})`);
  hookedModules.add(moduleName);

  for (const exp of m.enumerateExports()) {
    if (exp.type !== 'function') continue;
    const name = exp.name || '';
    if (!matchesAny(name, config.includePatterns)) continue;
    if (!matchesNone(name, config.excludePatterns)) continue;
    hookExportFunction(moduleName, exp);
  }
}

/* ======================= dynamic loaders ======================= */

function hookDynamicLoaders() {
  const plat = Process.platform;

  const hookUnix = sym => {
    try {
      const addr = Module.findExportByName(null, sym);
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter(args) {
          this.libName = null;
          try { this.libName = args[0] ? Memory.readUtf8String(args[0]) : null; } catch (_) {}
        },
        onLeave() {
          if (!this.libName) return;
          const base = this.libName.split('/').pop();
          if (config.target_modules.length === 0 ||
              config.target_modules.some(t => base && base.indexOf(t) !== -1)) {
            setTimeout(() => hookModuleExports(base), 0);
          }
        }
      });
      console.log(`[+] Hooked loader ${sym}`);
    } catch (_) {}
  };

  const hookWin = (mod, sym, wide) => {
    try {
      const addr = Module.findExportByName(mod, sym);
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter(args) {
          this.name = null;
          try {
            this.name = wide ? Memory.readUtf16String(args[0]) : Memory.readCString(args[0]);
          } catch (_) {}
        },
        onLeave() {
          if (!this.name) return;
          const base = this.name.split('\\').pop();
          if (config.target_modules.length === 0 ||
              config.target_modules.some(t => base && base.toLowerCase().includes(t.toLowerCase()))) {
            setTimeout(() => hookModuleExports(base), 0);
          }
        }
      });
      console.log(`[+] Hooked loader ${sym}`);
    } catch (_) {}
  };

  if (plat === 'linux' || plat === 'android' || plat === 'darwin') {
    ['dlopen', 'dlmopen', 'android_dlopen_ext'].forEach(hookUnix);
  } else if (plat === 'windows') {
    hookWin('kernel32.dll', 'LoadLibraryA', false);
    hookWin('kernel32.dll', 'LoadLibraryW', true);
    hookWin('kernel32.dll', 'LoadLibraryExA', false);
    hookWin('kernel32.dll', 'LoadLibraryExW', true);
    try {
      const addr = Module.findExportByName('ntdll.dll', 'LdrLoadDll');
      if (addr) {
        Interceptor.attach(addr, {
          onEnter(args) {
            this.name = null;
            try {
              const usPtr = args[2];
              if (!usPtr.isNull()) {
                const us = usPtr.readPointer();            // UNICODE_STRING
                const length = us.add(Process.pointerSize).readU16();
                const buffer = us.add(Process.pointerSize * 2).readPointer();
                this.name = Memory.readUtf16String(buffer, length / 2);
              }
            } catch (_) {}
          },
          onLeave() { if (this.name) setTimeout(() => hookModuleExports(this.name.split('\\').pop()), 0); }
        });
        console.log('[+] Hooked loader LdrLoadDll');
      }
    } catch (_) {}
  }
}

/* ======================= keep-alive ======================= */

function installKeepAlive() {
  const plat = Process.platform;

  if (plat === 'linux' || plat === 'android') {
    try {
      const addr = DebugSymbol.fromName('__libc_start_main').address;
      Interceptor.attach(addr, {
        onLeave() { console.log('[+] main() returned; keeping process briefly alive...'); Thread.sleep(1); }
      });
      console.log('[+] Keep-alive via __libc_start_main installed.');
    } catch (e) {
      console.error(`[!] Keep-alive (__libc_start_main) failed: ${e.message}`);
    }
    ['exit', '_exit', 'abort'].forEach(sym => {
      try {
        const a = Module.findExportByName(null, sym);
        if (a) Interceptor.attach(a, { onEnter() { Thread.sleep(0.2); } });
      } catch (_) {}
    });
  } else if (plat === 'darwin') {
    try {
      const a = Module.findExportByName(null, 'exit');
      if (a) Interceptor.attach(a, { onEnter() { Thread.sleep(0.2); } });
      console.log('[+] Keep-alive via exit() installed.');
    } catch (e) {
      console.error(`[!] Keep-alive (exit) failed: ${e.message}`);
    }
  } else if (plat === 'windows') {
    try {
      const a = Module.findExportByName('kernel32.dll', 'ExitProcess');
      if (a) Interceptor.attach(a, { onEnter() { Thread.sleep(0.2); } });
      console.log('[+] Keep-alive via ExitProcess installed.');
    } catch (_) {}
    try {
      const a = Module.findExportByName('ntdll.dll', 'NtTerminateProcess');
      if (a) Interceptor.attach(a, { onEnter() { Thread.sleep(0.2); } });
      console.log('[+] Keep-alive via NtTerminateProcess installed.');
    } catch (_) {}
  }
}

/* ======================= OpenSSL EVP introspection ======================= */

function findCryptoModule() {
  return Process.findModuleByName('libcrypto.so.3') ||
         Process.findModuleByName('libcrypto.so.1.1') ||
         Process.findModuleByName('libcrypto.3.dylib') ||
         Process.findModuleByName('libcrypto.dylib') ||
         Process.findModuleByName('libcrypto-3-x64.dll') ||
         Process.findModuleByName('libcrypto-1_1-x64.dll') ||
         Process.findModuleByName('libeay32.dll') || null;
}
const CRYPTO = findCryptoModule();

function NF(name, ret, args) {
  try {
    const addr = Module.findExportByName(CRYPTO ? CRYPTO.name : null, name) || Module.findExportByName(null, name);
    return addr ? new NativeFunction(addr, ret, args) : null;
  } catch (_) { return null; }
}

const F = {
  EVP_CIPHER_CTX_cipher:          NF('EVP_CIPHER_CTX_cipher',        'pointer', ['pointer']),
  EVP_CIPHER_CTX_key_length:      NF('EVP_CIPHER_CTX_key_length',    'int',     ['pointer']),
  EVP_CIPHER_CTX_iv_length:       NF('EVP_CIPHER_CTX_iv_length',     'int',     ['pointer']),
  EVP_CIPHER_CTX_encrypting:      NF('EVP_CIPHER_CTX_encrypting',    'int',     ['pointer']),
  EVP_CIPHER_get0_name:           NF('EVP_CIPHER_get0_name',         'pointer', ['pointer']),
  EVP_CIPHER_get_block_size:      NF('EVP_CIPHER_get_block_size',    'int',     ['pointer']),
  EVP_CIPHER_get_key_length:      NF('EVP_CIPHER_get_key_length',    'int',     ['pointer']),
  EVP_CIPHER_get_iv_length:       NF('EVP_CIPHER_get_iv_length',     'int',     ['pointer']),
  EVP_CIPHER_CTX_ctrl:            NF('EVP_CIPHER_CTX_ctrl',          'int',     ['pointer','int','int','pointer']),
  EVP_CIPHER_CTX_get_cipher_data: NF('EVP_CIPHER_CTX_get_cipher_data','pointer',['pointer']),
};

function cstr(p){ try { return (p && !p.isNull()) ? Memory.readUtf8String(p) : null; } catch(_) { return null; } }

function decodeEvpCtx(ctxPtr){
  if (!ctxPtr || ctxPtr.isNull()) return null;
  let cipherPtr = null, cipherName = null, blockSize = -1, keyLen = -1, ivLen = -1, enc = -1;
  try { cipherPtr = F.EVP_CIPHER_CTX_cipher ? F.EVP_CIPHER_CTX_cipher(ctxPtr) : ptr(0); } catch(_) {}
  try { cipherName = (cipherPtr && F.EVP_CIPHER_get0_name) ? cstr(F.EVP_CIPHER_get0_name(cipherPtr)) : null; } catch(_) {}
  try { blockSize  = (cipherPtr && F.EVP_CIPHER_get_block_size) ? F.EVP_CIPHER_get_block_size(cipherPtr) : -1; } catch(_) {}
  try {
    keyLen = F.EVP_CIPHER_CTX_key_length ? F.EVP_CIPHER_CTX_key_length(ctxPtr) : -1;
    if (keyLen < 0 && cipherPtr && F.EVP_CIPHER_get_key_length) keyLen = F.EVP_CIPHER_get_key_length(cipherPtr);
  } catch(_) {}
  try {
    ivLen = F.EVP_CIPHER_CTX_iv_length ? F.EVP_CIPHER_CTX_iv_length(ctxPtr) : -1;
    if (ivLen < 0 && cipherPtr && F.EVP_CIPHER_get_iv_length) ivLen = F.EVP_CIPHER_get_iv_length(cipherPtr);
  } catch(_) {}
  try { enc = F.EVP_CIPHER_CTX_encrypting ? F.EVP_CIPHER_CTX_encrypting(ctxPtr) : -1; } catch(_) {}
  return {
    ctx_ptr: ctxPtr.toString(),
    cipher_name: cipherName,
    block_size: blockSize,
    key_len: keyLen,
    iv_len: ivLen,
    encrypting: enc
  };
}

function sampleKeyIv(typePtr, keyPtr, ivPtr, cap=64){
  let klen=-1, ivlen=-1, keyHex=null, ivHex=null;
  try { if (F.EVP_CIPHER_get_key_length && typePtr && !typePtr.isNull()) klen = F.EVP_CIPHER_get_key_length(typePtr); } catch(_){}
  try { if (F.EVP_CIPHER_get_iv_length  && typePtr && !typePtr.isNull()) ivlen = F.EVP_CIPHER_get_iv_length(typePtr); } catch(_){}
  if (klen > 0) keyHex = hexdumpMax(keyPtr, klen, cap);
  if (ivlen > 0) ivHex  = hexdumpMax(ivPtr,  ivlen, cap);
  return { key_len: klen, iv_len: ivlen, key_sample: keyHex, iv_sample: ivHex };
}

function installOpenSslIntrospection(){
  if (!CRYPTO) { console.log('[i] libcrypto not found; skip OpenSSL introspection.'); return; }

  const attachIf = (name, handler) => {
    try {
      const addr = Module.findExportByName(CRYPTO.name, name) || Module.findExportByName(null, name);
      if (!addr) return;
      Interceptor.attach(addr, handler);
      console.log(`[+] OpenSSL introspection attached: ${name}`);
    } catch(_) {}
  };

  // CipherInit (enc flag 포함)
  attachIf('EVP_CipherInit_ex', {
    onEnter(args) {
      const ctx=args[0], type=args[1], key=args[3], iv=args[4];
      let enc=-1; try { enc = args[5] ? args[5].toInt32() : -1; } catch(_) {}
      this.__decoded = {
        api:'EVP_CipherInit_ex',
        enc_flag: enc,
        evp_ctx: decodeEvpCtx(ctx),
        key_iv: sampleKeyIv(type,key,iv,128)
      };
    },
    onLeave(retval) {
      if (!this.__decoded) return;
      this.__decoded.ret = retval ? retval.toInt32() : 0;
      stableSend('function_call', { moduleName: CRYPTO.name, functionName: 'EVP_CipherInit_ex', decoded: this.__decoded });
    }
  });

  // Encrypt
  attachIf('EVP_EncryptInit_ex', {
    onEnter(args) {
      const ctx=args[0], type=args[1], key=args[3], iv=args[4];
      this.__decoded = { api:'EVP_EncryptInit_ex', evp_ctx: decodeEvpCtx(ctx), key_iv: sampleKeyIv(type,key,iv,128) };
    },
    onLeave(retval) {
      if (!this.__decoded) return;
      this.__decoded.ret = retval ? retval.toInt32() : 0;
      stableSend('function_call', { moduleName: CRYPTO.name, functionName: 'EVP_EncryptInit_ex', decoded: this.__decoded });
    }
  });

  attachIf('EVP_EncryptUpdate', {
    onEnter(args) {
      const ctx=args[0], out=args[1], outl=args[2], inp=args[3], inl=args[4].toInt32();
      this.__decoded = {
        api:'EVP_EncryptUpdate',
        evp_ctx: decodeEvpCtx(ctx),
        in_len: inl,
        in_sample: hexdumpMax(inp,inl,512),
        in_ascii: toAsciiPreview(inp,inl,128)
      };
      this.__out = { out, outl };
    },
    onLeave(retval) {
      if (!this.__decoded) return;
      let outlen=0, outHex=null;
      try { outlen = Memory.readS32(this.__out.outl); } catch(_) {}
      if (outlen > 0) outHex = hexdumpMax(this.__out.out, outlen, 512);
      Object.assign(this.__decoded, {
        ret: retval ? retval.toInt32() : 0,
        out_len: outlen,
        out_sample: outHex
      });
      stableSend('function_call', { moduleName: CRYPTO.name, functionName: 'EVP_EncryptUpdate', decoded: this.__decoded });
    }
  });

  attachIf('EVP_EncryptFinal_ex', {
    onEnter(args) { this.__final = { out: args[1], outl: args[2] }; },
    onLeave(retval) {
      let outlen=0, outHex=null;
      try { outlen = Memory.readS32(this.__final.outl); } catch(_) {}
      if (outlen > 0) outHex = hexdumpMax(this.__final.out, outlen, 512);
      stableSend('function_call', {
        moduleName: CRYPTO.name,
        functionName: 'EVP_EncryptFinal_ex',
        decoded: { api: 'EVP_EncryptFinal_ex', ret: retval ? retval.toInt32() : 0, out_len: outlen, out_sample: outHex }
      });
    }
  });

  // Decrypt
  attachIf('EVP_DecryptInit_ex', {
    onEnter(args) {
      const ctx=args[0], type=args[1], key=args[3], iv=args[4];
      this.__decoded = { api:'EVP_DecryptInit_ex', evp_ctx: decodeEvpCtx(ctx), key_iv: sampleKeyIv(type,key,iv,128) };
    },
    onLeave(retval) {
      if (!this.__decoded) return;
      this.__decoded.ret = retval ? retval.toInt32() : 0;
      stableSend('function_call', { moduleName: CRYPTO.name, functionName: 'EVP_DecryptInit_ex', decoded: this.__decoded });
    }
  });

  attachIf('EVP_DecryptUpdate', {
    onEnter(args) {
      const ctx=args[0], out=args[1], outl=args[2], inp=args[3], inl=args[4].toInt32();
      this.__decoded = {
        api:'EVP_DecryptUpdate',
        evp_ctx: decodeEvpCtx(ctx),
        in_len: inl,
        in_sample: hexdumpMax(inp,inl,512),
        in_ascii: toAsciiPreview(inp,inl,128)
      };
      this.__out = { out, outl };
    },
    onLeave(retval) {
      if (!this.__decoded) return;
      let outlen=0, outHex=null;
      try { outlen = Memory.readS32(this.__out.outl); } catch(_) {}
      if (outlen > 0) outHex = hexdumpMax(this.__out.out, outlen, 512);
      Object.assign(this.__decoded, {
        ret: retval ? retval.toInt32() : 0,
        out_len: outlen,
        out_sample: outHex
      });
      stableSend('function_call', { moduleName: CRYPTO.name, functionName: 'EVP_DecryptUpdate', decoded: this.__decoded });
    }
  });

  attachIf('EVP_DecryptFinal_ex', {
    onEnter(args) { this.__final = { out: args[1], outl: args[2] }; },
    onLeave(retval) {
      let outlen=0, outHex=null;
      try { outlen = Memory.readS32(this.__final.outl); } catch(_) {}
      if (outlen > 0) outHex = hexdumpMax(this.__final.out, outlen, 512);
      stableSend('function_call', {
        moduleName: CRYPTO.name,
        functionName: 'EVP_DecryptFinal_ex',
        decoded: { api: 'EVP_DecryptFinal_ex', ret: retval ? retval.toInt32() : 0, out_len: outlen, out_sample: outHex }
      });
    }
  });

  // Generic Cipher (알고리즘/방향 구분 없이 동작)
  attachIf('EVP_CipherUpdate', {
    onEnter(args) {
      const ctx=args[0], out=args[1], outl=args[2], inp=args[3], inl=args[4].toInt32();
      this.__decoded = {
        api:'EVP_CipherUpdate',
        evp_ctx: decodeEvpCtx(ctx),
        in_len: inl,
        in_sample: hexdumpMax(inp,inl,512),
        in_ascii: toAsciiPreview(inp,inl,128)
      };
      this.__out = { out, outl };
    },
    onLeave(retval) {
      if (!this.__decoded) return;
      let outlen=0, outHex=null;
      try { outlen = Memory.readS32(this.__out.outl); } catch(_) {}
      if (outlen > 0) outHex = hexdumpMax(this.__out.out, outlen, 512);
      Object.assign(this.__decoded, {
        ret: retval ? retval.toInt32() : 0,
        out_len: outlen,
        out_sample: outHex
      });
      stableSend('function_call', { moduleName: CRYPTO.name, functionName: 'EVP_CipherUpdate', decoded: this.__decoded });
    }
  });

  attachIf('EVP_CipherFinal_ex', {
    onEnter(args) { this.__final = { out: args[1], outl: args[2] }; },
    onLeave(retval) {
      let outlen=0, outHex=null;
      try { outlen = Memory.readS32(this.__final.outl); } catch(_) {}
      if (outlen > 0) outHex = hexdumpMax(this.__final.out, outlen, 512);
      stableSend('function_call', {
        moduleName: CRYPTO.name,
        functionName: 'EVP_CipherFinal_ex',
        decoded: { api: 'EVP_CipherFinal_ex', ret: retval ? retval.toInt32() : 0, out_len: outlen, out_sample: outHex }
      });
    }
  });
}

/* ======================= bootstrap ======================= */

rpc.exports.init = function (newConfig) {
  console.log('[+] Agent (v12) received configuration.');
  config = Object.assign({}, config, newConfig || {});
  startTracing();
};

function startTracing() {
  console.log('[+] Starting universal tracing...');
  installKeepAlive();

  const modulesToHook = [config.main_module, ...(config.target_modules || [])].filter(Boolean);
  console.log(`[+] Initial modules to hook: [${modulesToHook.join(', ')}]`);
  modulesToHook.forEach(hookModuleExports);

  if (config.hookDynamicLoads) hookDynamicLoaders();

  try { installOpenSslIntrospection(); } catch (e) { console.log('OpenSSL introspection error:', e.message); }

  console.log('[+] Hooks are active.');
}
