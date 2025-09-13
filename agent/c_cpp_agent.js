/*
 * Advanced Generic Tracer (v10 - Universal & Resilient)
 * - Hooks ALL exported functions (optionally filtered) with strong crash-guards.
 * - Handles late-loaded libraries by hooking loader APIs (optional).
 * - Cross-platform keep-alive hints for smoother analysis sessions.
 */

'use strict';

let config = {
  main_module: null,          // "a.out" or "target.exe"
  target_modules: [],         // ["libcrypto.so", "libssl.so"...] - hints only
  dumpSize: 64,               // bytes to dump around pointers
  maxArgs: 8,                 // try to capture up to N args
  captureBacktrace: false,    // include backtraces
  hookDynamicLoads: true,     // hook dlopen/LoadLibrary family to catch late loads
  includePatterns: [
    '^EVP_', '^RSA_', '^EC_', '^ED25519', '^X25519', '^BN_', '^DH_', '^DSA_',
    '^HMAC_', '^CMAC_', 'HKDF', 'PBKDF2', '^RAND_',
    '^AES_', '^ChaCha20', '^Poly1305',
    '^SHA(1|224|256|384|512)$', '^MD(4|5)$',
    '^SSL_', '^TLS_'
  ],        // e.g., ["^RSA_", "^EVP_", "AES_"]
  excludePatterns: [
    '^CRYPTO_(malloc|zalloc|realloc|free)$', '^OPENSSL_(malloc|free)$',
    '^mem(cpy|set|move|cmp)$', '^bzero$', '^str.*$'
  ],        // e.g., ["^_ZN.*"] C++ mangled flood guard
};

const hookedModules = new Set();           // module.name
const hookedFunctions = new Set();         // `${module}!${symbol}`
const pendingModules = new Set();          // queue if needed

rpc.exports.init = function (newConfig) {
  console.log("[+] Agent (v10) received configuration.");
  config = Object.assign({}, config, newConfig || {});
  startTracing();
};

/* ---------- utils ---------- */

function matchesAny(name, patterns) {
  if (!patterns || patterns.length === 0) return true; // no filter -> allow all
  return patterns.some(p => {
    try { return new RegExp(p).test(name); }
    catch { return false; }
  });
}

function matchesNone(name, patterns) {
  if (!patterns || patterns.length === 0) return true;
  return !patterns.some(p => {
    try { return new RegExp(p).test(name); }
    catch { return false; }
  });
}

function stableSend(kind, payload) {
  try {
    send({ type: kind, payload: payload });
  } catch (_) {
    // swallow
  }
}

function safeHexdump(ptr, length) {
  try { return hexdump(ptr, { length }); } catch (_) { return null; }
}

function safeReadUtf8(ptr) {
  try { return Memory.readUtf8String(ptr); } catch (_) { return null; }
}

function safeRead(ptr) {
  try {
    if (!ptr || ptr.isNull()) return null;
    const len = Math.max(0, Math.min(config.dumpSize || 64, 4096));
    return {
      hex: safeHexdump(ptr, len),
      str: safeReadUtf8(ptr),
    };
  } catch (_) {
    return null;
  }
}

function tryBacktrace(ctx) {
  if (!config.captureBacktrace) return null;
  try {
    const frames = Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(addr => DebugSymbol.fromAddress(addr).toString());
    return frames;
  } catch (_) {
    return null;
  }
}

/* ---------- core hooking ---------- */

function hookExportFunction(moduleName, exp) {
  const key = `${moduleName}!${exp.name}`;
  if (hookedFunctions.has(key)) return;
  hookedFunctions.add(key);

  try {
    Interceptor.attach(exp.address, {
      onEnter(args) {
        this.__ctx = null;
        try {
          const argList = [];
          for (let i = 0; i < (config.maxArgs || 8); i++) {
            const a = args[i];
            if (a === undefined) break;
            argList.push({
              index: i,
              value: a ? a.toString() : "undefined",
              memory: a ? safeRead(a) : null
            });
          }

          this.__ctx = {
            moduleName,
            functionName: exp.name,
            args: argList,
            backtrace: tryBacktrace(this.context)
          };
        } catch (e) {
          this.__ctx = {
            moduleName,
            functionName: exp.name,
            error: `arg-parse: ${e.message}`
          };
        }
      },
      onLeave(retval) {
        if (!this.__ctx) return;
        try {
          if (!this.__ctx.error) {
            this.__ctx.returnValue = {
              value: retval ? retval.toString() : "null",
              memory: retval ? safeRead(retval) : null
            };
          }
          stableSend('function_call', this.__ctx);
        } catch (_) {
          // swallow
        }
      }
    });
  } catch (_) {
    // Interceptor.attach may fail on some symbols; ignore
  }
}

function hookModuleExports(moduleName) {
  if (!moduleName) return;
  if (hookedModules.has(moduleName)) return;

  const m = Process.findModuleByName(moduleName);
  if (!m) return;

  console.log(`[+] Hooking exports of ${moduleName} (${m.base}-${ptr(m.base).add(m.size)})`);
  hookedModules.add(moduleName);

  const exps = m.enumerateExports();
  for (const exp of exps) {
    if (exp.type !== 'function') continue;
    const name = exp.name || '';
    if (!matchesAny(name, config.includePatterns)) continue;
    if (!matchesNone(name, config.excludePatterns)) continue;
    hookExportFunction(moduleName, exp);
  }
}

/* ---------- dynamic load support ---------- */

function hookDynamicLoaders() {
  const plat = Process.platform;

  // UNIX-ish: dlopen variants
  const tryHook = (mod, sym) => {
    try {
      const addr = Module.findExportByName(mod, sym);
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter(args) {
          this.libName = null;
          try {
            // dlopen(const char *filename, int flags)
            this.libName = args[0] ? Memory.readUtf8String(args[0]) : null;
          } catch (_) {}
        },
        onLeave(retval) {
          if (!this.libName) return;
          // 이름이 전체 경로나 베이스네임일 수 있음
          const base = this.libName.split('/').pop();
          // 타겟 리스트가 비어있으면 모든 모듈, 아니면 매칭되는 것만
          if (config.target_modules.length === 0 ||
              config.target_modules.some(t => base && base.indexOf(t) !== -1)) {
            // 약간 지연 후 후킹(심볼 준비 시간)
            setTimeout(() => hookModuleExports(base), 0);
          }
        }
      });
      console.log(`[+] Hooked loader ${sym}`);
    } catch (_) {}
  };

  if (plat === 'linux' || plat === 'android' || plat === 'darwin') {
    tryHook(null, 'dlopen');
    tryHook(null, 'dlmopen');           // glibc
    tryHook(null, 'android_dlopen_ext'); // Android
  }

  // Windows: LoadLibrary* / LdrLoadDll
  if (plat === 'windows') {
    const hookW = (mod, sym) => {
      try {
        const addr = Module.findExportByName(mod, sym);
        if (!addr) return;
        Interceptor.attach(addr, {
          onEnter(args) {
            this.name = null;
            try {
              // LoadLibraryA/LW: arg0 is LPCSTR/LPCWSTR
              if (sym.endsWith('A')) this.name = Memory.readCString(args[0]);
              else if (sym.endsWith('W')) this.name = Memory.readUtf16String(args[0]);
            } catch (_) {}
          },
          onLeave(retval) {
            if (!this.name) return;
            const base = this.name.split('\\').pop();
            if (config.target_modules.length === 0 ||
                config.target_modules.some(t => base && base.toLowerCase().indexOf(t.toLowerCase()) !== -1)) {
              setTimeout(() => hookModuleExports(base), 0);
            }
          }
        });
        console.log(`[+] Hooked loader ${sym}`);
      } catch (_) {}
    };
    hookW('kernel32.dll', 'LoadLibraryA');
    hookW('kernel32.dll', 'LoadLibraryW');
    hookW('kernel32.dll', 'LoadLibraryExA');
    hookW('kernel32.dll', 'LoadLibraryExW');

    // Native loader: ntdll!LdrLoadDll
    try {
      const addr = Module.findExportByName('ntdll.dll', 'LdrLoadDll');
      if (addr) {
        Interceptor.attach(addr, {
          onEnter(args) {
            this.name = null;
            try {
              // UNICODE_STRING **ModuleFileName // args[2]
              const usPtr = args[2];
              if (!usPtr.isNull()) {
                const us = usPtr.readPointer(); // UNICODE_STRING
                const length = us.add(Process.pointerSize).readU16(); // Length
                const buffer = us.add(Process.pointerSize * 2).readPointer();
                this.name = Memory.readUtf16String(buffer, length / 2);
              }
            } catch (_) {}
          },
          onLeave(retval) {
            if (!this.name) return;
            const base = this.name.split('\\').pop();
            setTimeout(() => hookModuleExports(base), 0);
          }
        });
        console.log("[+] Hooked loader LdrLoadDll");
      }
    } catch (_) {}
  }
}

/* ---------- keep-alive helpers ---------- */

function installKeepAlive() {
  const plat = Process.platform;

  // Linux/Android: __libc_start_main onLeave
  if (plat === 'linux' || plat === 'android') {
    try {
      const addr = DebugSymbol.fromName('__libc_start_main').address;
      Interceptor.attach(addr, {
        onLeave() {
          console.log("[+] main() returned; keeping process briefly alive...");
          Thread.sleep(1);
        }
      });
      console.log("[+] Keep-alive via __libc_start_main installed.");
    } catch (e) {
      console.error(`[!] Keep-alive (__libc_start_main) failed: ${e.message}`);
    }

    // Also watch exit/_exit (best-effort)
    ['exit', '_exit', 'abort'].forEach(sym => {
      try {
        const addr = Module.findExportByName(null, sym);
        if (addr) {
          Interceptor.attach(addr, {
            onEnter() { console.log(`[+] ${sym} called; delaying a tick...`); Thread.sleep(0.2); }
          });
        }
      } catch (_) {}
    });
  }

  // macOS: libSystem `exit`
  if (plat === 'darwin') {
    try {
      const addr = Module.findExportByName(null, 'exit');
      if (addr) {
        Interceptor.attach(addr, {
          onEnter() { console.log("[+] exit() called; delaying a tick..."); Thread.sleep(0.2); }
        });
        console.log("[+] Keep-alive via exit() installed.");
      }
    } catch (e) {
      console.error(`[!] Keep-alive (exit) failed: ${e.message}`);
    }
  }

  // Windows: ExitProcess / NtTerminateProcess
  if (plat === 'windows') {
    ['ExitProcess'].forEach(sym => {
      try {
        const addr = Module.findExportByName('kernel32.dll', sym);
        if (addr) {
          Interceptor.attach(addr, {
            onEnter() { console.log(`[+] ${sym} called; delaying a tick...`); Thread.sleep(0.2); }
          });
          console.log(`[+] Keep-alive via ${sym} installed.`);
        }
      } catch (_) {}
    });
    try {
      const nt = Module.findExportByName('ntdll.dll', 'NtTerminateProcess');
      if (nt) {
        Interceptor.attach(nt, {
          onEnter() { console.log("[+] NtTerminateProcess called; delaying a tick..."); Thread.sleep(0.2); }
        });
        console.log("[+] Keep-alive via NtTerminateProcess installed.");
      }
    } catch (_) {}
  }
}

/* ---------- bootstrap ---------- */

function startTracing() {
  console.log("[+] Starting universal tracing...");

  // keep-alive helpers
  installKeepAlive();

  // initial set: main + hints
  const modulesToHook = [config.main_module, ...(config.target_modules || [])]
    .filter(Boolean);

  console.log(`[+] Initial modules to hook: [${modulesToHook.join(', ')}]`);
  modulesToHook.forEach(hookModuleExports);

  // dynamic loading support
  if (config.hookDynamicLoads) {
    hookDynamicLoaders();
  }

  console.log("[+] Hooks are active.");
}
