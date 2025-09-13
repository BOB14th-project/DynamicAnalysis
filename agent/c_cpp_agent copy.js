/*
 * Advanced Generic Tracer (v9 - Universal & Resilient)
 * - Hooks ALL exported functions without a predefined list for maximum discovery.
 * - Uses a robust try/catch block within the hook to handle non-standard functions
 * without crashing, ensuring universal compatibility and stability.
 */

let config = { main_module: null, target_modules: [], dumpSize: 64 };

rpc.exports.init = function(newConfig) {
    console.log("[+] Agent (v9 - Universal) received configuration.");
    config = { ...config, ...newConfig };
    startTracing();
};

function safeRead(ptr) {
    if (!ptr || ptr.isNull() || ptr.toInt32() < 4096) return null;
    try {
        return { hex: hexdump(ptr, { length: config.dumpSize }), str: ptr.readUtf8String() };
    } catch (e) {
        return null;
    }
}

function startTracing() {
    // 1. Keep-alive hook
    console.log("[+] Setting up robust keep-alive hook...");
    try {
        const startMainAddr = DebugSymbol.fromName('__libc_start_main').address;
        Interceptor.attach(startMainAddr, {
            onLeave: function(retval) {
                console.log("\n[+] 'main' has returned. Keeping process alive for analysis...");
                Thread.sleep(1000);
            }
        });
        console.log("[+] Keep-alive hook is set.");
    } catch (e) {
        console.error(`[!] Could not set keep-alive hook: ${e.message}.`);
    }

    // 2. Universal Hooking Logic
    const modulesToHook = [config.main_module, ...config.target_modules];
    console.log(`[+] Applying universal hook to modules: [${modulesToHook.join(', ')}]`);

    modulesToHook.forEach(moduleName => {
        const targetModule = Process.findModuleByName(moduleName);
        if (!targetModule) return;

        console.log(`[+] Scanning and hooking all exports of ${moduleName}...`);
        targetModule.enumerateExports().forEach(exp => {
            if (exp.type !== 'function') return;

            try {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        // --- UNIVERSAL HOOK CORE ---
                        // Use a try/catch block to gracefully handle functions
                        // with arguments that cannot be automatically parsed.
                        try {
                            // Best effort: Try to parse arguments in detail.
                            this.callContext = {
                                moduleName: moduleName,
                                functionName: exp.name,
                                args: Array.from(args).map((arg, i) => ({
                                    index: i, value: arg.toString(), memory: safeRead(arg)
                                }))
                            };
                        } catch (e) {
                            // Fallback: If parsing fails, record the call without args.
                            this.callContext = {
                                moduleName: moduleName,
                                functionName: exp.name,
                                error: `Could not parse arguments: ${e.message}`
                            };
                        }
                    },
                    onLeave: function(retval) {
                        if (!this.callContext) return;

                        // If arg parsing failed, just send the basic discovery info.
                        if (this.callContext.error) {
                            send({ type: 'function_call', payload: this.callContext });
                            return;
                        }

                        // Otherwise, add the return value and send the full details.
                        this.callContext.returnValue = { value: retval.toString(), memory: safeRead(retval) };
                        send({ type: 'function_call', payload: this.callContext });
                    }
                });
            } catch (e) {
                // This catches errors if Interceptor.attach itself fails on a function.
            }
        });
    });
    console.log("[+] All universal hooks are active.");
}