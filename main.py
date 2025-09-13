#!/usr/bin/env python3
import frida
import sys
import os
import json
import time
import platform
import subprocess
import magic
from pathlib import Path
from typing import List, Dict, Any, Optional

class CryptoOrchestrator:
    def __init__(self, binary_path: Path, args: List[str]):
        print("✅ Orchestrator initialized.")
        self.target_binary_path = binary_path
        self.target_args = args
        self.target_pid: int = 0
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.device = frida.get_local_device()
        self.captured_data: List[Dict[str, Any]] = []
        self.file_type = "UNKNOWN"

    def run_analysis(self, duration: int):
        try:
            # 1) Static identify
            self.file_type = self._identify_file_type()
            if self.file_type in ("UNSUPPORTED", "UNKNOWN"):
                print(f"❌ Analysis stopped: Unsupported file type detected.")
                return

            # 2) Dynamic
            if not self._spawn_and_attach():
                return
            if not self._load_agent():
                return
            self._start_monitoring(duration)

        except Exception as e:
            print(f"❌ An unexpected error occurred during analysis: {e}")
        finally:
            self._generate_report()
            self._cleanup()
            print("\n[✓] Analysis complete!")

    def _identify_file_type(self) -> str:
        """Perform basic static analysis to identify the target file type."""
        print(f"🔬 Performing static analysis on {self.target_binary_path.name}...")
        try:
            file_info = magic.from_file(str(self.target_binary_path)).lower()
            print(f"   -> Detected type: {file_info}")
            if "elf" in file_info and "executable" in file_info:
                return "ELF"
            elif "pe32" in file_info and "executable" in file_info:
                return "PE"
            elif "mach-o" in file_info and "executable" in file_info:
                return "MACH-O"
            elif "python script" in file_info:
                return "PYTHON"
            else:
                return "UNSUPPORTED"
        except Exception as e:
            print(f"❌ Could not identify file type: {e}")
            return "UNKNOWN"

    def _spawn_and_attach(self) -> bool:
        print(f"🚀 Spawning target: {self.target_binary_path}")
        try:
            self.target_pid = self.device.spawn([str(self.target_binary_path)] + self.target_args)
            print(f"   -> Process created with PID: {self.target_pid}")
            self.session = self.device.attach(self.target_pid)
            print("   -> Attached to process successfully.")
            self.session.on('detached', self._on_detached)
            return True
        except Exception as e:
            print(f"❌ Failed to spawn or attach: {e}")
            return False

    def _discover_shared_libraries(self, lib_substring: str) -> List[str]:
        """Best-effort: ldd output에서 대상 라이브러리 힌트를 뽑아냄(Linux). 실패시 빈 리스트."""
        if sys.platform != "linux":
            return []
        print(f"   -> Discovering libraries containing '{lib_substring}'...")
        try:
            command = ["ldd", str(self.target_binary_path)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            found_libs = set()
            for line in result.stdout.splitlines():
                line = line.strip()
                if lib_substring in line:
                    # e.g. "libcrypto.so.3 => /lib/x86_64-linux-gnu/libcrypto.so.3 (0x...)"
                    name = line.split()[0]
                    # 베이스네임만 사용
                    found_libs.add(Path(name).name)
            print(f"   -> Found: {list(found_libs)}")
            return list(found_libs)
        except Exception:
            return []

    def _load_agent(self) -> bool:
        """Selects and loads the appropriate agent based on file type."""
        agent_name = ""
        if self.file_type in ["ELF", "MACH-O", "PE"]:
            agent_name = "c_cpp_agent.js"
        else:
            print(f"❌ No suitable agent for file type '{self.file_type}'.")
            return False

        agent_path = Path(__file__).resolve().parent / "agent" / agent_name
        if not agent_path.exists():
            print(f"❌ Agent not found at: {agent_path}")
            return False

        print(f"📦 Loading agent: {agent_path.name}")
        try:
            agent_code = agent_path.read_text(encoding='utf-8')
            self.script = self.session.create_script(agent_code)
            self.script.on('message', self._on_message)
            self.script.load()

            # 대상 라이브러리 힌트 탐색(없어도 동적으로 후킹됨)
            crypto_libs = self._discover_shared_libraries('libcrypto.so')

            print(f"   -> Initializing agent for {self.target_binary_path.name}...")
            # v12 agent와 호환되는 설정
            config: Dict[str, Any] = {
                'main_module': self.target_binary_path.name,
                'target_modules': crypto_libs,       # []여도 hookDynamicLoads로 커버됨
                'dumpSize': int(os.getenv("CRYPTO_DUMP_SIZE", "128")),
                'maxArgs': int(os.getenv("CRYPTO_MAX_ARGS", "8")),
                'captureBacktrace': os.getenv("CRYPTO_BACKTRACE", "1") not in ("0", "false", "False"),
                'hookDynamicLoads': True,
                # 필요시 include/exclude를 명시적으로 넘겨 agent 기본값을 덮어쓸 수 있음
                # 'includePatterns': [...],
                # 'excludePatterns': ['_free$', '^CRYPTO_(malloc|zalloc|realloc|free)$', '^OPENSSL_(malloc|free|cleanse)$',
                #                     '^mem(?:cpy|set|move|cmp)$', '^bzero$', '^str.*$'],
                'signatureOverrides': {
                    # 노이즈 제거 및 시그니처 확정
                    'EVP_PBE_cleanup':   {'argc': 0, 'ret': 'void'},
                    'EVP_rc4_hmac_md5':  {'argc': 0, 'ret': 'pointer'},
                    'EVP_sha256':        {'argc': 0, 'ret': 'pointer'},
                    'EVP_aes_128_gcm':   {'argc': 0, 'ret': 'pointer'},

                    'OBJ_NAME_do_all':        {'argc': 3, 'ret': 'void'},
                    'OPENSSL_LH_doall_arg':   {'argc': 3, 'ret': 'void'},

                    # EVP Cipher/Encrypt/Decrypt 패밀리 고정
                    'EVP_CipherInit_ex':   {'argc': 6, 'ret': 'scalar'},
                    'EVP_CipherUpdate':    {'argc': 5, 'ret': 'scalar'},
                    'EVP_CipherFinal_ex':  {'argc': 3, 'ret': 'scalar'},

                    'EVP_EncryptInit_ex':  {'argc': 5, 'ret': 'scalar'},
                    'EVP_EncryptUpdate':   {'argc': 5, 'ret': 'scalar'},
                    'EVP_EncryptFinal_ex': {'argc': 3, 'ret': 'scalar'},

                    'EVP_DecryptInit_ex':  {'argc': 5, 'ret': 'scalar'},
                    'EVP_DecryptUpdate':   {'argc': 5, 'ret': 'scalar'},
                    'EVP_DecryptFinal_ex': {'argc': 3, 'ret': 'scalar'},
                }
            }

            # Agent init
            self.script.exports_sync.init(config)
            print("   -> Agent loaded and initialized successfully.")
            return True
        except Exception as e:
            print(f"❌ Failed to load or initialize agent: {e}")
            return False

    def _start_monitoring(self, duration: int):
        print(f"▶️ Resuming process and starting monitoring for {duration} seconds...")
        self.device.resume(self.target_pid)
        time.sleep(duration)
        print("⏹️ Monitoring time elapsed.")

    def _generate_report(self):
        output_filename = f"analysis_result_{self.target_binary_path.name}.json"
        print(f"💾 Saving results to {output_filename}...")
        report = {
            "metadata": {
                "version": "5.0-python-orchestrator",
                "agent_version": "v12",
                "analysis_timestamp": int(time.time()),
                "file_type": self.file_type
            },
            "static_info": {
                "platform": sys.platform,
                "architecture": platform.machine(),
                "python_version": platform.python_version()
            },
            "dynamic_analysis": {
                "count": len(self.captured_data),
                "raw_captures": self.captured_data
            },
        }
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print("   -> Report saved successfully.")
        except IOError as e:
            print(f"❌ Failed to write report file: {e}")

    def _cleanup(self):
        print("🧹 Cleaning up resources...")
        try:
            if self.script:
                try:
                    self.script.unload()
                except Exception:
                    pass
            if self.session and not self.session.is_detached:
                try:
                    self.device.kill(self.target_pid)
                except Exception:
                    pass
                try:
                    self.session.detach()
                except Exception:
                    pass
        except frida.InvalidOperationError:
            print("   -> Process was already terminated.")
        except Exception as e:
            print(f"⚠️ An error occurred during cleanup: {e}")

    def _on_message(self, message: dict, data):
        """Agent v12는 평평한(flat) 구조로 보냄: payload == {event, moduleName, functionName, ...}
        이전 버전(중첩 payload)도 겸용으로 처리."""
        try:
            mtype = message.get("type")
            if mtype != "send":
                if mtype == "error":
                    print(f"\n❗️ AGENT ERROR: {message.get('description')}")
                return

            raw = message.get("payload", {})

            # v12(flat): {"event": "...", "moduleName": "...", "functionName": "...", ...}
            if isinstance(raw, dict) and "event" in raw:
                event = raw.get("event", "unknown")
                data_obj = raw
            # 이전(중첩) 호환: {"type": "function_call", "payload": {...}}
            elif isinstance(raw, dict) and "payload" in raw and "type" in raw:
                event = raw.get("type", "unknown")
                data_obj = raw.get("payload") or {}
            else:
                event = "unknown"
                data_obj = raw if isinstance(raw, dict) else {"raw": raw}

            # 기록
            self.captured_data.append({"event": event, **data_obj})

            func_name = data_obj.get("functionName") or data_obj.get("name") or data_obj.get("symbol") or "unknown"
            module_name = data_obj.get("moduleName") or data_obj.get("module") or "unknown"
            print(f"   -> [AGENT:{event}] {module_name}!{func_name}")

            # 필요시 디버그 프리뷰
            if func_name == "unknown" and module_name == "unknown":
                try:
                    dbg = json.dumps(raw)[:300]
                    print(f"      [debug] raw payload preview: {dbg}...")
                except Exception:
                    pass

        except Exception as e:
            print(f"❌ CRITICAL ERROR in message handler: {e}")

    def _on_detached(self, reason: str):
        print(f"\n❗️ Detached from process (PID: {self.target_pid}). Reason: {reason}")

def main():
    print("=" * 60)
    print("      Crypto Dynamic Analysis Orchestrator (Dispatcher)")
    print("=" * 60)
    if len(sys.argv) < 2:
        print(f"\nUsage: python {sys.argv[0]} <path_to_binary> [args...]")
        sys.exit(1)

    binary_path = Path(sys.argv[1])
    args = sys.argv[2:]

    if not binary_path.is_file():
        print(f"\nError: '{binary_path}' is not a valid file.")
        sys.exit(1)

    monitor_duration = int(os.getenv("CRYPTO_MONITOR_DURATION", "10"))
    orchestrator = CryptoOrchestrator(binary_path, args)
    orchestrator.run_analysis(monitor_duration)

if __name__ == "__main__":
    main()
