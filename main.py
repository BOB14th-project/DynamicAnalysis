import frida
import sys
import os
import json
import time
import platform
import subprocess
from pathlib import Path
from enum import Enum

class CryptoOrchestrator:
    def __init__(self, binary_path: Path, args: list[str]):
        print("✅ Orchestrator initialized.")
        self.target_binary_path = binary_path
        self.target_args = args
        self.target_pid = 0
        self.session = None
        self.script = None
        self.device = frida.get_local_device()
        self.captured_data = []

    def run_analysis(self, duration: int):
        try:
            if not self._spawn_and_attach(): return
            if not self._load_agent(): return
            self._start_monitoring(duration)
        except Exception as e:
            print(f"❌ An unexpected error occurred during analysis: {e}")
        finally:
            self._generate_report()
            self._cleanup()
            print("\n[✓] Analysis complete!")

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

    def _discover_shared_libraries(self, lib_substring: str) -> list[str]:
        if sys.platform != "linux":
            print(f"   -> Library discovery is skipped on non-Linux platform: {sys.platform}")
            return []
        print(f"   -> Discovering libraries containing '{lib_substring}'...")
        try:
            command = ["ldd", str(self.target_binary_path)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            found_libs = {line.strip().split()[0] for line in result.stdout.splitlines() if lib_substring in line}
            print(f"   -> Found: {list(found_libs)}")
            return list(found_libs)
        except FileNotFoundError:
            print("   -> 'ldd' command not found. Skipping.")
            return []
        except subprocess.CalledProcessError as e:
            print(f"   -> 'ldd' failed: {e}. Skipping.")
            return []

    def _load_agent(self) -> bool:
        agent_path = Path(__file__).resolve().parent / "agent" / "agent.js"
        if not agent_path.exists():
            print(f"❌ Agent not found at: {agent_path}")
            return False
        print(f"📦 Loading agent: {agent_path.name}")
        try:
            agent_code = agent_path.read_text(encoding='utf-8')
            self.script = self.session.create_script(agent_code)
            self.script.on('message', self._on_message)
            self.script.load()

            crypto_libs = self._discover_shared_libraries('libcrypto.so')
            print(f"   -> Initializing agent for {self.target_binary_path.name} and discovered libraries...")
            config = {
                'main_module': self.target_binary_path.name,
                'target_modules': crypto_libs,
                'dumpSize': 64
            }
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
            "metadata": {"version": "3.1-python-automated", "analysis_timestamp": int(time.time())},
            "static_info": {"platform": sys.platform, "architecture": platform.machine()},
            "dynamic_analysis": {"raw_captures": self.captured_data},
        }
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
            print("   -> Report saved successfully.")
        except IOError as e:
            print(f"❌ Failed to write report file: {e}")

    def _cleanup(self):
        print("🧹 Cleaning up resources...")
        try:
            if self.script: self.script.unload()
            if self.session and not self.session.is_detached:
                self.device.kill(self.target_pid)
                self.session.detach()
        except frida.InvalidOperationError:
             print("   -> Process was already terminated.")
        except Exception as e:
            print(f"⚠️ An error occurred during cleanup: {e}")

    def _on_message(self, message: dict, data):
        try:
            if message.get("type") == "send":
                payload = message.get("payload", {})
                self.captured_data.append(payload)
                func_name = payload.get("payload", {}).get("functionName", "unknown")
                module_name = payload.get("payload", {}).get("moduleName", "unknown")
                print(f"   -> [AGENT] Captured call to: {module_name}!{func_name}")
            elif message.get("type") == "error":
                print(f"\n❗️ AGENT ERROR: {message.get('description')}")
        except Exception as e:
            print(f"❌ CRITICAL ERROR in message handler: {e}")

    def _on_detached(self, reason: str):
        print(f"\n❗️ Detached from process (PID: {self.target_pid}). Reason: {reason}")

def main():
    print("=" * 60)
    print("      Crypto Dynamic Analysis Orchestrator (Automated)")
    print("=" * 60)
    if len(sys.argv) < 2:
        print(f"\nUsage: python {sys.argv[0]} <path_to_binary> [args...]")
        sys.exit(1)
    binary_path = Path(sys.argv[1])
    args = sys.argv[2:]
    if not binary_path.is_file() or not os.access(binary_path, os.X_OK):
        print(f"\nError: '{binary_path}' is not a valid executable file.")
        sys.exit(1)
    monitor_duration = int(os.getenv("CRYPTO_MONITOR_DURATION", 10))
    orchestrator = CryptoOrchestrator(binary_path, args)
    orchestrator.run_analysis(monitor_duration)

if __name__ == "__main__":
    main()