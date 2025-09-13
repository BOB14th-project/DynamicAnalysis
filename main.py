import frida
import sys
import os
import json
import time
import platform
import subprocess
import magic  # <-- New import
from pathlib import Path

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
        self.file_type = "UNKNOWN"

    def run_analysis(self, duration: int):
        try:
            # 1. Perform initial static analysis to identify the file.
            self.file_type = self._identify_file_type()
            if self.file_type == "UNSUPPORTED" or self.file_type == "UNKNOWN":
                print(f"❌ Analysis stopped: Unsupported file type detected.")
                return

            # 2. Proceed with dynamic analysis.
            if not self._spawn_and_attach(): return
            if not self._load_agent(): return
            self._start_monitoring(duration)

        except Exception as e:
            print(f"❌ An unexpected error occurred during analysis: {e}")
        finally:
            self._generate_report()
            self._cleanup()
            print("\n[✓] Analysis complete!")

    def _identify_file_type(self) -> str:
        """Performs basic static analysis to identify the target file type."""
        print(f"🔬 Performing static analysis on {self.target_binary_path.name}...")
        try:
            # Use python-magic to identify the file type from its contents (magic numbers).
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
        # ... (This method remains unchanged)
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
        # ... (This method remains unchanged)
        if sys.platform != "linux":
            return []
        print(f"   -> Discovering libraries containing '{lib_substring}'...")
        try:
            command = ["ldd", str(self.target_binary_path)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            found_libs = {line.strip().split()[0] for line in result.stdout.splitlines() if lib_substring in line}
            print(f"   -> Found: {list(found_libs)}")
            return list(found_libs)
        except Exception:
            return []

    def _load_agent(self) -> bool:
        """Selects and loads the appropriate agent based on file type."""
        # --- NEW DISPATCHER LOGIC ---
        agent_name = ""
        if self.file_type in ["ELF", "MACH-O", "PE"]:
            agent_name = "c_cpp_agent.js"
        # Add future agents here
        # elif self.file_type == "PYTHON":
        #     agent_name = "python_agent.js" 
        else:
            # This case should be caught earlier, but as a safeguard:
            print(f"❌ No suitable agent for file type '{self.file_type}'.")
            return False
        
        agent_path = Path(__file__).resolve().parent / "agent" / agent_name
        if not agent_path.exists():
            print(f"❌ Agent not found at: {agent_path}")
            return False
        # --- END OF DISPATCHER LOGIC ---

        print(f"📦 Loading agent: {agent_path.name}")
        try:
            agent_code = agent_path.read_text(encoding='utf-8')
            self.script = self.session.create_script(agent_code)
            self.script.on('message', self._on_message)
            self.script.load()

            crypto_libs = self._discover_shared_libraries('libcrypto.so')
            print(f"   -> Initializing agent for {self.target_binary_path.name}...")
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

    # ... (The rest of the methods: _start_monitoring, _generate_report, _cleanup, _on_message, _on_detached remain unchanged) ...
    def _start_monitoring(self, duration: int):
        print(f"▶️ Resuming process and starting monitoring for {duration} seconds...")
        self.device.resume(self.target_pid)
        time.sleep(duration)
        print("⏹️ Monitoring time elapsed.")

    def _generate_report(self):
        output_filename = f"analysis_result_{self.target_binary_path.name}.json"
        print(f"💾 Saving results to {output_filename}...")
        report = {
            "metadata": {"version": "4.0-python-dispatcher", "analysis_timestamp": int(time.time()), "file_type": self.file_type},
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
                call_details = payload.get("payload", {})
                func_name = call_details.get("functionName", "unknown")
                module_name = call_details.get("moduleName", "unknown")
                if 'error' in call_details:
                    print(f"   -> [AGENT] Discovered call to: {module_name}!{func_name} (args failed to parse)")
                else:
                    print(f"   -> [AGENT] Captured DETAILED call to: {module_name}!{func_name}")
            elif message.get("type") == "error":
                print(f"\n❗️ AGENT ERROR: {message.get('description')}")
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
    monitor_duration = int(os.getenv("CRYPTO_MONITOR_DURATION", 10))
    orchestrator = CryptoOrchestrator(binary_path, args)
    orchestrator.run_analysis(monitor_duration)

if __name__ == "__main__":
    main()