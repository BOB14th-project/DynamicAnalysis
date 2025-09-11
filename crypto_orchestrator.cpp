// crypto_orchestrator.cpp 개선 버전
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <chrono>
#include <thread>
#include <set>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <json/json.h>
#include "frida-core/frida-core.h"
#include "crypto_library_types.h"

class CryptoOrchestrator {
private:
    FridaDeviceManager* device_manager;
    FridaDevice* device;
    FridaSession* session;
    std::vector<FridaScript*> active_scripts;
    std::vector<Json::Value> captured_data;
    static_analysis_result_t static_result;
    pid_t child_pid;  // 실행한 자식 프로세스 PID
    
public:
    CryptoOrchestrator() : device_manager(nullptr), device(nullptr), 
                          session(nullptr), child_pid(0) {
        initializeFrida();
    }
    
    ~CryptoOrchestrator() {
        cleanup();
    }
    
private:
    // 정적 분석 수행 (하드코딩된 버전)
    void performStaticAnalysis(const std::string& binary_path) {
        std::cout << "[+] 정적 분석 수행 중: " << binary_path << std::endl;
        
        // 기본값으로 초기화
        static_result.library_count = 0;
        static_result.binary_path = binary_path.c_str();
        static_result.platform = "linux";
        static_result.architecture = "x64";
        
        // 바이너리 이름에 따른 하드코딩된 라이브러리 탐지
        if (binary_path.find("aes") != std::string::npos || 
            binary_path.find("crypto") != std::string::npos ||
            binary_path.find("ssl") != std::string::npos) {
            // 암호화 관련 바이너리라면 OpenSSL 가정
            static_result.detected_libraries[static_result.library_count++] = CRYPTO_LIB_OPENSSL;
            std::cout << "  [탐지] OpenSSL (하드코딩)" << std::endl;
        } else {
            // 일반적인 경우 기본 라이브러리들 추가
            static_result.detected_libraries[static_result.library_count++] = CRYPTO_LIB_OPENSSL;
            std::cout << "  [탐지] OpenSSL (기본값)" << std::endl;
        }
        
        // 주요 라이브러리 선택
        if (static_result.library_count > 0) {
            static_result.primary_library = static_result.detected_libraries[0];
        } else {
            std::cout << "  [경고] 암호화 라이브러리를 탐지하지 못했습니다." << std::endl;
            std::cout << "  [정보] 런타임에 동적 로딩될 수 있습니다." << std::endl;
        }
        
        static_result.binary_path = binary_path.c_str();
        static_result.platform = "linux";
        static_result.architecture = "x64";
    }
    
    void initializeFrida() {
        std::cout << "[+] Frida 초기화 중..." << std::endl;
        
        frida_init();
        
        device_manager = frida_device_manager_new();
        
        GError* error = nullptr;
        device = frida_device_manager_get_device_by_type_sync(
            device_manager, 
            FRIDA_DEVICE_TYPE_LOCAL, 
            5000,
            nullptr, 
            &error
        );
        
        if (error) {
            std::cerr << "[-] Frida 디바이스 획득 실패: " << error->message << std::endl;
            g_error_free(error);
            throw std::runtime_error("Frida 초기화 실패");
        }
        
        std::cout << "[+] Frida 디바이스 연결 완료" << std::endl;
    }
    
    std::string loadAgentFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "[-] 에이전트 파일을 열 수 없음: " << filename << std::endl;
            return "";
        }
        
        std::string code((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
        return code;
    }
    
    std::vector<std::string> selectAgentFiles() {
        std::vector<std::string> agent_files;
        
        // 기본 에이전트 (존재하는 파일 사용)
        agent_files.push_back("agent/c_cpp_crypto_agent.js");
        
        // 탐지된 라이브러리에 따라 특화 에이전트 추가
        for (size_t i = 0; i < static_result.library_count; i++) {
            crypto_library_type_t lib = static_result.detected_libraries[i];
            
            if (lib == CRYPTO_LIB_OPENSSL || 
                lib == CRYPTO_LIB_LIBSSL || 
                lib == CRYPTO_LIB_LIBCRYPTO) {
                agent_files.push_back("agent/c_cpp/openssl_agent.js");
            } else if (lib == CRYPTO_LIB_MBEDTLS) {
                agent_files.push_back("agent/c_cpp/mbedTLS_agent.js");
            } else if (lib == CRYPTO_LIB_LIBSODIUM) {
                agent_files.push_back("agent/c_cpp/libsodium_agent.js");
            } else if (lib == CRYPTO_LIB_GNUTLS) {
                agent_files.push_back("agent/c_cpp/gnutls_agent.js");
            }
        }
        
        // 중복 제거
        std::set<std::string> unique_files(agent_files.begin(), agent_files.end());
        return std::vector<std::string>(unique_files.begin(), unique_files.end());
    }
    
    static void messageHandler(FridaScript* script, const gchar* message, 
                              GBytes* data, gpointer user_data) {
        (void)script; // 사용하지 않는 매개변수 억제
        (void)data;   // 사용하지 않는 매개변수 억제
        
        CryptoOrchestrator* orchestrator = static_cast<CryptoOrchestrator*>(user_data);
        
        Json::Value root;
        Json::Reader reader;
        
        if (reader.parse(message, root)) {
            root["received_at"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();
            
            orchestrator->captured_data.push_back(root);
            
            std::string agent_type = root.get("agent", "unknown").asString();
            std::string category = root.get("category", "unknown").asString();
            
            std::cout << "[" << agent_type << "] " << category;
            if (root.isMember("data")) {
                Json::Value data = root["data"];
                if (data.isMember("function")) {
                    std::cout << " - " << data["function"].asString();
                }
            }
            std::cout << std::endl;
        } else {
            std::cout << "[FRIDA] " << message << std::endl;
        }
    }
    
public:
    // 새로운 메서드: 프로세스 실행 및 자동 attach
    pid_t launchAndAttach(const std::string& binary_path, 
                          const std::vector<std::string>& args = {}) {
        std::cout << "[+] 타겟 프로세스 실행 중: " << binary_path << std::endl;
        
        // 먼저 정적 분석 수행
        performStaticAnalysis(binary_path);
        
        // fork()로 자식 프로세스 생성
        child_pid = fork();
        
        if (child_pid == -1) {
            std::cerr << "[-] fork() 실패" << std::endl;
            return -1;
        }
        
        if (child_pid == 0) {
            // 자식 프로세스: 타겟 바이너리 실행
            
            // 디버깅을 위해 잠시 대기 (Frida attach를 위함)
            usleep(100000); // 100ms
            
            // 인자 준비
            std::vector<char*> exec_args;
            exec_args.push_back(const_cast<char*>(binary_path.c_str()));
            for (const auto& arg : args) {
                exec_args.push_back(const_cast<char*>(arg.c_str()));
            }
            exec_args.push_back(nullptr);
            
            // 실행
            execvp(binary_path.c_str(), exec_args.data());
            
            // execvp가 실패한 경우에만 여기 도달
            std::cerr << "[-] 실행 실패: " << binary_path << std::endl;
            exit(1);
        }
        
        // 부모 프로세스: Frida로 attach
        std::cout << "[+] 자식 프로세스 PID: " << child_pid << std::endl;
        
        // 프로세스가 시작될 때까지 잠시 대기
        usleep(200000); // 200ms
        
        // Frida attach
        if (!attachToProcess(child_pid)) {
            // attach 실패시 자식 프로세스 종료
            kill(child_pid, SIGTERM);
            return -1;
        }
        
        return child_pid;
    }
    
    // 기존 attachToProcess 메서드는 그대로 유지
    bool attachToProcess(guint pid) {
        std::cout << "[+] 프로세스 " << pid << "에 연결 중..." << std::endl;
        
        GError* error = nullptr;
        session = frida_device_attach_sync(device, pid, nullptr, nullptr, &error);
        
        if (error) {
            std::cerr << "[-] 프로세스 연결 실패: " << error->message << std::endl;
            g_error_free(error);
            return false;
        }
        
        std::cout << "[+] 프로세스 연결 완료" << std::endl;
        return true;
    }
    
    bool loadAllAgents() {
        std::cout << "[+] 에이전트 로딩 시작..." << std::endl;
        
        auto agent_files = selectAgentFiles();
        
        for (const auto& filename : agent_files) {
            std::string agent_code = loadAgentFromFile(filename);
            if (agent_code.empty()) {
                std::cerr << "[-] 에이전트 코드 로딩 실패: " << filename << std::endl;
                continue;
            }
            
            GError* error = nullptr;
            FridaScript* script = frida_session_create_script_sync(
                session, 
                agent_code.c_str(), 
                nullptr, 
                nullptr, 
                &error
            );
            
            if (error) {
                std::cerr << "[-] 스크립트 생성 실패: " << error->message << std::endl;
                g_error_free(error);
                continue;
            }
            
            g_signal_connect(script, "message", G_CALLBACK(messageHandler), this);
            
            frida_script_load_sync(script, nullptr, &error);
            if (error) {
                std::cerr << "[-] 스크립트 로딩 실패: " << error->message << std::endl;
                g_error_free(error);
                g_object_unref(script);
                continue;
            }
            
            active_scripts.push_back(script);
            std::cout << "[+] 에이전트 로딩 완료: " << filename << std::endl;
        }
        
        std::cout << "[+] 총 " << active_scripts.size() << "개 에이전트 로딩 완료" << std::endl;
        return !active_scripts.empty();
    }
    
    void startMonitoring(int duration_seconds = 60) {
        std::cout << "[+] 암호화 모니터링 시작 (" << duration_seconds << "초)" << std::endl;
        
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::seconds(duration_seconds);
        
        bool process_alive = true;
        
        while (std::chrono::steady_clock::now() < end_time && process_alive) {
            g_main_context_iteration(g_main_context_default(), FALSE);
            
            // 자식 프로세스 상태 확인
            if (child_pid > 0) {
                int status;
                pid_t result = waitpid(child_pid, &status, WNOHANG);
                if (result == child_pid) {
                    std::cout << "[+] 타겟 프로세스가 종료되었습니다." << std::endl;
                    process_alive = false;
                    break;
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // 모니터링 종료 후 자식 프로세스가 아직 실행 중이면 종료
        if (process_alive && child_pid > 0) {
            std::cout << "[+] 모니터링 시간 만료, 프로세스 종료 중..." << std::endl;
            kill(child_pid, SIGTERM);
            
            // 프로세스가 종료될 때까지 대기 (최대 5초)
            int wait_count = 0;
            while (wait_count < 50) {
                int status;
                if (waitpid(child_pid, &status, WNOHANG) == child_pid) {
                    break;
                }
                usleep(100000); // 100ms
                wait_count++;
            }
            
            // 그래도 종료되지 않으면 강제 종료
            if (wait_count >= 50) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, nullptr, 0);
            }
        }
        
        std::cout << "[+] 모니터링 완료" << std::endl;
    }
    
    void saveResults(const std::string& output_file = "crypto_analysis_results.json") {
        std::cout << "[+] 결과 저장 중..." << std::endl;
        
        Json::Value final_result;
        
        // 정적 분석 결과
        final_result["static_analysis"]["binary_path"] = static_result.binary_path;
        final_result["static_analysis"]["detected_libraries"] = Json::Value(Json::arrayValue);
        for (size_t i = 0; i < static_result.library_count; i++) {
            const char* lib_name = crypto_library_type_to_string(static_result.detected_libraries[i]);
            final_result["static_analysis"]["detected_libraries"].append(lib_name);
        }
        
        // 동적 분석 결과
        final_result["dynamic_analysis"]["captured_operations"] = Json::Value(Json::arrayValue);
        for (const auto& data : captured_data) {
            final_result["dynamic_analysis"]["captured_operations"].append(data);
        }
        
        // 요약
        final_result["summary"]["total_operations"] = static_cast<int>(captured_data.size());
        final_result["summary"]["agents_loaded"] = static_cast<int>(active_scripts.size());
        final_result["summary"]["analysis_timestamp"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        // 암호화 알고리즘 통계
        std::map<std::string, int> algo_stats;
        for (const auto& op : captured_data) {
            if (op.isMember("data") && op["data"].isMember("algorithm")) {
                algo_stats[op["data"]["algorithm"].asString()]++;
            }
        }
        
        final_result["summary"]["algorithm_usage"] = Json::Value(Json::objectValue);
        for (const auto& pair : algo_stats) {
            final_result["summary"]["algorithm_usage"][pair.first] = pair.second;
        }
        
        // 파일 저장
        std::ofstream file(output_file);
        if (file.is_open()) {
            Json::StreamWriterBuilder builder;
            builder["indentation"] = "  ";
            std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
            writer->write(final_result, &file);
            file.close();
            
            std::cout << "[+] 결과 저장 완료: " << output_file << std::endl;
            std::cout << "[+] 총 캡처된 작업: " << captured_data.size() << "개" << std::endl;
        } else {
            std::cerr << "[-] 파일 저장 실패: " << output_file << std::endl;
        }
    }
    
private:
    void cleanup() {
        std::cout << "[+] 정리 작업 중..." << std::endl;
        
        for (auto script : active_scripts) {
            frida_script_unload_sync(script, nullptr, nullptr);
            g_object_unref(script);
        }
        active_scripts.clear();
        
        if (session) {
            frida_session_detach_sync(session, nullptr, nullptr);
            g_object_unref(session);
        }
        
        if (device) {
            g_object_unref(device);
        }
        
        if (device_manager) {
            g_object_unref(device_manager);
        }
        
        frida_deinit();
        std::cout << "[+] 정리 완료" << std::endl;
    }
};

// 메인 함수 - 개선된 버전
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "사용법: " << argv[0] << " <실행파일경로> [인자1] [인자2] ..." << std::endl;
        std::cerr << "  또는: " << argv[0] << " --pid <PID>  (기존 프로세스 분석)" << std::endl;
        std::cerr << std::endl;
        std::cerr << "예시:" << std::endl;
        std::cerr << "  " << argv[0] << " /usr/bin/wget https://example.com" << std::endl;
        std::cerr << "  " << argv[0] << " ./my_crypto_app input.txt" << std::endl;
        std::cerr << "  " << argv[0] << " --pid 1234" << std::endl;
        return 1;
    }
    
    try {
        std::cout << "=== 암호화 동적분석 Orchestrator v2.0 ===" << std::endl;
        
        CryptoOrchestrator orchestrator;
        
        // PID 모드인지 실행파일 모드인지 확인
        if (std::string(argv[1]) == "--pid") {
            // 기존 프로세스 attach 모드
            if (argc != 3) {
                std::cerr << "[-] PID를 지정하세요" << std::endl;
                return 1;
            }
            
            guint target_pid = std::stoul(argv[2]);
            std::cout << "[+] 기존 프로세스 분석 모드 (PID: " << target_pid << ")" << std::endl;
            
            if (!orchestrator.attachToProcess(target_pid)) {
                std::cerr << "[-] 프로세스 연결 실패" << std::endl;
                return 1;
            }
        } else {
            // 새 프로세스 실행 모드
            std::string binary_path = argv[1];
            std::vector<std::string> args;
            
            // 추가 인자들 수집
            for (int i = 2; i < argc; i++) {
                args.push_back(argv[i]);
            }
            
            std::cout << "[+] 새 프로세스 실행 모드: " << binary_path << std::endl;
            
            pid_t pid = orchestrator.launchAndAttach(binary_path, args);
            if (pid <= 0) {
                std::cerr << "[-] 프로세스 실행 및 연결 실패" << std::endl;
                return 1;
            }
        }
        
        // 모든 에이전트 로딩
        if (!orchestrator.loadAllAgents()) {
            std::cerr << "[-] 에이전트 로딩 실패" << std::endl;
            return 1;
        }
        
        // 모니터링 시작 (기본 60초)
        orchestrator.startMonitoring(60);
        
        // 결과 저장
        orchestrator.saveResults("crypto_analysis_results.json");
        
        std::cout << "[+] 분석 완료!" << std::endl;
        std::cout << "[+] 결과 파일: crypto_analysis_results.json" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "[-] 오류 발생: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}