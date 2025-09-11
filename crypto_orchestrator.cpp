// crypto_orchestrator.cpp - Frida spawn 모드 사용 버전
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
    guint spawned_pid;  // Frida spawn으로 생성한 프로세스 PID
    
public:
    CryptoOrchestrator() : device_manager(nullptr), device(nullptr), 
                          session(nullptr), spawned_pid(0) {
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
            binary_path.find("ssl") != std::string::npos ||
            binary_path.find("openssl") != std::string::npos) {
            // 암호화 관련 바이너리라면 OpenSSL 가정
            static_result.detected_libraries[static_result.library_count++] = CRYPTO_LIB_OPENSSL;
            std::cout << "  [탐지] OpenSSL (하드코딩)" << std::endl;
        } else if (binary_path.find("wget") != std::string::npos ||
                   binary_path.find("curl") != std::string::npos ||
                   binary_path.find("ssh") != std::string::npos) {
            // 네트워크 도구들도 대부분 OpenSSL 사용
            static_result.detected_libraries[static_result.library_count++] = CRYPTO_LIB_OPENSSL;
            std::cout << "  [탐지] OpenSSL (네트워크 도구)" << std::endl;
        } else {
            // 일반적인 경우 기본 라이브러리들 추가
            static_result.detected_libraries[static_result.library_count++] = CRYPTO_LIB_OPENSSL;
            std::cout << "  [탐지] OpenSSL (기본값)" << std::endl;
        }
        
        // 주요 라이브러리 선택
        if (static_result.library_count > 0) {
            static_result.primary_library = static_result.detected_libraries[0];
            std::cout << "  [주요 라이브러리] " << crypto_library_type_to_string(static_result.primary_library) << std::endl;
        } else {
            std::cout << "  [경고] 암호화 라이브러리를 탐지하지 못했습니다." << std::endl;
            std::cout << "  [정보] 런타임에 동적 로딩될 수 있습니다." << std::endl;
        }
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
            } else if (lib == CRYPTO_LIB_WIN_CNG) {
                agent_files.push_back("agent/windows/cng_agent.js");
            } else if (lib == CRYPTO_LIB_WIN_CRYPTOAPI) {
                agent_files.push_back("agent/windows/cryptoapi_agent.js");
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
            
            // 타입별 출력 처리
            std::string msg_type = root.get("type", "unknown").asString();
            
            if (msg_type == "send") {
                // send() 메시지 처리
                if (root.isMember("payload")) {
                    Json::Value payload = root["payload"];
                    if (payload.isMember("category")) {
                        std::string category = payload["category"].asString();
                        std::cout << "[CAPTURE] " << category;
                        
                        if (payload.isMember("data")) {
                            Json::Value data = payload["data"];
                            if (data.isMember("function")) {
                                std::cout << " - " << data["function"].asString();
                            }
                            if (data.isMember("algorithm")) {
                                std::cout << " (" << data["algorithm"].asString() << ")";
                            }
                        }
                        std::cout << std::endl;
                    }
                }
            } else if (msg_type == "log") {
                // console.log() 메시지는 디버그 모드에서만 출력
                #ifdef DEBUG
                std::string payload = root.get("payload", "").asString();
                std::cout << "[LOG] " << payload << std::endl;
                #endif
            }
        } else {
            // JSON 파싱 실패시 원본 메시지 출력
            std::cout << "[FRIDA] " << message << std::endl;
        }
    }
    
public:
    // Frida spawn을 사용한 프로세스 실행 및 attach
    guint spawnAndAttach(const std::string& binary_path, 
                         const std::vector<std::string>& args = {}) {
        std::cout << "[+] 타겟 프로세스 spawn 중: " << binary_path << std::endl;
        
        // 먼저 정적 분석 수행
        performStaticAnalysis(binary_path);
        
        // Spawn 옵션 생성
        FridaSpawnOptions* options = frida_spawn_options_new();
        
        // 인자 배열 생성
        gchar** argv = nullptr;
        if (!args.empty()) {
            argv = g_new0(gchar*, args.size() + 2);
            argv[0] = g_strdup(binary_path.c_str());
            for (size_t i = 0; i < args.size(); i++) {
                argv[i + 1] = g_strdup(args[i].c_str());
            }
            frida_spawn_options_set_argv(options, argv, args.size() + 1);
        }
        
        // 환경 변수 설정 (필요시)
        // gchar** envp = g_get_environ();
        // frida_spawn_options_set_envp(options, envp, g_strv_length(envp));
        
        GError* error = nullptr;
        
        // 프로세스 spawn (일시정지 상태로 생성)
        spawned_pid = frida_device_spawn_sync(
            device, 
            binary_path.c_str(),
            options,
            nullptr,
            &error
        );
        
        // 옵션과 인자 메모리 해제
        if (argv) {
            g_strfreev(argv);
        }
        g_object_unref(options);
        
        if (error) {
            std::cerr << "[-] 프로세스 spawn 실패: " << error->message << std::endl;
            g_error_free(error);
            return 0;
        }
        
        std::cout << "[+] 프로세스 생성됨 (PID: " << spawned_pid << ")" << std::endl;
        
        // 생성된 프로세스에 attach
        session = frida_device_attach_sync(device, spawned_pid, nullptr, nullptr, &error);
        
        if (error) {
            std::cerr << "[-] 프로세스 연결 실패: " << error->message << std::endl;
            g_error_free(error);
            
            // attach 실패시 spawn된 프로세스 종료
            frida_device_kill_sync(device, spawned_pid, nullptr, nullptr);
            return 0;
        }
        
        std::cout << "[+] 프로세스 연결 완료" << std::endl;
        return spawned_pid;
    }
    
    bool loadAllAgents() {
        std::cout << "[+] 에이전트 로딩 시작..." << std::endl;
        
        auto agent_files = selectAgentFiles();
        
        if (agent_files.empty()) {
            std::cerr << "[-] 로드할 에이전트가 없습니다" << std::endl;
            return false;
        }
        
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
                std::cerr << "[-] 스크립트 생성 실패 (" << filename << "): " << error->message << std::endl;
                g_error_free(error);
                continue;
            }
            
            g_signal_connect(script, "message", G_CALLBACK(messageHandler), this);
            
            frida_script_load_sync(script, nullptr, &error);
            if (error) {
                std::cerr << "[-] 스크립트 로딩 실패 (" << filename << "): " << error->message << std::endl;
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
    
    // 프로세스 재개 (spawn 후 일시정지 상태에서)
    bool resumeProcess() {
        if (spawned_pid == 0) {
            std::cerr << "[-] 재개할 프로세스가 없습니다" << std::endl;
            return false;
        }
        
        GError* error = nullptr;
        frida_device_resume_sync(device, spawned_pid, nullptr, &error);
        
        if (error) {
            std::cerr << "[-] 프로세스 재개 실패: " << error->message << std::endl;
            g_error_free(error);
            return false;
        }
        
        std::cout << "[+] 프로세스 실행 재개됨" << std::endl;
        return true;
    }
    
    void startMonitoring(int duration_seconds = 60) {
        std::cout << "[+] 암호화 모니터링 시작 (" << duration_seconds << "초)" << std::endl;
        
        // spawn된 프로세스 재개
        if (spawned_pid > 0) {
            resumeProcess();
        }
        
        std::cout << "[+] 암호화 작업 캡처 중..." << std::endl;
        
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::seconds(duration_seconds);
        
        bool process_alive = true;
        int check_counter = 0;
        
        while (std::chrono::steady_clock::now() < end_time && process_alive) {
            g_main_context_iteration(g_main_context_default(), FALSE);
            
            // 프로세스 상태 확인 (매 10회마다)
            if (++check_counter % 10 == 0 && spawned_pid > 0) {
                // Frida API로 프로세스 상태 확인
                GError* error = nullptr;
                FridaProcessList* processes = frida_device_enumerate_processes_sync(
                    device, nullptr, nullptr, &error);
                
                if (error) {
                    g_error_free(error);
                } else {
                    bool found = false;
                    gint count = frida_process_list_size(processes);
                    for (gint i = 0; i < count; i++) {
                        FridaProcess* proc = frida_process_list_get(processes, i);
                        if (frida_process_get_pid(proc) == spawned_pid) {
                            found = true;
                            break;
                        }
                    }
                    g_object_unref(processes);
                    
                    if (!found) {
                        std::cout << "[+] 타겟 프로세스가 종료되었습니다." << std::endl;
                        process_alive = false;
                        break;
                    }
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // 모니터링 종료 후 프로세스가 아직 실행 중이면 종료
        if (process_alive && spawned_pid > 0) {
            std::cout << "[+] 모니터링 시간 만료, 프로세스 종료 중..." << std::endl;
            
            GError* error = nullptr;
            frida_device_kill_sync(device, spawned_pid, nullptr, &error);
            
            if (error) {
                std::cerr << "[-] 프로세스 종료 실패: " << error->message << std::endl;
                g_error_free(error);
            }
        }
        
        std::cout << "[+] 모니터링 완료" << std::endl;
    }
    
    void saveResults(const std::string& output_file = "crypto_analysis_results.json") {
        std::cout << "[+] 결과 저장 중..." << std::endl;
        
        Json::Value final_result;
        
        // 분석 메타데이터
        final_result["metadata"]["version"] = "2.0";
        final_result["metadata"]["analysis_timestamp"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        // 정적 분석 결과
        final_result["static_analysis"]["binary_path"] = static_result.binary_path;
        final_result["static_analysis"]["platform"] = static_result.platform;
        final_result["static_analysis"]["architecture"] = static_result.architecture;
        final_result["static_analysis"]["detected_libraries"] = Json::Value(Json::arrayValue);
        for (size_t i = 0; i < static_result.library_count; i++) {
            const char* lib_name = crypto_library_type_to_string(static_result.detected_libraries[i]);
            final_result["static_analysis"]["detected_libraries"].append(lib_name);
        }
        if (static_result.library_count > 0) {
            final_result["static_analysis"]["primary_library"] = 
                crypto_library_type_to_string(static_result.primary_library);
        }
        
        // 동적 분석 결과 - 실제 암호화 작업만 필터링
        final_result["dynamic_analysis"]["captured_operations"] = Json::Value(Json::arrayValue);
        int crypto_ops_count = 0;
        
        for (const auto& data : captured_data) {
            // send 타입이고 crypto_capture 카테고리인 것만 저장
            if (data.get("type", "").asString() == "send") {
                if (data.isMember("payload")) {
                    Json::Value payload = data["payload"];
                    if (payload.get("type", "").asString() == "crypto_capture" &&
                        payload.get("category", "").asString() != "process_info") {
                        final_result["dynamic_analysis"]["captured_operations"].append(payload);
                        crypto_ops_count++;
                    }
                }
            }
        }
        
        // 요약 통계
        final_result["summary"]["total_operations"] = crypto_ops_count;
        final_result["summary"]["agents_loaded"] = static_cast<int>(active_scripts.size());
        final_result["summary"]["libraries_detected"] = static_cast<int>(static_result.library_count);
        
        // 암호화 알고리즘 통계
        std::map<std::string, int> algo_stats;
        std::map<std::string, int> category_stats;
        
        for (const auto& op : captured_data) {
            if (op.get("type", "").asString() == "send" && op.isMember("payload")) {
                Json::Value payload = op["payload"];
                if (payload.isMember("data") && payload["data"].isMember("algorithm")) {
                    algo_stats[payload["data"]["algorithm"].asString()]++;
                }
                if (payload.isMember("category")) {
                    std::string cat = payload["category"].asString();
                    if (cat != "process_info") {
                        category_stats[cat]++;
                    }
                }
            }
        }
        
        final_result["summary"]["algorithm_usage"] = Json::Value(Json::objectValue);
        for (const auto& pair : algo_stats) {
            final_result["summary"]["algorithm_usage"][pair.first] = pair.second;
        }
        
        final_result["summary"]["category_distribution"] = Json::Value(Json::objectValue);
        for (const auto& pair : category_stats) {
            final_result["summary"]["category_distribution"][pair.first] = pair.second;
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
            std::cout << "[+] 총 캡처된 암호화 작업: " << crypto_ops_count << "개" << std::endl;
            
            // 간단한 요약 출력
            if (!algo_stats.empty()) {
                std::cout << "[+] 사용된 알고리즘:" << std::endl;
                for (const auto& pair : algo_stats) {
                    std::cout << "    - " << pair.first << ": " << pair.second << "회" << std::endl;
                }
            }
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
            session = nullptr;
        }
        
        if (device) {
            g_object_unref(device);
            device = nullptr;
        }
        
        if (device_manager) {
            g_object_unref(device_manager);
            device_manager = nullptr;
        }
        
        frida_deinit();
        std::cout << "[+] 정리 완료" << std::endl;
    }
};

// 메인 함수 - spawn 모드 사용 버전
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "사용법: " << argv[0] << " <실행파일경로> [인자1] [인자2] ..." << std::endl;
        std::cerr << std::endl;
        std::cerr << "예시:" << std::endl;
        std::cerr << "  " << argv[0] << " /usr/bin/wget https://example.com" << std::endl;
        std::cerr << "  " << argv[0] << " ./my_crypto_app input.txt" << std::endl;
        std::cerr << "  " << argv[0] << " /usr/bin/openssl enc -aes-256-cbc -in file.txt -out file.enc" << std::endl;
        return 1;
    }
    
    try {
        std::cout << "==========================================" << std::endl;
        std::cout << "   암호화 동적분석 Orchestrator v2.0     " << std::endl;
        std::cout << "==========================================" << std::endl;
        std::cout << std::endl;
        
        CryptoOrchestrator orchestrator;
        
        // 바이너리 경로와 인자 추출
        std::string binary_path = argv[1];
        std::vector<std::string> args;
        
        // 추가 인자들 수집
        for (int i = 2; i < argc; i++) {
            args.push_back(argv[i]);
        }
        
        std::cout << "[+] 분석 대상: " << binary_path << std::endl;
        if (!args.empty()) {
            std::cout << "[+] 실행 인자: ";
            for (const auto& arg : args) {
                std::cout << arg << " ";
            }
            std::cout << std::endl;
        }
        std::cout << std::endl;
        
        // 프로세스 spawn 및 attach (일시정지 상태로 생성)
        guint pid = orchestrator.spawnAndAttach(binary_path, args);
        if (pid == 0) {
            std::cerr << "[-] 프로세스 생성 및 연결 실패" << std::endl;
            return 1;
        }
        
        // 모든 에이전트 로딩 (프로세스는 아직 일시정지 상태)
        if (!orchestrator.loadAllAgents()) {
            std::cerr << "[-] 에이전트 로딩 실패" << std::endl;
            return 1;
        }
        
        std::cout << std::endl;
        
        // 모니터링 시작 (프로세스 재개 포함)
        int monitoring_duration = 60;
        const char* duration_env = getenv("CRYPTO_MONITOR_DURATION");
        if (duration_env) {
            monitoring_duration = std::atoi(duration_env);
        }
        
        orchestrator.startMonitoring(monitoring_duration);
        
        std::cout << std::endl;
        
        // 결과 저장
        std::string output_file = "crypto_analysis_results.json";
        const char* output_env = getenv("CRYPTO_OUTPUT_FILE");
        if (output_env) {
            output_file = output_env;
        }
        
        orchestrator.saveResults(output_file);
        
        std::cout << std::endl;
        std::cout << "==========================================" << std::endl;
        std::cout << "[✓] 분석 완료!" << std::endl;
        std::cout << "[✓] 결과 파일: " << output_file << std::endl;
        std::cout << "==========================================" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "[-] 오류 발생: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}