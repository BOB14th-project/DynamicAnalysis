// crypto_orchestrator.cpp - Frida spawn 모드 사용 버전 (개선됨)
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
    
    // 에이전트 로딩 모드
    enum AgentLoadingMode {
        MODE_SPECIALIZED_ONLY,  // 특화 에이전트만 사용
        MODE_GENERIC_ONLY,      // 범용 에이전트만 사용
        MODE_HYBRID            // 특화 + 보조 에이전트 조합
    };
    
    AgentLoadingMode loading_mode;
    
public:
    CryptoOrchestrator() : device_manager(nullptr), device(nullptr), 
                          session(nullptr), spawned_pid(0), 
                          loading_mode(MODE_SPECIALIZED_ONLY) {
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
        } else if (binary_path.find("mbedtls") != std::string::npos ||
                   binary_path.find("mbed") != std::string::npos) {
            // mbedTLS 사용 추정
            static_result.detected_libraries[static_result.library_count++] = CRYPTO_LIB_MBEDTLS;
            std::cout << "  [탐지] mbedTLS" << std::endl;
        } else if (binary_path.find("sodium") != std::string::npos) {
            // libsodium 사용 추정
            static_result.detected_libraries[static_result.library_count++] = CRYPTO_LIB_LIBSODIUM;
            std::cout << "  [탐지] libsodium" << std::endl;
        } else {
            // 일반적인 경우 - 라이브러리를 확실하게 알 수 없음
            // 범용 에이전트를 사용하도록 설정
            std::cout << "  [정보] 특정 암호화 라이브러리를 탐지하지 못함" << std::endl;
            std::cout << "  [정보] 범용 에이전트를 사용합니다" << std::endl;
        }
        
        // 주요 라이브러리 선택
        if (static_result.library_count > 0) {
            static_result.primary_library = static_result.detected_libraries[0];
            std::cout << "  [주요 라이브러리] " << crypto_library_type_to_string(static_result.primary_library) << std::endl;
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
    
    // 개선된 에이전트 선택 로직 - 조건부 로딩
    std::vector<std::string> selectAgentFiles() {
        std::vector<std::string> agent_files;
        bool specialized_agent_found = false;
        
        std::cout << "[+] 에이전트 선택 중..." << std::endl;
        
        // 1. 특화 에이전트 확인
        for (size_t i = 0; i < static_result.library_count; i++) {
            crypto_library_type_t lib = static_result.detected_libraries[i];
            
            // OpenSSL 계열
            if (lib == CRYPTO_LIB_OPENSSL || 
                lib == CRYPTO_LIB_LIBSSL || 
                lib == CRYPTO_LIB_LIBCRYPTO ||
                lib == CRYPTO_LIB_BORINGSSL ||
                lib == CRYPTO_LIB_LIBRESSL) {
                
                agent_files.push_back("agent/c_cpp/openssl_agent.js");
                specialized_agent_found = true;
                std::cout << "  [선택] OpenSSL 특화 에이전트" << std::endl;
                break;  // OpenSSL 에이전트만 사용
            }
            // mbedTLS
            else if (lib == CRYPTO_LIB_MBEDTLS) {
                agent_files.push_back("agent/c_cpp/mbedTLS_agent.js");
                specialized_agent_found = true;
                std::cout << "  [선택] mbedTLS 특화 에이전트" << std::endl;
                break;
            }
            // libsodium
            else if (lib == CRYPTO_LIB_LIBSODIUM) {
                agent_files.push_back("agent/c_cpp/libsodium_agent.js");
                specialized_agent_found = true;
                std::cout << "  [선택] libsodium 특화 에이전트" << std::endl;
                break;
            }
            // GnuTLS
            else if (lib == CRYPTO_LIB_GNUTLS) {
                agent_files.push_back("agent/c_cpp/gnutls_agent.js");
                specialized_agent_found = true;
                std::cout << "  [선택] GnuTLS 특화 에이전트" << std::endl;
                break;
            }
            // Windows CNG
            else if (lib == CRYPTO_LIB_WIN_CNG || 
                     lib == CRYPTO_LIB_WIN_BCRYPT) {
                agent_files.push_back("agent/windows/cng_agent.js");
                specialized_agent_found = true;
                std::cout << "  [선택] Windows CNG 특화 에이전트" << std::endl;
                break;
            }
            // Windows CryptoAPI (레거시)
            else if (lib == CRYPTO_LIB_WIN_CRYPTOAPI || 
                     lib == CRYPTO_LIB_WIN_CRYPT32) {
                agent_files.push_back("agent/windows/cryptoapi_agent.js");
                specialized_agent_found = true;
                std::cout << "  [선택] Windows CryptoAPI 특화 에이전트" << std::endl;
                break;
            }
        }
        
        // 2. 특화 에이전트가 없는 경우에만 범용 에이전트 사용
        if (!specialized_agent_found) {
            agent_files.push_back("agent/c_cpp_crypto_agent.js");
            std::cout << "  [선택] 범용 C/C++ 암호화 에이전트" << std::endl;
            loading_mode = MODE_GENERIC_ONLY;
        } else {
            loading_mode = MODE_SPECIALIZED_ONLY;
        }
        
        // 3. 하이브리드 모드 (환경변수로 활성화 가능)
        const char* hybrid_mode_env = getenv("CRYPTO_HYBRID_MODE");
        if (hybrid_mode_env && std::string(hybrid_mode_env) == "1") {
            if (specialized_agent_found) {
                // 특화 에이전트가 있어도 보조 에이전트 추가
                agent_files.push_back("agent/auxiliary/memory_agent.js");  // 메모리 추적용
                agent_files.push_back("agent/auxiliary/file_agent.js");    // 파일 작업 추적용
                loading_mode = MODE_HYBRID;
                std::cout << "  [선택] 하이브리드 모드 - 보조 에이전트 추가" << std::endl;
            }
        }
        
        // 4. 중복 제거 (혹시 모를 중복 방지)
        std::set<std::string> unique_files(agent_files.begin(), agent_files.end());
        std::vector<std::string> final_files(unique_files.begin(), unique_files.end());
        
        std::cout << "[+] 총 " << final_files.size() << "개 에이전트 선택됨" << std::endl;
        return final_files;
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
            
            // 에이전트 타입에 따른 구분
            if (msg_type == "crypto_capture") {
                // 범용 에이전트 메시지
                orchestrator->handleGenericMessage(root);
            } else if (msg_type == "openssl_capture") {
                // OpenSSL 특화 에이전트 메시지
                orchestrator->handleOpenSSLMessage(root);
            } else if (msg_type == "send") {
                // 레거시 형식 지원
                orchestrator->handleLegacyMessage(root);
            } else if (msg_type == "log") {
                // 디버그 로그
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
    
    // 범용 에이전트 메시지 처리
    void handleGenericMessage(const Json::Value& root) {
        if (root.isMember("category") && root.isMember("data")) {
            std::string category = root["category"].asString();
            Json::Value data = root["data"];
            
            std::cout << "[GENERIC] " << category;
            
            if (category == "algorithm") {
                if (data.isMember("cipher")) {
                    std::cout << " - " << data["cipher"].asString();
                }
            } else if (category == "key_generation") {
                if (data.isMember("algorithm") && data.isMember("key_size")) {
                    std::cout << " - " << data["algorithm"].asString() 
                             << " (" << data["key_size"].asInt() << " bits)";
                }
            } else if (category == "memory_dump") {
                if (data.isMember("label") && data.isMember("entropy")) {
                    std::cout << " - " << data["label"].asString() 
                             << " (entropy: " << data["entropy"].asFloat() << ")";
                }
            } else if (category == "timing") {
                if (data.isMember("function") && data.isMember("duration_ms")) {
                    std::cout << " - " << data["function"].asString() 
                             << " (" << data["duration_ms"].asInt() << "ms)";
                }
            }
            
            std::cout << std::endl;
        }
    }
    
    // OpenSSL 특화 에이전트 메시지 처리
    void handleOpenSSLMessage(const Json::Value& root) {
        if (root.isMember("category") && root.isMember("data")) {
            std::string category = root["category"].asString();
            Json::Value data = root["data"];
            
            std::cout << "[OPENSSL] " << category;
            
            if (category == "cipher_init") {
                if (data.isMember("cipher")) {
                    std::cout << " - " << data["cipher"].asString();
                }
            } else if (category == "rsa_keygen") {
                if (data.isMember("key_size_bits")) {
                    std::cout << " - RSA " << data["key_size_bits"].asInt() << " bits";
                }
            } else if (category == "hash_init") {
                if (data.isMember("algorithm")) {
                    std::cout << " - " << data["algorithm"].asString();
                }
            } else if (category == "memory_dump") {
                if (data.isMember("label") && data.isMember("appears_random")) {
                    std::cout << " - " << data["label"].asString();
                    if (data["appears_random"].asBool()) {
                        std::cout << " [ENCRYPTED/RANDOM]";
                    }
                }
            }
            
            std::cout << std::endl;
        }
    }
    
    // 레거시 메시지 처리 (이전 버전 호환성)
    void handleLegacyMessage(const Json::Value& root) {
        if (root.isMember("payload")) {
            Json::Value payload = root["payload"];
            if (payload.isMember("category")) {
                std::string category = payload["category"].asString();
                std::cout << "[LEGACY] " << category;
                
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
        
        // 로딩 모드 출력
        switch (loading_mode) {
            case MODE_SPECIALIZED_ONLY:
                std::cout << "[+] 모드: 특화 에이전트만 사용" << std::endl;
                break;
            case MODE_GENERIC_ONLY:
                std::cout << "[+] 모드: 범용 에이전트만 사용" << std::endl;
                break;
            case MODE_HYBRID:
                std::cout << "[+] 모드: 하이브리드 (특화 + 보조)" << std::endl;
                break;
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
        final_result["metadata"]["version"] = "2.1";
        final_result["metadata"]["analysis_timestamp"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        final_result["metadata"]["loading_mode"] = 
            loading_mode == MODE_SPECIALIZED_ONLY ? "specialized_only" :
            loading_mode == MODE_GENERIC_ONLY ? "generic_only" : "hybrid";
        
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
        
        // 동적 분석 결과 - 에이전트 타입별로 분류
        final_result["dynamic_analysis"]["generic_captures"] = Json::Value(Json::arrayValue);
        final_result["dynamic_analysis"]["openssl_captures"] = Json::Value(Json::arrayValue);
        final_result["dynamic_analysis"]["other_captures"] = Json::Value(Json::arrayValue);
        
        int generic_count = 0, openssl_count = 0, other_count = 0;
        
        for (const auto& data : captured_data) {
            std::string msg_type = data.get("type", "").asString();
            
            if (msg_type == "crypto_capture") {
                final_result["dynamic_analysis"]["generic_captures"].append(data);
                generic_count++;
            } else if (msg_type == "openssl_capture") {
                final_result["dynamic_analysis"]["openssl_captures"].append(data);
                openssl_count++;
            } else if (msg_type == "send") {
                // 레거시 형식 처리
                if (data.isMember("payload")) {
                    Json::Value payload = data["payload"];
                    if (payload.get("type", "").asString() == "crypto_capture") {
                        final_result["dynamic_analysis"]["other_captures"].append(payload);
                        other_count++;
                    }
                }
            }
        }
        
        // 로드된 에이전트 정보
        final_result["agents_loaded"] = Json::Value(Json::arrayValue);
        for (size_t i = 0; i < active_scripts.size(); i++) {
            final_result["agents_loaded"].append(
                loading_mode == MODE_SPECIALIZED_ONLY ? "specialized_agent" :
                loading_mode == MODE_GENERIC_ONLY ? "generic_agent" : 
                "hybrid_agent_" + std::to_string(i)
            );
        }
        
        // 간단한 카운터만 제공 (통계 분석은 제거)
        int event_count = 0;
        for (const auto& data : captured_data) {
            std::string msg_type = data.get("type", "").asString();
            if (msg_type == "crypto_capture" || msg_type == "openssl_capture") {
                event_count++;
            }
        }
        
        final_result["metadata"]["crypto_events_count"] = event_count;
        
        // 파일 저장
        std::ofstream file(output_file);
        if (file.is_open()) {
            Json::StreamWriterBuilder builder;
            builder["indentation"] = "  ";
            std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
            writer->write(final_result, &file);
            file.close();
            
            std::cout << "[+] 결과 저장 완료: " << output_file << std::endl;
            std::cout << "[+] 총 캡처된 이벤트: " << captured_data.size() << "개" << std::endl;
            std::cout << "[+] 암호화 관련 이벤트: " << event_count << "개" << std::endl;
            
            // 에이전트 타입 정보만 출력
            if (loading_mode == MODE_SPECIALIZED_ONLY) {
                std::cout << "[+] 사용된 에이전트: 특화 에이전트" << std::endl;
            } else if (loading_mode == MODE_GENERIC_ONLY) {
                std::cout << "[+] 사용된 에이전트: 범용 에이전트" << std::endl;
            } else if (loading_mode == MODE_HYBRID) {
                std::cout << "[+] 사용된 에이전트: 하이브리드 (특화 + 보조)" << std::endl;
            }
            
            std::cout << "[+] 모든 원시 데이터가 저장되었습니다." << std::endl;
            std::cout << "[+] 후처리 분석을 위해 raw_captures 필드를 사용하세요." << std::endl;
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
        std::cerr << std::endl;
        std::cerr << "환경변수:" << std::endl;
        std::cerr << "  CRYPTO_MONITOR_DURATION=120  # 모니터링 시간 (초)" << std::endl;
        std::cerr << "  CRYPTO_OUTPUT_FILE=result.json  # 결과 파일명" << std::endl;
        std::cerr << "  CRYPTO_HYBRID_MODE=1  # 하이브리드 모드 활성화" << std::endl;
        return 1;
    }
    
    try {
        std::cout << "==========================================" << std::endl;
        std::cout << "   암호화 동적분석 Orchestrator v2.1     " << std::endl;
        std::cout << "      (조건부 에이전트 로딩 적용)        " << std::endl;
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