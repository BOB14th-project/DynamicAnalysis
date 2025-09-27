#include "pch.h"
#include "dynamic_analysis.h"
#include "hook_common.h"
#include "log.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <cerrno>

#if defined(__linux__)
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <sys/wait.h>
  #include <unistd.h>
#endif

namespace {

enum class HostOS {
    Linux,
    Windows,
    Unsupported
};

static HostOS detect_host_os() {
#if defined(_WIN32) || defined(_WIN64)
    return HostOS::Windows;
#elif defined(__linux__)
    return HostOS::Linux;
#else
    return HostOS::Unsupported;
#endif
}

#if defined(__linux__)
static std::filesystem::path locate_hook_library() {
    namespace fs = std::filesystem;
    std::vector<fs::path> candidates;

    if (const char* env = std::getenv("HOOK_LIBRARY_PATH")) {
        if (*env) candidates.emplace_back(env);
    }

    std::error_code ec;
    fs::path exe_path = fs::read_symlink("/proc/self/exe", ec);
    if (!ec) {
        fs::path bin_dir = exe_path.parent_path();
        if (!bin_dir.empty()) {
            fs::path build_dir = bin_dir.parent_path();
            if (!build_dir.empty()) {
                candidates.emplace_back(build_dir / "lib" / "libhook.so");
                candidates.emplace_back(build_dir / "libhook.so");
            }
        }
    }

    candidates.emplace_back(std::filesystem::current_path() / "build" / "lib" / "libhook.so");
    candidates.emplace_back(std::filesystem::current_path() / "build" / "libhook.so");
    candidates.emplace_back(std::filesystem::current_path() / "libhook.so");

    for (const auto& candidate : candidates) {
        if (candidate.empty()) continue;
        std::error_code exists_ec;
        if (std::filesystem::exists(candidate, exists_ec) && !exists_ec) {
            std::error_code canon_ec;
            auto canonical_path = std::filesystem::canonical(candidate, canon_ec);
            return canon_ec ? std::filesystem::absolute(candidate) : canonical_path;
        }
    }
    return {};
}

static bool is_executable(const std::filesystem::path& target) {
    struct stat st;
    if (stat(target.c_str(), &st) != 0) return false;
    return (st.st_mode & S_IXUSR) != 0;
}

static int run_linux_dynamic_analysis(const std::filesystem::path& directory,
                                      const std::filesystem::path& binary) {
    namespace fs = std::filesystem;

    fs::path target = directory.empty() ? binary : directory / binary;
    std::error_code ec;
    target = fs::weakly_canonical(target, ec);
    if (ec) target = fs::absolute(target);

    if (!fs::exists(target)) {
        std::cerr << "[dynamic_analysis] target not found: " << target << '\n';
        return 1;
    }
    if (!is_executable(target)) {
        std::cerr << "[dynamic_analysis] target is not executable: " << target << '\n';
        return 1;
    }

    fs::path hook = locate_hook_library();
    if (hook.empty() || !fs::exists(hook)) {
        std::cerr << "[dynamic_analysis] unable to locate libhook.so" << '\n';
        return 1;
    }

    fs::path logs_dir = fs::current_path() / "logs";
    fs::create_directories(logs_dir);

    fs::path log_file = logs_dir / (binary.filename().string() + ".ndjson");
    std::error_code remove_ec;
    fs::remove(log_file, remove_ec);

    auto capture_env = [](const char* key) {
        const char* value = std::getenv(key);
        return value ? std::optional<std::string>(value) : std::nullopt;
    };
    auto restore_env = [](const char* key, const std::optional<std::string>& value) {
        if (value.has_value()) {
            setenv(key, value->c_str(), 1);
        } else {
            unsetenv(key);
        }
    };

    std::optional<std::string> prev_ld_preload = capture_env("LD_PRELOAD");
    std::optional<std::string> prev_hook_verbose = capture_env(HOOK_ENV_VERBOSE);
    std::optional<std::string> prev_hook_ndjson = capture_env("HOOK_NDJSON");

    setenv("LD_PRELOAD", hook.c_str(), 1);
    setenv(HOOK_ENV_VERBOSE, "1", 1);
    setenv("HOOK_NDJSON", log_file.c_str(), 1);

    std::cout << "[dynamic_analysis] host: Linux" << '\n';
    std::cout << "[dynamic_analysis] preload: " << hook << '\n';
    std::cout << "[dynamic_analysis] target:  " << target << '\n';
    std::cout << "[dynamic_analysis] log:     " << log_file << '\n';

    pid_t pid = fork();
    if (pid == 0) {
        execl(target.c_str(), target.c_str(), static_cast<char*>(nullptr));
        perror("execl");
        _exit(errno ? errno : 1);
    }
    if (pid < 0) {
        perror("fork");
        restore_env("LD_PRELOAD", prev_ld_preload);
        restore_env(HOOK_ENV_VERBOSE, prev_hook_verbose);
        restore_env("HOOK_NDJSON", prev_hook_ndjson);
        return 1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        restore_env("LD_PRELOAD", prev_ld_preload);
        restore_env(HOOK_ENV_VERBOSE, prev_hook_verbose);
        restore_env("HOOK_NDJSON", prev_hook_ndjson);
        return 1;
    }

    restore_env("LD_PRELOAD", prev_ld_preload);
    restore_env(HOOK_ENV_VERBOSE, prev_hook_verbose);
    restore_env("HOOK_NDJSON", prev_hook_ndjson);

    if (WIFEXITED(status)) {
        std::cout << "[dynamic_analysis] child exit code: " << WEXITSTATUS(status) << '\n';
    } else if (WIFSIGNALED(status)) {
        std::cout << "[dynamic_analysis] child terminated by signal: " << WTERMSIG(status) << '\n';
    }

    std::ifstream in(log_file);
    if (!in.good()) {
        std::cout << "[dynamic_analysis] no hook output written." << '\n';
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }

    std::cout << "[dynamic_analysis] captured events:" << '\n';
    std::string line;
    while (std::getline(in, line)) {
        std::cout << line << '\n';
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 0;
}
#endif

} // namespace

int dynamic_analysis(const std::string& directory, const std::string& binary_name) {
    HostOS os = detect_host_os();
    switch (os) {
        case HostOS::Linux:
#if defined(__linux__)
            return run_linux_dynamic_analysis(directory, binary_name);
#else
            std::cerr << "[dynamic_analysis] built without Linux support." << '\n';
            return 1;
#endif
        case HostOS::Windows:
            std::cout << "[dynamic_analysis] host: Windows" << '\n';
            std::cout << "[dynamic_analysis] Windows dynamic analysis is not implemented." << '\n';
            return 1;
        default:
            std::cout << "[dynamic_analysis] unsupported host platform." << '\n';
            return 1;
    }
}
