#include <iostream>
#include <fstream>
#include <windows.h>
#include <vector>
#include <string>
#include <tlhelp32.h>
#include <algorithm>
#include <iterator>

// 함수 선언
bool LaunchProcessForDebugging(const std::string& path, PROCESS_INFORMATION& pi);
DWORD GetMainThreadId(DWORD processId);
PVOID FindPatternInProcess(HANDLE hProcess, const std::vector<uint8_t>& pattern);
bool SetHardwareBreakpoint(DWORD threadId, PVOID address);
void DebugLoop(HANDLE hProcess, DWORD processId, PVOID bpAddress);

// 텍스트 파일에서 Hex 문자열을 읽어 바이너리 벡터로 변환
std::vector<uint8_t> ReadHexPatternFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "[-] Failed to open pattern file: " << filename << std::endl;
        return {};
    }

    std::vector<uint8_t> data;
    std::string hex_str;

    // 파일 스트림에서 공백으로 구분된 hex 문자열을 하나씩 읽음
    while (file >> hex_str) {
        try {
            // stoi를 사용하여 16진수 문자열을 unsigned long으로 변환 후 uint8_t로 캐스팅
            data.push_back(static_cast<uint8_t>(std::stoul(hex_str, nullptr, 16)));
        }
        catch (const std::invalid_argument& ia) {
            // 경고(C4101)를 해결하기 위해 예외 변수 사용
            std::cerr << "[-] Invalid hex string in pattern file: " << hex_str << " (" << ia.what() << ")" << std::endl;
        }
        catch (const std::out_of_range& oor) {
            // 경고(C4101)를 해결하기 위해 예외 변수 사용
            std::cerr << "[-] Hex string out of range in pattern file: " << hex_str << " (" << oor.what() << ")" << std::endl;
        }
    }
    return data;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <path_to_executable> <pattern_file>" << std::endl;
        return 1;
    }

    std::string targetPath = argv[1];
    std::string patternFile = argv[2];

    std::vector<uint8_t> sboxPattern = ReadHexPatternFile(patternFile);
    if (sboxPattern.empty()) {
        std::cerr << "[-] Pattern file is empty or could not be read properly." << std::endl;
        return 1;
    }

    PROCESS_INFORMATION pi = { 0 };
    if (!LaunchProcessForDebugging(targetPath, pi)) {
        return 1;
    }
    std::cout << "[+] Process launched in debug mode. PID: " << pi.dwProcessId << std::endl;

    Sleep(1000);

    std::cout << "[*] Searching for pattern in memory..." << std::endl;
    PVOID patternAddress = FindPatternInProcess(pi.hProcess, sboxPattern);

    if (!patternAddress) {
        std::cerr << "[-] Pattern not found in process memory." << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    std::cout << "[+] Pattern found at address: " << patternAddress << std::endl;

    DWORD mainThreadId = GetMainThreadId(pi.dwProcessId);
    if (mainThreadId == 0) {
        std::cerr << "[-] Could not find main thread ID." << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    std::cout << "[*] Setting hardware breakpoint on the main thread (" << mainThreadId << ")..." << std::endl;
    if (!SetHardwareBreakpoint(mainThreadId, patternAddress)) {
        std::cerr << "[-] Failed to set hardware breakpoint." << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    std::cout << "[+] Hardware breakpoint set successfully!" << std::endl;

    std::cout << "[*] Entering debug loop. Waiting for breakpoint to be hit..." << std::endl;
    DebugLoop(pi.hProcess, pi.dwProcessId, patternAddress);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

// 1. 디버그 모드로 프로세스 실행
bool LaunchProcessForDebugging(const std::string& path, PROCESS_INFORMATION& pi) {
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(STARTUPINFOA);
    return CreateProcessA(
        path.c_str(),
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS,
        NULL,
        NULL,
        &si,
        &pi
    );
}

// 2. 프로세스 메모리에서 패턴 검색
PVOID FindPatternInProcess(HANDLE hProcess, const std::vector<uint8_t>& pattern) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    PBYTE pCurrent = (PBYTE)sysInfo.lpMinimumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;

    while (pCurrent < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, pCurrent, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                std::vector<uint8_t> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, pCurrent, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    auto it = std::search(buffer.begin(), buffer.begin() + bytesRead, pattern.begin(), pattern.end());
                    if (it != buffer.begin() + bytesRead) {
                        return pCurrent + (it - buffer.begin());
                    }
                }
            }
            pCurrent += mbi.RegionSize;
        }
        else {
            pCurrent += 4096;
        }
    }
    return nullptr;
}


// 3. 메인 스레드 ID 찾기
DWORD GetMainThreadId(DWORD processId) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {
                CloseHandle(hSnap);
                return te.th32ThreadID;
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return 0;
}


// 4. 하드웨어 브레이크포인트 설정
bool SetHardwareBreakpoint(DWORD threadId, PVOID address) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread) return false;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        return false;
    }

    ctx.Dr0 = (DWORD64)address;
    ctx.Dr7 = 0; // 초기화
    ctx.Dr7 |= (1 << 0); // 0번 비트: Dr0 Local Enable
    ctx.Dr7 |= (3 << 16); // 16-17번 비트: RW0 (11 = Read/Write Access)
    ctx.Dr7 |= (0 << 18); // 18-19번 비트: LEN0 (00 = 1-byte length)

    if (!SetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        return false;
    }

    CloseHandle(hThread);
    return true;
}

// 5. 디버그 이벤트 루프
void DebugLoop(HANDLE hProcess, DWORD processId, PVOID bpAddress) {
    DEBUG_EVENT dbgEvent = { 0 };
    bool continueDebugging = true;

    while (continueDebugging) {
        if (!WaitForDebugEvent(&dbgEvent, INFINITE)) {
            break;
        }

        switch (dbgEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD* ex = &dbgEvent.u.Exception.ExceptionRecord;
            // [수정됨] 하드웨어 BP는 EXCEPTION_SINGLE_STEP 예외를 발생시킵니다.
            // 이 간단한 디버거에서는 이 조건만으로 충분합니다.
            if (ex->ExceptionCode == EXCEPTION_SINGLE_STEP) {
                std::cout << "\n========================================================" << std::endl;
                // ExceptionAddress는 데이터에 접근한 '명령어'의 주소입니다.
                std::cout << ">> Hardware Breakpoint Hit! Instruction at: " << ex->ExceptionAddress << std::endl;
                std::cout << "   (This instruction accessed data at: " << bpAddress << ")" << std::endl;

                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, dbgEvent.dwThreadId);
                if (hThread) {
                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                    GetThreadContext(hThread, &ctx);

                    std::cout << "   RAX: " << std::hex << ctx.Rax << std::endl;
                    std::cout << "   RCX: " << std::hex << ctx.Rcx << std::endl;
                    std::cout << "   RDX: " << std::hex << ctx.Rdx << std::endl;
                    std::cout << "   RSI: " << std::hex << ctx.Rsi << std::endl;
                    std::cout << "   RDI: " << std::hex << ctx.Rdi << std::endl;
                    CloseHandle(hThread);
                }
                std::cout << "========================================================" << std::endl;
                continueDebugging = false;
            }
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT: {
            std::cout << "[+] Target process finished." << std::endl;
            continueDebugging = false;
            break;
        }
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    }
}

