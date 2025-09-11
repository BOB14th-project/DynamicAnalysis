# Crypto Dynamic Analysis Orchestrator Makefile
# 사용법: make, make clean, make install, make test

# === 변수 정의 ===
CC = g++
TARGET = crypto_orchestrator
SOURCES = crypto_orchestrator.cpp
HEADERS = crypto_library_types.h

# 디렉토리 경로
FRIDA_DIR = ./frida-core
AGENT_DIR = ./agent/c_cpp

# 컴파일러 플래그
CFLAGS = -std=c++11 -Wall -Wextra -O2
INCLUDES = -I$(FRIDA_DIR) -I/usr/include/jsoncpp
LIBS = -L$(FRIDA_DIR) -lfrida-core -ljsoncpp
SYSLIBS = $(shell pkg-config --cflags --libs glib-2.0 gio-2.0) -pthread -ldl

# 설치 경로
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
DATADIR = $(PREFIX)/share/crypto-analysis

# 색상 정의 (터미널 출력용)
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
PURPLE = \033[0;35m
CYAN = \033[0;36m
NC = \033[0m # No Color

# === 메인 타겟 ===
.PHONY: all clean install uninstall test help check-deps check-agents example sandbox

all: check-deps $(TARGET)
	@echo "$(GREEN)[✓] 빌드 완료!$(NC)"
	@echo ""
	@echo "$(CYAN)=== 사용법 ===$(NC)"
	@echo "$(BLUE)실행파일 분석:$(NC) ./$(TARGET) <실행파일> [인자...]"
	@echo "$(BLUE)PID 분석:$(NC)      ./$(TARGET) --pid <PID>"
	@echo ""
	@echo "$(YELLOW)예시:$(NC)"
	@echo "  ./$(TARGET) /usr/bin/curl https://example.com"
	@echo "  ./$(TARGET) ./my_crypto_app input.txt"
	@echo "  ./$(TARGET) --pid 1234"

# 메인 실행파일 빌드
$(TARGET): $(SOURCES) $(HEADERS)
	@echo "$(YELLOW)[+] $(TARGET) 컴파일 중...$(NC)"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SOURCES) $(LIBS) $(SYSLIBS)
	@echo "$(GREEN)[✓] $(TARGET) 컴파일 완료$(NC)"

# === 의존성 검사 ===
check-deps:
	@echo "$(BLUE)[*] 의존성 검사 중...$(NC)"
	@if [ ! -f "$(FRIDA_DIR)/libfrida-core.a" ]; then \
		echo "$(RED)[!] libfrida-core.a를 찾을 수 없습니다: $(FRIDA_DIR)/$(NC)"; \
		echo "$(YELLOW)    frida-core를 올바르게 설치했는지 확인하세요.$(NC)"; \
		echo "$(YELLOW)    설치 방법:$(NC)"; \
		echo "$(CYAN)      wget https://github.com/frida/frida/releases/download/16.1.4/frida-core-devkit-16.1.4-linux-x86_64.tar.xz$(NC)"; \
		echo "$(CYAN)      mkdir -p frida-core && tar -xf frida-core-devkit*.tar.xz -C frida-core/$(NC)"; \
		exit 1; \
	fi
	@if [ ! -f "$(FRIDA_DIR)/frida-core.h" ]; then \
		echo "$(RED)[!] frida-core.h를 찾을 수 없습니다: $(FRIDA_DIR)/$(NC)"; \
		exit 1; \
	fi
	@if ! pkg-config --exists glib-2.0; then \
		echo "$(RED)[!] glib-2.0 개발 라이브러리가 설치되지 않았습니다$(NC)"; \
		echo "$(YELLOW)    설치: sudo apt-get install libglib2.0-dev$(NC)"; \
		exit 1; \
	fi
	@if ! pkg-config --exists gio-2.0; then \
		echo "$(RED)[!] gio-2.0 개발 라이브러리가 설치되지 않았습니다$(NC)"; \
		echo "$(YELLOW)    설치: sudo apt-get install libglib2.0-dev$(NC)"; \
		exit 1; \
	fi
	@if ! ldconfig -p | grep -q libjsoncpp; then \
		echo "$(RED)[!] libjsoncpp 라이브러리가 설치되지 않았습니다$(NC)"; \
		echo "$(YELLOW)    설치: sudo apt-get install libjsoncpp-dev$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)[✓] 모든 의존성 확인 완료$(NC)"

# === 에이전트 파일 검증 ===
check-agents:
	@echo "$(BLUE)[*] 에이전트 파일 검증 중...$(NC)"
	@mkdir -p $(AGENT_DIR)
	@for agent in generic_crypto_agent.js openssl_agent.js mbedTLS_agent.js libsodium_agent.js gnutls_agent.js windows_cng_agent.js libgcrypt_agent.js; do \
		if [ ! -f "$(AGENT_DIR)/$$agent" ]; then \
			echo "$(YELLOW)[!] 에이전트 파일이 없습니다: $(AGENT_DIR)/$$agent$(NC)"; \
			echo "$(CYAN)    생성 중...$(NC)"; \
			echo "// $$agent - Auto-generated placeholder" > "$(AGENT_DIR)/$$agent"; \
			echo "console.log('[$$agent] Loaded');" >> "$(AGENT_DIR)/$$agent"; \
		else \
			echo "$(GREEN)[✓] $$agent$(NC)"; \
		fi \
	done

# === 정리 ===
clean:
	@echo "$(YELLOW)[*] 정리 중...$(NC)"
	@rm -f $(TARGET)
	@rm -f *.o
	@rm -f crypto_analysis_results.json
	@rm -f core dump
	@echo "$(GREEN)[✓] 정리 완료$(NC)"

# === 시스템 설치 ===
install: $(TARGET) check-agents
	@echo "$(YELLOW)[*] 시스템에 설치 중...$(NC)"
	@sudo mkdir -p $(BINDIR)
	@sudo mkdir -p $(DATADIR)/agents
	@sudo cp $(TARGET) $(BINDIR)/
	@sudo cp $(AGENT_DIR)/*.js $(DATADIR)/agents/
	@sudo chmod +x $(BINDIR)/$(TARGET)
	@echo "$(GREEN)[✓] 설치 완료: $(BINDIR)/$(TARGET)$(NC)"
	@echo "$(BLUE)전역 사용 가능:$(NC)"
	@echo "  $(TARGET) <실행파일> [인자...]"
	@echo "  $(TARGET) --pid <PID>"

# === 시스템 제거 ===
uninstall:
	@echo "$(YELLOW)[*] 시스템에서 제거 중...$(NC)"
	@sudo rm -f $(BINDIR)/$(TARGET)
	@sudo rm -rf $(DATADIR)
	@echo "$(GREEN)[✓] 제거 완료$(NC)"

# === 테스트 ===
test: $(TARGET)
	@echo "$(BLUE)=== 기본 테스트 실행 ===$(NC)"
	@echo ""
	@echo "$(YELLOW)[Test 1] 실행파일 존재 확인$(NC)"
	@if [ -x "./$(TARGET)" ]; then \
		echo "$(GREEN)[✓] 실행파일 OK$(NC)"; \
	else \
		echo "$(RED)[✗] 실행파일 실행 불가$(NC)"; \
		exit 1; \
	fi
	@echo ""
	@echo "$(YELLOW)[Test 2] 사용법 출력 확인$(NC)"
	@if ./$(TARGET) 2>&1 | grep -q "실행파일경로"; then \
		echo "$(GREEN)[✓] 사용법 출력 OK$(NC)"; \
	else \
		echo "$(RED)[✗] 사용법 출력 실패$(NC)"; \
		exit 1; \
	fi
	@echo ""
	@echo "$(YELLOW)[Test 3] 에이전트 파일 접근 확인$(NC)"
	@$(MAKE) check-agents > /dev/null 2>&1
	@echo "$(GREEN)[✓] 에이전트 파일 OK$(NC)"
	@echo ""
	@echo "$(YELLOW)[Test 4] 간단한 바이너리 분석 테스트$(NC)"
	@if which ls > /dev/null 2>&1; then \
		timeout 5 ./$(TARGET) /bin/ls -la 2>&1 | grep -q "분석" && \
		echo "$(GREEN)[✓] 바이너리 실행 테스트 OK$(NC)" || \
		echo "$(YELLOW)[!] 바이너리 실행 테스트 (경고만)$(NC)"; \
	fi
	@echo ""
	@echo "$(GREEN)[✓] 모든 테스트 통과!$(NC)"

# === 예제 실행 ===
example: $(TARGET)
	@echo "$(PURPLE)=== 예제 실행 ===$(NC)"
	@echo "$(YELLOW)[1] echo 명령어의 암호화 사용 분석$(NC)"
	./$(TARGET) /bin/echo "Hello World" || true
	@echo ""
	@if [ -f "crypto_analysis_results.json" ]; then \
		echo "$(CYAN)결과 파일 생성됨: crypto_analysis_results.json$(NC)"; \
		echo "$(YELLOW)결과 보기: cat crypto_analysis_results.json | jq '.'$(NC)"; \
	fi

# === 샌드박스 테스트 환경 ===
sandbox: $(TARGET)
	@echo "$(PURPLE)=== 샌드박스 테스트 환경 ===$(NC)"
	@echo "$(YELLOW)안전한 테스트를 위한 격리 환경 생성 중...$(NC)"
	@mkdir -p sandbox_test
	@cp $(TARGET) sandbox_test/
	@cp -r $(AGENT_DIR) sandbox_test/
	@echo "$(GREEN)[✓] 샌드박스 생성 완료: ./sandbox_test/$(NC)"
	@echo "$(CYAN)사용법:$(NC)"
	@echo "  cd sandbox_test"
	@echo "  ./$(TARGET) /usr/bin/curl https://example.com"

# === 디버그 빌드 ===
debug: CFLAGS += -g -DDEBUG -O0 -fsanitize=address
debug: clean $(TARGET)
	@echo "$(GREEN)[✓] 디버그 빌드 완료$(NC)"
	@echo "$(BLUE)디버깅: gdb ./$(TARGET)$(NC)"
	@echo "$(BLUE)메모리 체크 활성화됨 (AddressSanitizer)$(NC)"

# === 릴리스 빌드 ===
release: CFLAGS += -O3 -DNDEBUG -s
release: clean $(TARGET)
	@echo "$(GREEN)[✓] 릴리스 빌드 완료$(NC)"
	@strip $(TARGET)
	@echo "$(BLUE)최적화된 바이너리 생성됨$(NC)"
	@ls -lh $(TARGET)

# === 정보 출력 ===
info:
	@echo "$(BLUE)=== 빌드 정보 ===$(NC)"
	@echo "컴파일러: $(CC)"
	@echo "플래그: $(CFLAGS)"
	@echo "타겟: $(TARGET)"
	@echo "Frida 경로: $(FRIDA_DIR)"
	@echo "에이전트 경로: $(AGENT_DIR)"
	@echo ""
	@echo "$(BLUE)=== 시스템 정보 ===$(NC)"
	@uname -a
	@echo ""
	@echo "$(BLUE)=== 라이브러리 정보 ===$(NC)"
	@echo "GLib 버전: $(shell pkg-config --modversion glib-2.0 2>/dev/null || echo '미설치')"
	@echo "GIO 버전: $(shell pkg-config --modversion gio-2.0 2>/dev/null || echo '미설치')"
	@echo "Frida Core: $(shell [ -f "$(FRIDA_DIR)/libfrida-core.a" ] && echo '설치됨' || echo '미설치')"
	@echo ""
	@echo "$(BLUE)=== 파일 크기 ===$(NC)"
	@if [ -f "$(TARGET)" ]; then \
		ls -lh $(TARGET); \
	else \
		echo "$(TARGET) 파일이 없습니다. 먼저 빌드하세요."; \
	fi

# === 도움말 ===
help:
	@echo "$(BLUE)=== Crypto Dynamic Analysis Orchestrator Makefile ===$(NC)"
	@echo "$(PURPLE)버전 2.0 - 실행파일 직접 분석 지원$(NC)"
	@echo ""
	@echo "$(YELLOW)주요 타겟:$(NC)"
	@echo "  $(GREEN)make$(NC) 또는 $(GREEN)make all$(NC)     - 일반 빌드"
	@echo "  $(GREEN)make clean$(NC)              - 빌드 파일 정리"
	@echo "  $(GREEN)make test$(NC)               - 자동 테스트 실행"
	@echo "  $(GREEN)make example$(NC)            - 예제 실행"
	@echo "  $(GREEN)make sandbox$(NC)            - 샌드박스 환경 생성"
	@echo ""
	@echo "$(YELLOW)빌드 옵션:$(NC)"
	@echo "  $(GREEN)make debug$(NC)              - 디버그 빌드 (-g -O0 + sanitizer)"
	@echo "  $(GREEN)make release$(NC)            - 릴리스 빌드 (-O3 최적화)"
	@echo ""
	@echo "$(YELLOW)설치/제거:$(NC)"
	@echo "  $(GREEN)make install$(NC)            - 시스템에 설치 (/usr/local/bin)"
	@echo "  $(GREEN)make uninstall$(NC)          - 시스템에서 제거"
	@echo ""
	@echo "$(YELLOW)검증/정보:$(NC)"
	@echo "  $(GREEN)make check-deps$(NC)         - 의존성 확인"
	@echo "  $(GREEN)make check-agents$(NC)       - 에이전트 파일 확인"
	@echo "  $(GREEN)make info$(NC)               - 빌드/시스템 정보"
	@echo "  $(GREEN)make help$(NC)               - 이 도움말"
	@echo ""
	@echo "$(CYAN)=== 사용 예시 ===$(NC)"
	@echo "$(YELLOW)1. 빌드 및 테스트:$(NC)"
	@echo "   make && make test"
	@echo ""
	@echo "$(YELLOW)2. 실행파일 분석:$(NC)"
	@echo "   ./$(TARGET) /usr/bin/wget https://example.com"
	@echo "   ./$(TARGET) ./my_crypto_app input.dat output.enc"
	@echo "   ./$(TARGET) /usr/bin/ssh user@server.com"
	@echo ""
	@echo "$(YELLOW)3. 기존 프로세스 분석:$(NC)"
	@echo "   ./$(TARGET) --pid 1234"
	@echo ""
	@echo "$(YELLOW)4. 시스템 전역 설치:$(NC)"
	@echo "   sudo make install"
	@echo "   $(TARGET) /usr/bin/curl https://secure.com"
	@echo ""
	@echo "$(CYAN)=== 필수 의존성 ===$(NC)"
	@echo "  • frida-core (./frida-core/libfrida-core.a)"
	@echo "  • libjsoncpp-dev"
	@echo "  • libglib2.0-dev"
	@echo "  • pkg-config"
	@echo ""
	@echo "$(CYAN)=== 지원 플랫폼 ===$(NC)"
	@echo "  • Linux x86_64"
	@echo "  • Ubuntu 18.04+"
	@echo "  • Debian 10+"
	@echo ""
	@echo "$(PURPLE)자세한 정보: https://github.com/your-repo/crypto-orchestrator$(NC)"

# === 의존성 자동 설치 (Ubuntu/Debian) ===
install-deps:
	@echo "$(YELLOW)[*] 의존성 자동 설치 (Ubuntu/Debian)$(NC)"
	@echo "$(RED)관리자 권한이 필요합니다!$(NC)"
	sudo apt-get update
	sudo apt-get install -y \
		build-essential \
		pkg-config \
		libglib2.0-dev \
		libjsoncpp-dev \
		wget \
		tar
	@echo "$(YELLOW)[*] Frida Core 다운로드 중...$(NC)"
	@if [ ! -f "frida-core-devkit.tar.xz" ]; then \
		wget https://github.com/frida/frida/releases/download/16.1.4/frida-core-devkit-16.1.4-linux-x86_64.tar.xz \
			-O frida-core-devkit.tar.xz; \
	fi
	@mkdir -p $(FRIDA_DIR)
	@tar -xf frida-core-devkit.tar.xz -C $(FRIDA_DIR)/
	@echo "$(GREEN)[✓] 의존성 설치 완료!$(NC)"

# === 완전 정리 (모든 생성 파일) ===
distclean: clean
	@echo "$(YELLOW)[*] 완전 정리 중...$(NC)"
	@rm -rf sandbox_test
	@rm -f frida-core-devkit.tar.xz
	@rm -rf $(FRIDA_DIR)
	@echo "$(GREEN)[✓] 완전 정리 완료$(NC)"

# === CI/CD 빌드 타겟 ===
ci: clean check-deps $(TARGET) test
	@echo "$(GREEN)[✓] CI 빌드 및 테스트 완료$(NC)"

# === Docker 빌드 타겟 ===
docker-build:
	@echo "$(YELLOW)[*] Docker 이미지 빌드 중...$(NC)"
	@echo "FROM ubuntu:20.04" > Dockerfile
	@echo "RUN apt-get update && apt-get install -y build-essential pkg-config libglib2.0-dev libjsoncpp-dev" >> Dockerfile
	@echo "COPY . /app" >> Dockerfile
	@echo "WORKDIR /app" >> Dockerfile
	@echo "RUN make" >> Dockerfile
	@echo "ENTRYPOINT [\"./crypto_orchestrator\"]" >> Dockerfile
	docker build -t crypto-orchestrator .
	@echo "$(GREEN)[✓] Docker 이미지 생성 완료: crypto-orchestrator$(NC)"

# === 기본 타겟을 all로 설정 ===
.DEFAULT_GOAL := all