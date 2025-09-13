# ECC 프로젝트 Makefile

# 컴파일러 설정
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -Wno-deprecated-declarations

# OpenSSL 라이브러리 설정
LDFLAGS = -lssl -lcrypto

# 타겟 설정
TARGET = ecc
SRCS = ecc.cpp
OBJS = $(SRCS:.cpp=.o)

# 기본 타겟
all: $(TARGET)

# 실행 파일 생성 규칙
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# 오브젝트 파일 생성 규칙
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 실행
run: $(TARGET)
	./$(TARGET)

# 클린
clean:
	rm -f $(OBJS) $(TARGET)

# 디버그 빌드
debug: CXXFLAGS += -g -DDEBUG
debug: all

.PHONY: all run clean debug
