# 변수 정의

CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2
TARGET = aes_lib
SRC = main.cpp
LIBS = -lcrypto

# 기본 타겟
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
