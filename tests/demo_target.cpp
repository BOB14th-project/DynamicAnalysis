#include <stdio.h>

// 원본 foo (LD_PRELOAD 미사용 실행 시 이게 호출됨)
void foo(int a, int b) {
    printf("[orig] %d + %d = %d\n", a, b, a+b);
}

int main() {
    foo(2, 3);
    return 0;
}
