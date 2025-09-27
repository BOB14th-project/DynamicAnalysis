// pch.h
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <fcntl.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Java JNI 헤더 (시스템에 JDK가 설치된 경우)
#ifdef JAVA_SUPPORT_ENABLED
#include <jni.h>
#endif