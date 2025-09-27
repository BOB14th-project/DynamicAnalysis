// include/reentry_guard.h
#pragma once

// 간단 재진입 가드: 같은 스레드에서 훅 → real 호출이 다시 훅을 타는 걸 1레벨 차단
struct ReentryGuard {
  inline static thread_local int depth = 0;  // ODR-safe
  bool active = false;
  ReentryGuard() { if (depth++ == 0) active = true; }
  ~ReentryGuard() { --depth; }
  explicit operator bool() const { return active; }
};
