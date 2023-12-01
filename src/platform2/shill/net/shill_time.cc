// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <time.h>

#include "shill/net/shill_time.h"

#include <base/format_macros.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>

namespace shill {

Time::Time() {}

Time::~Time() {}

Time* Time::GetInstance() {
  // As Time may be instantiated by MemoryLogMessage during a callback of
  // AtExitManager, it needs to be a leaky singleton to avoid
  // AtExitManager::RegisterCallback() from potentially being called within a
  // callback of AtExitManager, which will lead to a crash. Making Time leaky is
  // fine as it does not need to clean up or release any resource at
  // destruction.
  static base::NoDestructor<Time> instance;
  return instance.get();
}

bool Time::GetSecondsMonotonic(time_t* seconds) {
  struct timeval now;
  if (GetTimeMonotonic(&now) < 0) {
    return false;
  } else {
    *seconds = now.tv_sec;
    return true;
  }
}

bool Time::GetMicroSecondsMonotonic(int64_t* usecs) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return false;
  }
  *usecs = ConvertTimespecToMicros(ts);
  return true;
}

bool Time::GetSecondsBoottime(time_t* seconds) {
  struct timeval now;
  if (GetTimeBoottime(&now) < 0) {
    return false;
  } else {
    *seconds = now.tv_sec;
    return true;
  }
}

int Time::GetTimeMonotonic(struct timeval* tv) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return -1;
  }

  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec / 1000;
  return 0;
}

int Time::GetTimeBoottime(struct timeval* tv) {
  struct timespec ts;
  if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
    return -1;
  }

  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec / 1000;
  return 0;
}

int Time::GetTimeOfDay(struct timeval* tv, struct timezone* tz) {
  return gettimeofday(tv, tz);
}

Timestamp Time::GetNow() {
  struct timeval now_monotonic = {};
  struct timeval now_boottime = {};
  struct timeval now_wall_clock = {};
  struct tm local_time = {};
  std::string wall_clock_string;

  GetTimeMonotonic(&now_monotonic);
  GetTimeBoottime(&now_boottime);
  GetTimeOfDay(&now_wall_clock, nullptr);
  localtime_r(&now_wall_clock.tv_sec, &local_time);
  wall_clock_string = FormatTime(local_time, now_wall_clock.tv_usec);

  return Timestamp(now_monotonic, now_boottime, wall_clock_string);
}

// static
std::string Time::FormatTime(const struct tm& date_time, suseconds_t usec) {
  char date_time_string[64];
  size_t date_time_length;
  date_time_length = strftime(date_time_string, sizeof(date_time_string),
                              "%Y-%m-%dT%H:%M:%S %z", &date_time);

  // Stitch in the microseconds, to provider finer resolution than
  // strftime allows.
  std::string full_string = "<unknown>";
  char* split_pos = static_cast<char*>(
      memchr(date_time_string, ' ', sizeof(date_time_string)));
  if (date_time_length && date_time_length < sizeof(date_time_string) &&
      split_pos) {
    *split_pos = '\0';
    full_string =
        base::StringPrintf("%s.%06" PRIu64 "%s", date_time_string,
                           static_cast<uint64_t>(usec), split_pos + 1);
  }

  return full_string;
}

// TODO(crbug.com/166153): Copied from Chrome's //base/time/time_now_posix.cc.
// Make upstream code available via libchrome and use it here: crbug.com/166153
// static
int64_t Time::ConvertTimespecToMicros(const struct timespec& ts) {
  // On 32-bit systems, the calculation cannot overflow int64_t.
  // 2**32 * 1000000 + 2**64 / 1000 < 2**63
  if (sizeof(ts.tv_sec) <= 4 && sizeof(ts.tv_nsec) <= 8) {
    int64_t result = ts.tv_sec;
    result *= base::Time::kMicrosecondsPerSecond;
    result += (ts.tv_nsec / base::Time::kNanosecondsPerMicrosecond);
    return result;
  }
  base::CheckedNumeric<int64_t> result(ts.tv_sec);
  result *= base::Time::kMicrosecondsPerSecond;
  result += (ts.tv_nsec / base::Time::kNanosecondsPerMicrosecond);
  return result.ValueOrDie();
}

time_t Time::GetSecondsSinceEpoch() const {
  return time(nullptr);
}

}  // namespace shill
