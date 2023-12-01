/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * libfake_date_time
 *
 * This library is limited for faking datetime.
 * For sophisticated time manipulation, please see libfaketime,
 * https://github.com/wolfcw/libfaketime/
 * (stopping time, speeding/slowing time).
 *
 * Environment Variables:
 * - SECONDS_OFFSET
 *     Adding or subtracting current seconds.
 *
 * Example Usage:
 *     LD_PRELOAD=libfake_date_time.so SECONDS_OFFSET=<int> <commands>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cerrno>
#include <cstdlib>
#include <dlfcn.h>
#include <string>
#include <sys/timeb.h>
#include <time.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <cros-camera/export.h>

typedef time_t (*TimeFunc)(time_t*);
typedef int (*FTimeFunc)(struct timeb*);
typedef int (*GetTimeOfDayFunc)(struct timeval*, struct timezone*);
typedef int (*ClockGetTimeFunc)(clockid_t clk_id, struct timespec* tp);

static const char kEnvSecondsOffset[] = "SECONDS_OFFSET";
static const clockid_t kOverriddenClockIds[] = {
    CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_REALTIME_ALARM, CLOCK_TAI};

static void* LoadLibCFunction(const char* name) {
  void* result = dlsym(RTLD_NEXT, name);
  CHECK_NE(result, nullptr) << "Error in `dlsym`: " << dlerror();
  return result;
}

// ParseTime returns 0 if there is any error in the parsing process
static time_t ParseTime(const char* str) {
  int64_t ret;
  if (!base::StringToInt64(str, &ret)) {
    return 0;
  }
  return ret;
}

static time_t GetSecondsOffset() {
  static const time_t seconds_offset = []() {
    char* seconds_offset_env_value = std::getenv(kEnvSecondsOffset);
    if (seconds_offset_env_value == nullptr) {
      return 0L;
    } else {
      return ParseTime(seconds_offset_env_value);
    }
  }();
  return seconds_offset;
}

CROS_CAMERA_EXPORT
extern "C" time_t time(time_t* time_ptr) {
  static const TimeFunc real_time = []() {
    return reinterpret_cast<TimeFunc>(LoadLibCFunction("time"));
  }();
  if (time_ptr == nullptr) {
    time_t result;
    real_time(&result);
    time_ptr = &result;
  } else {
    real_time(time_ptr);
  }
  if ((*time_ptr) == (time_t)-1) {
    return *time_ptr;
  }
  (*time_ptr) += GetSecondsOffset();
  return *time_ptr;
}

CROS_CAMERA_EXPORT
extern "C" int gettimeofday(struct timeval* time_ptr, struct timezone* tz) {
  static const GetTimeOfDayFunc real_gettimeofday = []() {
    return reinterpret_cast<GetTimeOfDayFunc>(LoadLibCFunction("gettimeofday"));
  }();
  int ret = real_gettimeofday(time_ptr, tz);
  if (ret != 0) {
    return ret;
  }
  time_ptr->tv_sec += GetSecondsOffset();
  return ret;
}

CROS_CAMERA_EXPORT
extern "C" int ftime(struct timeb* tb_ptr) {
  static const FTimeFunc real_ftime = []() {
    return reinterpret_cast<FTimeFunc>(LoadLibCFunction("ftime"));
  }();
  int ret = real_ftime(tb_ptr);
  if (ret != 0) {
    return ret;
  }
  tb_ptr->time += GetSecondsOffset();
  return ret;
}

CROS_CAMERA_EXPORT
extern "C" int clock_gettime(clockid_t id, struct timespec* timespec_ptr) {
  static const ClockGetTimeFunc real_clock_gettime = []() {
    return reinterpret_cast<ClockGetTimeFunc>(
        LoadLibCFunction("clock_gettime"));
  }();
  int ret = real_clock_gettime(id, timespec_ptr);
  if (ret != 0) {
    return ret;
  }

  for (clockid_t clock_id : kOverriddenClockIds) {
    if (id == clock_id) {
      timespec_ptr->tv_sec += GetSecondsOffset();
      break;
    }
  }
  return ret;
}
