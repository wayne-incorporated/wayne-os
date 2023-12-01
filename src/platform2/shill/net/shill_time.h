// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_SHILL_TIME_H_
#define SHILL_NET_SHILL_TIME_H_

#include <sys/time.h>
#include <time.h>

#include <string>

#include <base/no_destructor.h>

#include "shill/net/shill_export.h"

namespace shill {

// Timestamp encapsulates a |monotonic| and a |boottime| clock that can be used
// to compare the relative order and distance of events as well as a
// |wall_clock| time that can be used for presenting the time in human-readable
// format. Note that the monotonic clock does not necessarily advance during
// suspend, while boottime clock does include any time that the system is
// suspended.
struct SHILL_EXPORT Timestamp {
  Timestamp() : monotonic{} {}
  Timestamp(const struct timeval& in_monotonic,
            const struct timeval& in_boottime,
            const std::string& in_wall_clock)
      : monotonic(in_monotonic),
        boottime(in_boottime),
        wall_clock(in_wall_clock) {}

  struct timeval monotonic;
  struct timeval boottime;
  std::string wall_clock;
};

// A "sys/time.h" abstraction allowing mocking in tests.
class SHILL_EXPORT Time {
 public:
  virtual ~Time();

  static Time* GetInstance();

  // Returns CLOCK_MONOTONIC time, or 0 if a failure occurred.
  virtual bool GetSecondsMonotonic(time_t* seconds);

  // Sets |usecs| to CLOCK_MONOTONIC, in microseconds.
  virtual bool GetMicroSecondsMonotonic(int64_t* usecs);

  // Returns CLOCK_BOOTTIME time, or 0 if a failure occurred.
  virtual bool GetSecondsBoottime(time_t* seconds);

  // On success, sets |tv| to CLOCK_MONOTONIC time, and returns 0.
  virtual int GetTimeMonotonic(struct timeval* tv);

  // On success, sets |tv| to CLOCK_BOOTTIME time, and returns 0.
  virtual int GetTimeBoottime(struct timeval* tv);

  // gettimeofday
  virtual int GetTimeOfDay(struct timeval* tv, struct timezone* tz);

  // Returns a snapshot of the current time.
  virtual Timestamp GetNow();

  virtual time_t GetSecondsSinceEpoch() const;

  static std::string FormatTime(const struct tm& date_time, suseconds_t usec);

  static int64_t ConvertTimespecToMicros(const struct timespec& ts);

 protected:
  Time();
  Time(const Time&) = delete;
  Time& operator=(const Time&) = delete;

 private:
  friend class base::NoDestructor<Time>;
};

}  // namespace shill

#endif  // SHILL_NET_SHILL_TIME_H_
