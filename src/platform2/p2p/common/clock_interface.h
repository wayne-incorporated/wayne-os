// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_COMMON_CLOCK_INTERFACE_H_
#define P2P_COMMON_CLOCK_INTERFACE_H_

#include <base/time/time.h>

namespace p2p {

namespace common {

// TODO(deymo): Move this class to libchromeos and merge it with the one in
// update_engine.

// The clock interface allows access to some system time-related functions.
class ClockInterface {
 public:
  // Suspends the execution of the calling thread for the time
  // indicated by |duration|.
  virtual void Sleep(const base::TimeDelta& duration) = 0;

  // Returns monotonic time since some unspecified starting point. It
  // is not increased when the system is sleeping nor is it affected
  // by NTP or the user changing the time.
  //
  // (This is a simple wrapper around clock_gettime(2) / CLOCK_MONOTONIC_RAW.)
  virtual base::Time GetMonotonicTime() = 0;

  virtual ~ClockInterface() = default;
};

}  // namespace common

}  // namespace p2p

#endif  // P2P_COMMON_CLOCK_INTERFACE_H_
