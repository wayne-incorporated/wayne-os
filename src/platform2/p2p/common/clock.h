// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_COMMON_CLOCK_H_
#define P2P_COMMON_CLOCK_H_

#include "p2p/common/clock_interface.h"

namespace p2p {

namespace common {

class Clock : public ClockInterface {
 public:
  Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;

  void Sleep(const base::TimeDelta& duration) override;

  base::Time GetMonotonicTime() override;
};

}  // namespace common

}  // namespace p2p

#endif  // P2P_COMMON_CLOCK_H_
