// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_POWER_EVENT_OBSERVER_H_
#define BIOD_POWER_EVENT_OBSERVER_H_

#include "base/observer_list_types.h"

namespace biod {

// Interface for observing signals from the power manager client.
class PowerEventObserver : public base::CheckedObserver {
 public:
  PowerEventObserver() = default;
  PowerEventObserver(const PowerEventObserver&) = delete;
  PowerEventObserver& operator=(const PowerEventObserver&) = delete;

  virtual ~PowerEventObserver() = default;

  // Called when power button is pressed or released.
  virtual void PowerButtonEventReceived(bool down,
                                        const base::TimeTicks& timestamp) = 0;
};

}  // namespace biod

#endif  // BIOD_POWER_EVENT_OBSERVER_H_
