// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/fake_power_manager_client.h"

#include <base/check.h>

namespace biod {

void FakePowerManagerClient::AddObserver(PowerEventObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

bool FakePowerManagerClient::HasObserver(PowerEventObserver* observer) {
  DCHECK(observer);
  return observers_.HasObserver(observer);
}

void FakePowerManagerClient::RemoveObserver(PowerEventObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void FakePowerManagerClient::GeneratePowerButtonEvent(
    bool down, base::TimeTicks timestamp) {
  for (auto& observer : observers_)
    observer.PowerButtonEventReceived(down, timestamp);
}

}  // namespace biod
