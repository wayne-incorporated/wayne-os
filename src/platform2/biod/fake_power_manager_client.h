// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_FAKE_POWER_MANAGER_CLIENT_H_
#define BIOD_FAKE_POWER_MANAGER_CLIENT_H_

#include "biod/power_manager_client_interface.h"

#include <base/time/time.h>
#include <base/observer_list.h>

namespace biod {

class FakePowerManagerClient : public PowerManagerClientInterface {
 public:
  FakePowerManagerClient() = default;
  FakePowerManagerClient(const FakePowerManagerClient&) = delete;
  FakePowerManagerClient& operator=(const FakePowerManagerClient&) = delete;

  ~FakePowerManagerClient() override = default;

  // Implement PowerManagerInterface.
  void AddObserver(PowerEventObserver* observer) override;
  bool HasObserver(PowerEventObserver* observer) override;
  void RemoveObserver(PowerEventObserver* observer) override;

  void GeneratePowerButtonEvent(bool down, base::TimeTicks timestamp);

 private:
  base::ObserverList<PowerEventObserver> observers_;
};

}  // namespace biod

#endif  // BIOD_FAKE_POWER_MANAGER_CLIENT_H_
