// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_WAKEUP_SOURCE_IDENTIFIER_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_WAKEUP_SOURCE_IDENTIFIER_STUB_H_

#include "power_manager/powerd/system/wakeup_source_identifier_interface.h"

namespace power_manager::system {

class WakeupSourceIdentifierStub : public WakeupSourceIdentifierInterface {
 public:
  WakeupSourceIdentifierStub();
  WakeupSourceIdentifierStub(const WakeupSourceIdentifierStub&) = delete;
  WakeupSourceIdentifierStub& operator=(const WakeupSourceIdentifierStub&) =
      delete;

  ~WakeupSourceIdentifierStub() override;

  void PrepareForSuspendRequest() override;

  void HandleResume() override;

  bool InputDeviceCausedLastWake() const override;

  void SetInputDeviceCausedLastWake(bool input_device_caused_last_wake);

 private:
  bool input_device_caused_last_wake_ = false;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_WAKEUP_SOURCE_IDENTIFIER_STUB_H_
