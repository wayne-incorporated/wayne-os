// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/wakeup_source_identifier_stub.h"

namespace power_manager {
namespace system {

WakeupSourceIdentifierStub::WakeupSourceIdentifierStub() = default;
WakeupSourceIdentifierStub::~WakeupSourceIdentifierStub() = default;

void WakeupSourceIdentifierStub::PrepareForSuspendRequest() {}

void WakeupSourceIdentifierStub::HandleResume() {}

bool WakeupSourceIdentifierStub::InputDeviceCausedLastWake() const {
  return input_device_caused_last_wake_;
}

void WakeupSourceIdentifierStub::SetInputDeviceCausedLastWake(
    bool input_device_caused_last_wake) {
  input_device_caused_last_wake_ = input_device_caused_last_wake;
}

};  // namespace system
}  // namespace power_manager
