// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/local_service.h"

#include <base/strings/string_number_conversions.h>

#include "shill/logging.h"
#include "shill/wifi/local_device.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kService;
}  // namespace Logging

// static
unsigned int LocalService::next_serial_number_ = 0;

LocalService::LocalService(LocalDeviceConstRefPtr device)
    : device_(device),
      state_(LocalServiceState::kStateIdle),
      serial_number_(next_serial_number_++) {
  // Provide a default name.
  log_name_ = "local_service_" + base::NumberToString(serial_number_);
}

LocalService::~LocalService() = default;

// static
const char* LocalService::StateToString(const LocalServiceState& state) {
  switch (state) {
    case LocalServiceState::kStateIdle:
      return "Idle";
    case LocalServiceState::kStateStarting:
      return "Starting";
    case LocalServiceState::kStateUp:
      return "Up";
  }
  return "Invalid";
}

void LocalService::SetState(LocalServiceState state) {
  if (state == state_) {
    return;
  }

  SLOG(1) << log_name() << ": Local service state " << StateToString(state_)
          << " -> " << StateToString(state);

  auto prev_state = state_;
  state_ = state;

  if (IsUpState(prev_state)) {
    // Service changed from connect state to other non-connect state.
    device_->PostDeviceEvent(LocalDevice::DeviceEvent::kServiceDown);
  } else if (IsUpState(state)) {
    // Service changed from non-connect state to connect state.
    device_->PostDeviceEvent(LocalDevice::DeviceEvent::kServiceUp);
  }
}

// static
bool LocalService::IsUpState(LocalServiceState state) {
  return state == LocalServiceState::kStateUp;
}

bool LocalService::IsUp() const {
  return IsUpState(state());
}

}  // namespace shill
