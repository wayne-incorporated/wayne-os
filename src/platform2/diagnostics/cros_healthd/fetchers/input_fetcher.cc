// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/input_fetcher.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "diagnostics/cros_healthd/utils/callback_barrier.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/mojom/external/cros_healthd_internal.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;
namespace internal_mojom = ::ash::cros_healthd::internal::mojom;

mojom::InputDevice::ConnectionType Convert(
    internal_mojom::InputDevice::ConnectionType enum_value) {
  switch (enum_value) {
    case internal_mojom::InputDevice::ConnectionType::kUnmappedEnumField:
      return mojom::InputDevice::ConnectionType::kUnmappedEnumField;
    case internal_mojom::InputDevice::ConnectionType::kInternal:
      return mojom::InputDevice::ConnectionType::kInternal;
    case internal_mojom::InputDevice::ConnectionType::kUSB:
      return mojom::InputDevice::ConnectionType::kUSB;
    case internal_mojom::InputDevice::ConnectionType::kBluetooth:
      return mojom::InputDevice::ConnectionType::kBluetooth;
    case internal_mojom::InputDevice::ConnectionType::kUnknown:
      return mojom::InputDevice::ConnectionType::kUnknown;
  }
}

class State {
 public:
  State();
  State(const State&) = delete;
  State& operator=(const State&) = delete;
  ~State();

  void HandleTouchscreenDevice(
      std::vector<internal_mojom::TouchscreenDevicePtr> devices);

  void HandleTouchpadLibraryName(const std::string& library_name);

  void HandleResult(InputFetcher::ResultCallback callback, bool success);

 private:
  // The info to be returned.
  mojom::InputInfoPtr info_;
};

State::State() : info_(mojom::InputInfo::New()) {}

State::~State() = default;

void State::HandleTouchscreenDevice(
    std::vector<internal_mojom::TouchscreenDevicePtr> devices) {
  for (const internal_mojom::TouchscreenDevicePtr& device : devices) {
    const auto& input_device = device->input_device;
    auto out_input_device = mojom::InputDevice::New();
    out_input_device->name = input_device->name;
    out_input_device->connection_type = Convert(input_device->connection_type);
    out_input_device->physical_location = input_device->physical_location;
    out_input_device->is_enabled = input_device->is_enabled;

    auto out_device = mojom::TouchscreenDevice::New();
    out_device->input_device = std::move(out_input_device);
    out_device->touch_points = device->touch_points;
    out_device->has_stylus = device->has_stylus;
    out_device->has_stylus_garage_switch = device->has_stylus_garage_switch;

    info_->touchscreen_devices.push_back(std::move(out_device));
  }
}

void State::HandleTouchpadLibraryName(const std::string& library_name) {
  info_->touchpad_library_name = library_name;
}

void State::HandleResult(InputFetcher::ResultCallback callback, bool success) {
  if (success) {
    std::move(callback).Run(mojom::InputResult::NewInputInfo(std::move(info_)));
    return;
  }
  std::move(callback).Run(mojom::InputResult::NewError(
      CreateAndLogProbeError(mojom::ErrorType::kServiceUnavailable,
                             "Some async task cannot be finish.")));
}

}  // namespace

void InputFetcher::Fetch(ResultCallback callback) {
  auto state = std::make_unique<State>();
  State* state_ptr = state.get();
  CallbackBarrier barrier{base::BindOnce(&State::HandleResult, std::move(state),
                                         std::move(callback))};

  auto* collector = context_->mojo_service()->GetChromiumDataCollector();
  collector->GetTouchscreenDevices(barrier.Depend(base::BindOnce(
      &State::HandleTouchscreenDevice, base::Unretained(state_ptr))));
  collector->GetTouchpadLibraryName(barrier.Depend(base::BindOnce(
      &State::HandleTouchpadLibraryName, base::Unretained(state_ptr))));
}

}  // namespace diagnostics
