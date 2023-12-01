// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fake/fake_chromium_data_collector.h"

#include <utility>

namespace diagnostics {

namespace internal_mojom = ::ash::cros_healthd::internal::mojom;

FakeChromiumDataCollector::FakeChromiumDataCollector() : receiver_(this) {}

FakeChromiumDataCollector::~FakeChromiumDataCollector() = default;

void FakeChromiumDataCollector::GetTouchscreenDevices(
    GetTouchscreenDevicesCallback callback) {
  std::vector<internal_mojom::TouchscreenDevicePtr> res;
  for (const internal_mojom::TouchscreenDevicePtr& item :
       touchscreen_devices_) {
    res.push_back(item.Clone());
  }
  std::move(callback).Run(std::move(res));
}

void FakeChromiumDataCollector::GetTouchpadLibraryName(
    GetTouchpadLibraryNameCallback callback) {
  std::move(callback).Run(touchpad_library_name_);
}

void FakeChromiumDataCollector::SetPrivacyScreenState(
    bool target_state, SetPrivacyScreenStateCallback callback) {
  if (!privacy_screen_request_processed_.has_value()) {
    // Browser does not response.
    return;
  }

  if (on_receive_privacy_screen_set_request_.has_value()) {
    std::move(on_receive_privacy_screen_set_request_.value()).Run();
  }
  std::move(callback).Run(privacy_screen_request_processed_.value());
}

void FakeChromiumDataCollector::SetAudioOutputMute(
    bool mute_on, SetAudioOutputMuteCallback callback) {
  std::move(callback).Run(audio_output_mute_request_result_);
}

}  // namespace diagnostics
