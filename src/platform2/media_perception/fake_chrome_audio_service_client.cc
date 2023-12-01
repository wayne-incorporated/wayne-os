// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/fake_chrome_audio_service_client.h"

namespace mri {

bool FakeChromeAudioServiceClient::Connect() {
  connected_ = true;
  return connected_;
}

bool FakeChromeAudioServiceClient::IsConnected() {
  return connected_;
}

void FakeChromeAudioServiceClient::SetDevicesForGetInputDevices(
    std::vector<SerializedAudioDevice> devices) {
  devices_ = devices;
}

std::vector<SerializedAudioDevice>
FakeChromeAudioServiceClient::GetInputDevices() {
  return devices_;
}

bool FakeChromeAudioServiceClient::IsAudioCaptureStartedForDevice(
    const std::string& device_id, SerializedAudioStreamParams* capture_format) {
  return false;
}

int FakeChromeAudioServiceClient::AddFrameHandler(
    const std::string& device_id,
    const SerializedAudioStreamParams& capture_format,
    AudioFrameHandler handler) {
  return 0;
}

bool FakeChromeAudioServiceClient::RemoveFrameHandler(
    const std::string& device_id, int frame_handler_id) {
  return false;
}

}  // namespace mri
