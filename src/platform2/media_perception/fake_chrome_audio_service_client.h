// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_FAKE_CHROME_AUDIO_SERVICE_CLIENT_H_
#define MEDIA_PERCEPTION_FAKE_CHROME_AUDIO_SERVICE_CLIENT_H_

#include "media_perception/chrome_audio_service_client.h"

#include <string>
#include <vector>

namespace mri {

class FakeChromeAudioServiceClient : public ChromeAudioServiceClient {
 public:
  FakeChromeAudioServiceClient() = default;
  FakeChromeAudioServiceClient(const FakeChromeAudioServiceClient&) = delete;
  FakeChromeAudioServiceClient& operator=(const FakeChromeAudioServiceClient&) =
      delete;

  void SetDevicesForGetInputDevices(std::vector<SerializedAudioDevice> devices);

  // ChromeAudioServiceClient:
  bool Connect() override;
  bool IsConnected() override;
  std::vector<SerializedAudioDevice> GetInputDevices() override;
  bool IsAudioCaptureStartedForDevice(
      const std::string& device_id,
      SerializedAudioStreamParams* capture_format) override;
  int AddFrameHandler(const std::string& device_id,
                      const SerializedAudioStreamParams& capture_format,
                      AudioFrameHandler handler) override;
  bool RemoveFrameHandler(const std::string& device_id,
                          int frame_handler_id) override;

 private:
  std::vector<SerializedAudioDevice> devices_;
  bool connected_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_FAKE_CHROME_AUDIO_SERVICE_CLIENT_H_
