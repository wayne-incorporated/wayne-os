// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_CHROME_AUDIO_SERVICE_CLIENT_IMPL_H_
#define MEDIA_PERCEPTION_CHROME_AUDIO_SERVICE_CLIENT_IMPL_H_

#include "media_perception/chrome_audio_service_client.h"

#include <base/synchronization/lock.h>
#include <cras_client.h>
#include <cras_helpers.h>
#include <cras_types.h>
#include <cras_util.h>
#include <map>
#include <string>
#include <vector>

#include "media_perception/audio_receiver.h"

namespace mri {

// This interface uses a lock to ensure that changes to data members is
// thread-safe.
class ChromeAudioServiceClientImpl : public ChromeAudioServiceClient {
 public:
  // ChromeAudioServiceClient:
  ~ChromeAudioServiceClientImpl() override;
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
  // Destructs client_;
  void DestroyClient();

  std::map<std::string /* device_id */, AudioReceiver>
      device_id_to_audio_receiver_map_;

  base::Lock client_lock_;
  struct cras_client* client_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_CHROME_AUDIO_SERVICE_CLIENT_IMPL_H_
