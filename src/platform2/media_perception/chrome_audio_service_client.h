// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_CHROME_AUDIO_SERVICE_CLIENT_H_
#define MEDIA_PERCEPTION_CHROME_AUDIO_SERVICE_CLIENT_H_

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace mri {

using SerializedAudioStreamParams = std::vector<uint8_t>;
using SerializedAudioDevice = std::vector<uint8_t>;

// The implementation of the ChromeAudioServiceClient is thread-safe and can be
// shared between multiple clients.
class ChromeAudioServiceClient {
 public:
  // Handler for incoming audio frames.
  using AudioFrameHandler =
      std::function<void(const uint8_t* samples, int size)>;

  virtual ~ChromeAudioServiceClient() {}

  // Connects to CrAS. Does nothing if we are already connected.
  virtual bool Connect() = 0;

  // Check if the service is connected.
  virtual bool IsConnected() = 0;

  virtual std::vector<SerializedAudioDevice> GetInputDevices() = 0;

  // Determines if a particular device has already started capture and if it
  // has, fills in the |capture_format| with the current parameters used to
  // read frames from the device.
  virtual bool IsAudioCaptureStartedForDevice(
      const std::string& device_id,
      SerializedAudioStreamParams* capture_format) = 0;

  // Add a frame handler for a particular device id. Return value is the handler
  // id, which is globally unique for a single device. Note that multiple
  // clients can add a frame handler for a single device. AddFrameHandler will
  // start audio capture on a device if it is not already started. If the
  // |capture_format| matches the current format, in the case that audio capture
  // is already started, then the frame handler will be successfully added. An
  // return value of 0 indicates a failure to add the handler or start audio
  // capture.
  virtual int AddFrameHandler(const std::string& device_id,
                              const SerializedAudioStreamParams& capture_format,
                              AudioFrameHandler handler) = 0;

  // Remove a frame handler for a particular device by specifying the frame
  // handler id. Audio capture on a particular device will only stop when all
  // frame handlers are removed for a particular device.
  virtual bool RemoveFrameHandler(const std::string& device_id,
                                  int frame_handler_id) = 0;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_CHROME_AUDIO_SERVICE_CLIENT_H_
