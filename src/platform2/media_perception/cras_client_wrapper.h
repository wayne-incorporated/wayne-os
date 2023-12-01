// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_CRAS_CLIENT_WRAPPER_H_
#define MEDIA_PERCEPTION_CRAS_CLIENT_WRAPPER_H_

#include <alsa/asoundlib.h>
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace mri {

// This class provides a generic base class for encapsulating methods used for
// interacting with Chrome audio service on ChromeOS devices.
class CrasClientWrapper {
 public:
  // Handler for incoming audio samples.
  using AudioInputHandler =
      std::function<void(const uint8_t* samples, int size)>;

  // Pure virtuals for the interfaces that need to be available in the
  // implementation.
  virtual ~CrasClientWrapper() {}

  // Connects to CrAS server.
  virtual bool Connect() = 0;

  // Disconnects from CrAS server.
  virtual void Disconnect() = 0;

  // Checks if it has been connected to CrAS server.
  virtual bool IsConnected() const = 0;

  // Starts audio capture. Return value indicates success or failure.
  virtual bool StartAudioCapture() = 0;

  // Stops audio capture.
  virtual void StopAudioCapture() = 0;

  // Checks if audio capture has been started.
  virtual bool HasAudioCaptureStarted() const = 0;

  // Sets parameters for audio capture. Return value indicates success or
  // failure.
  virtual bool SetParams(const std::string& device_name,
                         unsigned int num_channels,
                         unsigned int block_size,
                         unsigned int frame_rate,
                         snd_pcm_format_t format) = 0;

  // Sets handler for processing audio samples.
  void SetAudioInputHandler(AudioInputHandler handler) {
    audio_input_handler_ = std::move(handler);
  }

 protected:
  // Handler for processing audio samples.
  AudioInputHandler audio_input_handler_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_CRAS_CLIENT_WRAPPER_H_
