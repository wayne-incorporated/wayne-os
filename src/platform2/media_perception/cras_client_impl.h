// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_CRAS_CLIENT_IMPL_H_
#define MEDIA_PERCEPTION_CRAS_CLIENT_IMPL_H_

#include <cras_client.h>
#include <cras_helpers.h>
#include <cras_types.h>
#include <cras_util.h>
#include <stdint.h>
#include <stdio.h>
#include <string>

#include "media_perception/cras_client_wrapper.h"

namespace mri {

// A wrapper class that encapsulates methods used for interacting with Chrome
// audio service on ChromeOS devices. This class is not thread safe and so it
// should not be accessed from multiple threads.
class CrasClientImpl : public CrasClientWrapper {
 public:
  CrasClientImpl()
      : client_(nullptr),
        audio_format_(nullptr),
        audio_capture_params_(nullptr),
        has_audio_capture_started_(false) {}

  ~CrasClientImpl() override;

  // Connects to CrAS server.
  bool Connect() override;

  // Disconnects from CrAS server.
  void Disconnect() override;

  // Checks if it has been connected to CrAS server.
  bool IsConnected() const override;

  // Starts audio capture. Return value indicates success or failure.
  bool StartAudioCapture() override;

  // Stops audio capture.
  void StopAudioCapture() override;

  // Checks if audio capture has been started.
  bool HasAudioCaptureStarted() const override;

  // Sets parameters for audio capture. Return value indicates success or
  // failure.
  bool SetParams(const std::string& device_name,
                 unsigned int num_channels,
                 unsigned int block_size,
                 unsigned int frame_rate,
                 snd_pcm_format_t format) override;

  // Callback when getting a new audio frame.
  void ProcessAudioSamples(const uint8_t* samples, unsigned int num_samples);

 private:
  // Destructs audio_format_ and audio_capture_params_;
  void DestroyParams();

  // Destructs client_;
  void DestroyClient();

  struct cras_client* client_;
  struct cras_audio_format* audio_format_;
  struct cras_stream_params* audio_capture_params_;
  bool has_audio_capture_started_;
  std::string device_name_;
  cras_stream_id_t stream_id_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_CRAS_CLIENT_IMPL_H_
