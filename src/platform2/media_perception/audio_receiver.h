// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_AUDIO_RECEIVER_H_
#define MEDIA_PERCEPTION_AUDIO_RECEIVER_H_

#include <cras_client.h>
#include <cras_helpers.h>
#include <cras_types.h>
#include <cras_util.h>
#include <map>
#include <stdint.h>
#include <stdio.h>
#include <string>

#include "media_perception/chrome_audio_service_client.h"
#include "media_perception/device_management.pb.h"

namespace mri {

// Handles interaction with a single audio device and piping outputs to the
// registered handlers. By itself, this class is not thread safe.
class AudioReceiver {
 public:
  explicit AudioReceiver(const std::string& device_id);

  ~AudioReceiver() { DestroyParams(); }

  // Returns true if the |requested| params match the current |params_|.
  bool CaptureFormatMatches(const AudioStreamParams& requested);

  // Returns the size of the frame handler map.
  int GetFrameHandlerCount();

  // Sets the audio stream |params_| on the AudioReceiver.
  bool SetAudioStreamParams(const AudioStreamParams& params);

  AudioStreamParams GetAudioStreamParams();

  // Attempts to start audio capture.
  bool StartAudioCaptureForDeviceIdx(struct cras_client* client, int dev_idx);

  // Adds an audio frame handler into the frame handler map. Return value is the
  // frame handler id.
  int AddAudioFrameHandler(ChromeAudioServiceClient::AudioFrameHandler handler);

  // Callback when getting a new audio frame.
  void ProcessAudioSamples(const uint8_t* samples, unsigned int num_samples);

  // Attempts to remove a frame handler based on id value. Return value
  // indicates success or failure.
  bool RemoveFrameHandler(int frame_handler_id);

  void StopAudioCapture(struct cras_client* client);

 private:
  void DestroyParams();

  // Keeps track of the current capture parameters for an audio device.
  AudioStreamParams params_;

  // Cras structures managed by the AudioReceiver class.
  struct cras_audio_format* audio_format_;
  struct cras_stream_params* audio_capture_params_;
  cras_stream_id_t stream_id_;

  // The device id associated with this device.
  std::string device_id_;

  // Keeps a counter to ensure that each frame handler has a unique id.
  int frame_handler_counter_;

  // Stores a map of frame handler ids to AudioFrameHandlers.
  std::map<int /* frame_handler_id */,
           ChromeAudioServiceClient::AudioFrameHandler>
      frame_handler_id_to_audio_frame_handler_map_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_AUDIO_RECEIVER_H_
