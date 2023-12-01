// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/audio_receiver.h"

#include <alsa/asoundlib.h>
#include <utility>

#include "base/logging.h"

namespace mri {

namespace {

// Callback when getting a new audio frame.
int OnAudioSamples(struct cras_client* client,
                   cras_stream_id_t stream_id,
                   uint8_t* captured_samples,
                   uint8_t* playback_samples,
                   unsigned int num_samples,
                   const struct timespec* captured_time,
                   const struct timespec* playback_time,
                   void* user_arg) {
  mri::AudioReceiver* audio_receiver = (mri::AudioReceiver*)user_arg;
  audio_receiver->ProcessAudioSamples(captured_samples, num_samples);
  return num_samples;
}

// Callback when getting audio capture error.
int OnAudioCaptureError(struct cras_client* client,
                        cras_stream_id_t stream_id,
                        int err,
                        void* arg) {
  LOG(ERROR) << "Audio capture error with code: " << err;
  return err;
}

}  // namespace

void AudioReceiver::ProcessAudioSamples(const uint8_t* samples,
                                        unsigned int num_frames) {
  const int bytes_per_frame = cras_client_format_bytes_per_frame(audio_format_);
  const int total_bytes = bytes_per_frame * num_frames;
  for (auto& handler_pair : frame_handler_id_to_audio_frame_handler_map_) {
    handler_pair.second(samples, total_bytes);
  }
}

AudioReceiver::AudioReceiver(const std::string& device_id)
    : device_id_(device_id), frame_handler_counter_(0) {}

bool AudioReceiver::CaptureFormatMatches(const AudioStreamParams& requested) {
  return params_.frequency_in_hz() == requested.frequency_in_hz() &&
         params_.num_channels() == requested.num_channels() &&
         params_.frame_size() == requested.frame_size() &&
         params_.sample_format() == requested.sample_format();
}

int AudioReceiver::GetFrameHandlerCount() {
  return frame_handler_id_to_audio_frame_handler_map_.size();
}

bool AudioReceiver::SetAudioStreamParams(const AudioStreamParams& params) {
  DestroyParams();

  snd_pcm_format_t sample_format;
  switch (params.sample_format()) {
    case SampleFormat::SND_PCM_FORMAT_S32_LE:
      sample_format = ::SND_PCM_FORMAT_S32_LE;
      break;
    case SampleFormat::SND_PCM_FORMAT_S16_LE:
      sample_format = ::SND_PCM_FORMAT_S16_LE;
      break;
    default:
      LOG(ERROR) << "Sample format unknown or not supported.";
      return false;
  }

  audio_format_ = cras_audio_format_create(
      sample_format, params.frequency_in_hz(), params.num_channels());
  if (!audio_format_) {
    LOG(ERROR) << "Failed to create CrAS audio format.";
    DestroyParams();
    return false;
  }

  audio_capture_params_ = cras_client_unified_params_create(
      CRAS_STREAM_INPUT, params.frame_size(), CRAS_STREAM_TYPE_DEFAULT, 0, this,
      OnAudioSamples, OnAudioCaptureError, audio_format_);
  if (!audio_capture_params_) {
    LOG(ERROR) << "Failed to create CrAS audio capture format.";
    DestroyParams();
    return false;
  }

  params_ = params;
  return true;
}

AudioStreamParams AudioReceiver::GetAudioStreamParams() {
  return params_;
}

bool AudioReceiver::StartAudioCaptureForDeviceIdx(struct cras_client* client,
                                                  int dev_idx) {
  // Create a pinned stream. Return 0 on success, or negative error code on
  // failure.
  int rc = cras_client_add_pinned_stream(client, dev_idx, &stream_id_,
                                         audio_capture_params_);
  if (rc != 0) {
    LOG(ERROR) << "Failed to add pinned stream with error code: " << rc;
    return false;
  }
  return true;
}

int AudioReceiver::AddAudioFrameHandler(
    ChromeAudioServiceClient::AudioFrameHandler handler) {
  frame_handler_counter_++;
  frame_handler_id_to_audio_frame_handler_map_[frame_handler_counter_] =
      std::move(handler);
  return frame_handler_counter_;
}

bool AudioReceiver::RemoveFrameHandler(int frame_handler_id) {
  if (frame_handler_id_to_audio_frame_handler_map_.find(frame_handler_id) ==
      frame_handler_id_to_audio_frame_handler_map_.end()) {
    // Frame handler not found.
    return false;
  }

  frame_handler_id_to_audio_frame_handler_map_.erase(frame_handler_id);
  return true;
}

void AudioReceiver::StopAudioCapture(struct cras_client* client) {
  cras_client_rm_stream(client, stream_id_);
}

void AudioReceiver::DestroyParams() {
  if (audio_format_) {
    cras_audio_format_destroy(audio_format_);
    audio_format_ = nullptr;
  }

  if (audio_capture_params_) {
    cras_client_stream_params_destroy(audio_capture_params_);
    audio_capture_params_ = nullptr;
  }
}

}  // namespace mri
