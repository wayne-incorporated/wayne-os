// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/cras_client_impl.h"

#include <syslog.h>

namespace {
// Max number of devices to probe.
const size_t MAX_IODEVS = 10;

// Max number of nodes to probe.
const size_t MAX_IONODES = 20;

// Callback when getting a new audio frame.
int OnAudioSamples(struct cras_client* client,
                   cras_stream_id_t stream_id,
                   uint8_t* captured_samples,
                   uint8_t* playback_samples,
                   unsigned int num_samples,
                   const struct timespec* captured_time,
                   const struct timespec* playback_time,
                   void* user_arg) {
  mri::CrasClientImpl* cras_client = (mri::CrasClientImpl*)user_arg;
  cras_client->ProcessAudioSamples(captured_samples, num_samples);
  return num_samples;
}

// Callback when getting audio capture error.
int OnAudioCaptureError(struct cras_client* client,
                        cras_stream_id_t stream_id,
                        int err,
                        void* arg) {
  syslog(LOG_ERR, "Audio capture error with code: %d.", err);
  return err;
}

}  // namespace

namespace mri {

CrasClientImpl::~CrasClientImpl() {
  Disconnect();
}

bool CrasClientImpl::Connect() {
  if (IsConnected()) {
    syslog(LOG_WARNING, "Client is already connected to CrAS server.");
    return true;
  }

  // Create and connect a client to the CrAS server. cras_helper_create_connect
  // returns 0 on success, or a negative error code on failure.
  int rc = cras_helper_create_connect(&client_);
  if (rc < 0) {
    syslog(LOG_ERR, "Failed to connect to CrAS server with error code: %d.",
           rc);
    DestroyClient();
    return false;
  }

  return true;
}

void CrasClientImpl::Disconnect() {
  StopAudioCapture();
  DestroyParams();
  DestroyClient();
}

bool CrasClientImpl::IsConnected() const {
  return client_ != nullptr;
}

bool CrasClientImpl::SetParams(const std::string& device_name,
                               unsigned int num_channels,
                               unsigned int block_size,
                               unsigned int frame_rate,
                               snd_pcm_format_t format) {
  DestroyParams();

  audio_format_ = cras_audio_format_create(format, frame_rate, num_channels);
  if (!audio_format_) {
    syslog(LOG_ERR, "Failed to create CrAS audio format.");
    DestroyParams();
    return false;
  }

  audio_capture_params_ = cras_client_unified_params_create(
      CRAS_STREAM_INPUT, block_size, CRAS_STREAM_TYPE_DEFAULT, 0, this,
      OnAudioSamples, OnAudioCaptureError, audio_format_);
  if (!audio_capture_params_) {
    syslog(LOG_ERR, "Failed to create CrAS audio capture format.");
    DestroyParams();
    return false;
  }

  device_name_ = device_name;
  return true;
}

bool CrasClientImpl::StartAudioCapture() {
  if (!IsConnected()) {
    return false;
  }

  if (HasAudioCaptureStarted()) {
    return true;
  }

  struct cras_iodev_info devs[MAX_IODEVS];
  struct cras_ionode_info nodes[MAX_IONODES];
  size_t num_devs = MAX_IODEVS;
  size_t num_nodes = MAX_IONODES;

  // Get the current list of input devices. Return 0 on success, -EINVAL if the
  // client isn't valid or isn't running.
  int rc = cras_client_get_input_devices(client_, devs, nodes, &num_devs,
                                         &num_nodes);
  if (rc != 0) {
    syslog(LOG_ERR, "Failed to query audio input devices.");
    return false;
  }

  // Search for the device that matches the given name.
  int dev_idx = NO_DEVICE;
  bool found_matched_device = false;
  for (int i = 0; !device_name_.empty() && i < num_devs; i++) {
    if (std::string(devs[i].name).find(device_name_) != std::string::npos) {
      dev_idx = devs[i].idx;
      syslog(LOG_INFO, "Found audio device: ID=%u, name=%s.", devs[i].idx,
             devs[i].name);
      found_matched_device = true;
      break;
    }
  }

  if (!device_name_.empty() && !found_matched_device) {
    syslog(LOG_ERR, "Failed to find matched audio input device: %s.",
           device_name_.c_str());
    return false;
  }

  // Create a pinned stream. Return 0 on success, or negative error code on
  // failure.
  cras_stream_id_t stream_id;
  rc = cras_client_add_pinned_stream(client_, dev_idx, &stream_id,
                                     audio_capture_params_);
  if (rc != 0) {
    syslog(LOG_ERR, "Failed to add pinned stream with error code: %d.", rc);
    return false;
  }

  has_audio_capture_started_ = true;
  return true;
}

void CrasClientImpl::StopAudioCapture() {
  if (IsConnected() && HasAudioCaptureStarted()) {
    cras_client_rm_stream(client_, stream_id_);
    has_audio_capture_started_ = false;
  }
}

bool CrasClientImpl::HasAudioCaptureStarted() const {
  return has_audio_capture_started_;
}

void CrasClientImpl::ProcessAudioSamples(const uint8_t* samples,
                                         unsigned int num_frames) {
  if (!audio_input_handler_) {
    return;
  }

  const int bytes_per_frame = cras_client_format_bytes_per_frame(audio_format_);
  const int total_bytes = bytes_per_frame * num_frames;
  audio_input_handler_(samples, total_bytes);
}

void CrasClientImpl::DestroyParams() {
  if (audio_format_) {
    cras_audio_format_destroy(audio_format_);
    audio_format_ = nullptr;
  }

  if (audio_capture_params_) {
    cras_client_stream_params_destroy(audio_capture_params_);
    audio_capture_params_ = nullptr;
  }
}

void CrasClientImpl::DestroyClient() {
  if (client_) {
    cras_client_destroy(client_);
    client_ = nullptr;
  }
}

}  // namespace mri
