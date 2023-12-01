// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/chrome_audio_service_client_impl.h"

#include <utility>

#include "base/logging.h"
#include "media_perception/device_management.pb.h"
#include "media_perception/proto_mojom_conversion.h"
#include "media_perception/serialized_proto.h"

namespace mri {

namespace {

// Max number of devices to probe.
const size_t MAX_IODEVS = 10;

// Max number of nodes to probe.
const size_t MAX_IONODES = 20;

}  // namespace

bool ChromeAudioServiceClientImpl::Connect() {
  if (IsConnected()) {
    LOG(INFO) << "Client is already connected.";
    return true;
  }

  base::AutoLock auto_lock(client_lock_);
  // cras_helper_create_connect returns 0 on success, or a negative error code
  // on failure.
  int rc = cras_helper_create_connect(&client_);
  if (rc < 0) {
    LOG(ERROR) << "Failed to connect to CrAS server with error code: " << rc;
    DestroyClient();
    return false;
  }
  return true;
}

void ChromeAudioServiceClientImpl::DestroyClient() {
  base::AutoLock auto_lock(client_lock_);
  if (client_) {
    cras_client_destroy(client_);
    client_ = nullptr;
  }
}

ChromeAudioServiceClientImpl::~ChromeAudioServiceClientImpl() {
  DestroyClient();
}

bool ChromeAudioServiceClientImpl::IsConnected() {
  base::AutoLock auto_lock(client_lock_);
  return client_ != nullptr;
}

std::vector<SerializedAudioDevice>
ChromeAudioServiceClientImpl::GetInputDevices() {
  std::vector<SerializedAudioDevice> serialized_audio_devices;
  if (!IsConnected()) {
    LOG(WARNING) << "CrAS client is not connected. "
                 << "Must Connect() to query devices.";
    return serialized_audio_devices;
  }

  struct cras_iodev_info devs[MAX_IODEVS];
  struct cras_ionode_info nodes[MAX_IONODES];
  size_t num_devs = MAX_IODEVS;
  size_t num_nodes = MAX_IONODES;

  base::AutoLock auto_lock(client_lock_);
  // Get the current list of input devices. Return 0 on success, -EINVAL if the
  // client isn't valid or isn't running.
  int rc = cras_client_get_input_devices(client_, devs, nodes, &num_devs,
                                         &num_nodes);
  if (rc != 0) {
    LOG(ERROR) << "Failed to query audio input devices with error code: " << rc;
    return serialized_audio_devices;
  }

  LOG(INFO) << "Got devices from CrAS.";

  // Loop through the result and create the necessary AudioDevice protos.
  for (int i = 0; i < num_devs; i++) {
    if (std::string(devs[i].name).empty()) {
      continue;
    }
    AudioDevice audio_device;
    audio_device.set_id(std::to_string(devs[i].stable_id));
    audio_device.set_display_name(std::string(devs[i].name));
    serialized_audio_devices.push_back(
        Serialized<AudioDevice>(audio_device).GetBytes());

    // Add the stable device id to the audio receivers map if it does not exist.
    if (device_id_to_audio_receiver_map_.find(audio_device.id()) ==
        device_id_to_audio_receiver_map_.end()) {
      device_id_to_audio_receiver_map_.emplace(
          audio_device.id(), AudioReceiver(audio_device.id()));
    }
  }
  return serialized_audio_devices;
}

bool ChromeAudioServiceClientImpl::IsAudioCaptureStartedForDevice(
    const std::string& device_id, SerializedAudioStreamParams* capture_format) {
  base::AutoLock auto_lock(client_lock_);
  std::map<std::string, AudioReceiver>::iterator it =
      device_id_to_audio_receiver_map_.find(device_id);
  if (it == device_id_to_audio_receiver_map_.end()) {
    LOG(WARNING) << "Device id not found in map.";
    return false;
  }

  if (it->second.GetFrameHandlerCount() == 0) {
    return false;
  }

  *capture_format =
      Serialized<AudioStreamParams>(it->second.GetAudioStreamParams())
          .GetBytes();
  return true;
}

int ChromeAudioServiceClientImpl::AddFrameHandler(
    const std::string& device_id,
    const SerializedAudioStreamParams& capture_format,
    AudioFrameHandler handler) {
  AudioStreamParams params =
      Serialized<AudioStreamParams>(capture_format).Deserialize();

  base::AutoLock auto_lock(client_lock_);
  std::map<std::string, AudioReceiver>::iterator receiver_it =
      device_id_to_audio_receiver_map_.find(device_id);
  if (receiver_it == device_id_to_audio_receiver_map_.end()) {
    LOG(WARNING) << "Device id not found in map.";
    return 0;
  }

  // If the internal handler map already has a frame handler, then we need to
  // compare the requested params with the params saved for the device.
  if (receiver_it->second.GetFrameHandlerCount() > 0 &&
      !receiver_it->second.CaptureFormatMatches(params)) {
    LOG(WARNING)
        << "Capture formats do not match for device already streaming.";
    return 0;
  } else if (receiver_it->second.GetFrameHandlerCount() == 0) {
    // Start streaming audio for this device since it not started.
    struct cras_iodev_info devs[MAX_IODEVS];
    struct cras_ionode_info nodes[MAX_IONODES];
    size_t num_devs = MAX_IODEVS;
    size_t num_nodes = MAX_IONODES;

    // Get the current list of input devices. Return 0 on success, -EINVAL if
    // the client isn't valid or isn't running.
    int rc = cras_client_get_input_devices(client_, devs, nodes, &num_devs,
                                           &num_nodes);
    if (rc != 0) {
      LOG(ERROR) << "Failed to query audio input devices with error code: "
                 << rc;
      return 0;
    }

    int dev_idx = NO_DEVICE;
    bool found_matched_device = false;
    for (int i = 0; i < num_devs; i++) {
      if (std::to_string(devs[i].stable_id) == device_id) {
        LOG(INFO) << "Found audio device with stable id: " << device_id;
        found_matched_device = true;
        dev_idx = devs[i].idx;
      }
    }

    if (!found_matched_device) {
      LOG(WARNING) << "Failed to find a matched audio device for id: "
                   << device_id;
      return 0;
    }

    if (!receiver_it->second.SetAudioStreamParams(params)) {
      LOG(ERROR) << "Failed to set the audio stream params.";
      return 0;
    }

    // Use the dev_idx to start audio capture.
    if (!receiver_it->second.StartAudioCaptureForDeviceIdx(client_, dev_idx)) {
      LOG(ERROR) << "Failed to start audio capture.";
      return 0;
    }
  }

  // Store the audio stream parameters for this device.
  return receiver_it->second.AddAudioFrameHandler(std::move(handler));
}

bool ChromeAudioServiceClientImpl::RemoveFrameHandler(
    const std::string& device_id, int frame_handler_id) {
  base::AutoLock auto_lock(client_lock_);
  std::map<std::string, AudioReceiver>::iterator it =
      device_id_to_audio_receiver_map_.find(device_id);
  if (it == device_id_to_audio_receiver_map_.end()) {
    LOG(WARNING) << "Device id not found in map.";
    return false;
  }

  bool success = it->second.RemoveFrameHandler(frame_handler_id);
  if (success && it->second.GetFrameHandlerCount() == 0) {
    it->second.StopAudioCapture(client_);
  }
  return success;
}

}  // namespace mri
