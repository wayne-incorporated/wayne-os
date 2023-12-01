/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/fake/camera_hal_device_ops.h"

#include "cros-camera/common.h"
#include "hal/fake/camera_client.h"

namespace cros {

namespace {

// Get handle to camera from device priv data.
CameraClient* deviceToClient(const camera3_device_t* dev) {
  return reinterpret_cast<CameraClient*>(dev->priv);
}

int initialize(const camera3_device_t* dev,
               const camera3_callback_ops_t* callback_ops) {
  CameraClient* client = deviceToClient(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return client->Initialize(callback_ops);
}

int configure_streams(const camera3_device_t* dev,
                      camera3_stream_configuration_t* stream_list) {
  CameraClient* client = deviceToClient(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return client->ConfigureStreams(stream_list);
}

const camera_metadata_t* construct_default_request_settings(
    const camera3_device_t* dev, int type) {
  CameraClient* client = deviceToClient(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return nullptr;
  }
  return client->ConstructDefaultRequestSettings(type);
}

int process_capture_request(const camera3_device_t* dev,
                            camera3_capture_request_t* request) {
  CameraClient* client = deviceToClient(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return client->ProcessCaptureRequest(request);
}

void dump(const camera3_device_t* dev, int fd) {
  CameraClient* client = deviceToClient(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return;
  }
  client->Dump(fd);
}

int flush(const camera3_device_t* dev) {
  CameraClient* client = deviceToClient(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return client->Flush(dev);
}

}  // namespace

camera3_device_ops_t g_camera_device_ops = {
    .initialize = initialize,
    .configure_streams = configure_streams,
    .register_stream_buffers = nullptr,
    .construct_default_request_settings = construct_default_request_settings,
    .process_capture_request = process_capture_request,
    .get_metadata_vendor_tag_ops = nullptr,
    .dump = dump,
    .flush = flush,
    .reserved = {},
};

}  // namespace cros
