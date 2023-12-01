/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/camera_hal_device_ops.h"

#include "cros-camera/common.h"
#include "hal/usb/camera_client.h"

namespace cros {

// Get handle to camera from device priv data
static CameraClient* camdev_to_camera(const camera3_device_t* dev) {
  return reinterpret_cast<CameraClient*>(dev->priv);
}

static int initialize(const camera3_device_t* dev,
                      const camera3_callback_ops_t* callback_ops) {
  CameraClient* client = camdev_to_camera(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return client->Initialize(callback_ops);
}

static int configure_streams(const camera3_device_t* dev,
                             camera3_stream_configuration_t* stream_list) {
  CameraClient* client = camdev_to_camera(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return client->ConfigureStreams(stream_list);
}

static const camera_metadata_t* construct_default_request_settings(
    const camera3_device_t* dev, int type) {
  CameraClient* client = camdev_to_camera(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return NULL;
  }
  return client->ConstructDefaultRequestSettings(type);
}

static int process_capture_request(const camera3_device_t* dev,
                                   camera3_capture_request_t* request) {
  CameraClient* client = camdev_to_camera(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return client->ProcessCaptureRequest(request);
}

static void dump(const camera3_device_t* dev, int fd) {
  CameraClient* client = camdev_to_camera(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return;
  }
  client->Dump(fd);
}

static int flush(const camera3_device_t* dev) {
  CameraClient* client = camdev_to_camera(dev);
  if (!client) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return client->Flush(dev);
}

camera3_device_ops_t g_camera_device_ops = {
    .initialize = cros::initialize,
    .configure_streams = cros::configure_streams,
    .register_stream_buffers = NULL,
    .construct_default_request_settings =
        cros::construct_default_request_settings,
    .process_capture_request = cros::process_capture_request,
    .get_metadata_vendor_tag_ops = NULL,
    .dump = cros::dump,
    .flush = cros::flush,
    .reserved = {0},
};

}  // namespace cros
