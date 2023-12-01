// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_CAMERA_CAMERA_SERVICE_H_
#define FACED_CAMERA_CAMERA_SERVICE_H_

#include "cros-camera/camera_service_connector.h"

namespace faced {

// Interface for fetching camera frames from a video source.
class CameraService {
 public:
  virtual ~CameraService() = default;

  // Initializes the connection to camera HAL dispatcher and registers the
  // camera HAL client. Must be called before any other functions.
  virtual int Init() = 0;

  // Terminates camera HAL client, all connections and threads.
  virtual int Exit() = 0;

  // Sets the callback for camera info changes and fires |callback| with the
  // info of the cameras currently present.
  virtual int GetCameraInfo(cros_cam_get_cam_info_cb_t callback,
                            void* context) = 0;

  // Starts capturing with the given parameters.
  virtual int StartCapture(const cros_cam_capture_request_t* request,
                           cros_cam_capture_cb_t callback,
                           void* context) = 0;

  // Stops capturing. Waits for the ongoing capture callback if there is any
  // underway.
  virtual int StopCapture(int id) = 0;
};

}  // namespace faced

#endif  // FACED_CAMERA_CAMERA_SERVICE_H_
