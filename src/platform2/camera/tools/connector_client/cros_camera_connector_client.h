/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_TOOLS_CONNECTOR_CLIENT_CROS_CAMERA_CONNECTOR_CLIENT_H_
#define CAMERA_TOOLS_CONNECTOR_CLIENT_CROS_CAMERA_CONNECTOR_CLIENT_H_

#include <list>
#include <map>
#include <queue>
#include <vector>

#include <base/threading/thread.h>
#include <brillo/daemons/daemon.h>

#include "cros-camera/camera_service_connector.h"

namespace cros {

int OnGotCameraInfo(void* context, const cros_cam_info_t* info, int is_removed);

class CrosCameraConnectorClient : public brillo::Daemon {
 public:
  CrosCameraConnectorClient();

  int OnInit() override;

  void OnShutdown(int* exit_code) override;

  void SetCamInfo(const cros_cam_info_t* info);

  void RemoveCamera(int32_t id);

  void ProcessFrame(const cros_cam_frame_t* frame);

  void StartCapture();

  void RestartCapture();

 private:
  void StartCaptureOnThread();

  void StopCaptureOnThread();

  void RestartCaptureOnThread();

  scoped_refptr<base::SequencedTaskRunner> client_runner_;

  std::list<int32_t> camera_device_list_;
  std::map<int32_t, std::vector<cros_cam_format_info_t>> format_info_map_;
  base::Lock camera_info_lock_;  // Lock that protects |camera_device_list_|
                                 // and |format_info_map_|.
  bool init_done_;

  std::map<int32_t, std::queue<cros_cam_format_info_t>> pending_captures_map_;
  int32_t current_id_;
  cros_cam_format_info_t current_format_info_;
  base::Lock capture_lock_;  // Lock that protects |pending_captures_map_|,
                             // |current_id_| and |current_format_info_|.

  base::Thread capture_thread_;
  int num_restarts_;
};

}  // namespace cros

#endif  // CAMERA_TOOLS_CONNECTOR_CLIENT_CROS_CAMERA_CONNECTOR_CLIENT_H_
