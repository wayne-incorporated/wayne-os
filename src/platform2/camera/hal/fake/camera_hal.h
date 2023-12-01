/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_CAMERA_HAL_H_
#define CAMERA_HAL_FAKE_CAMERA_HAL_H_

#include <memory>

#include <base/containers/flat_map.h>
#include <base/sequence_checker.h>
#include <base/task/sequenced_task_runner.h>
#include <camera/camera_metadata.h>

#include "common/reloadable_config_file.h"
#include "cros-camera/cros_camera_hal.h"
#include "hal/fake/camera_client.h"
#include "hal/fake/hal_spec.h"

namespace cros {

// This class is not thread-safe. All functions in camera_module_t are called by
// one mojo thread which is in hal adapter. The hal adapter makes sure these
// functions are not called concurrently. The hal adapter also has different
// dedicated threads to handle camera_module_callbacks_t, camera3_device_ops_t,
// and camera3_callback_ops_t.
class CameraHal {
 public:
  CameraHal();
  CameraHal(const CameraHal&) = delete;
  CameraHal& operator=(const CameraHal&) = delete;

  ~CameraHal();

  static CameraHal& GetInstance();

  // Implementations for camera_module_t.
  int GetNumberOfCameras() const;
  int SetCallbacks(const camera_module_callbacks_t* callbacks);
  int Init();

  // Implementations for cros_camera_hal_t.
  void SetUp(CameraMojoChannelManagerToken* token);
  void TearDown();
  void SetPrivacySwitchCallback(PrivacySwitchStateChangeCallback callback);
  int OpenDevice(int id,
                 const hw_module_t* module,
                 hw_device_t** hw_device,
                 ClientType client_type);
  int GetCameraInfo(int id, struct camera_info* info, ClientType client_type);

  // Runs on device ops thread. Post a task to the thread which is used for
  // OpenDevice.
  void CloseDevice(int id);

  CameraMojoChannelManagerToken* GetMojoManagerToken() {
    DCHECK(mojo_manager_token_ != nullptr);
    return mojo_manager_token_;
  }

 private:
  void CloseDeviceOnHalThread(int id);

  void OnSpecUpdated(const base::Value::Dict& json_values);

  void ApplySpec(const HalSpec& old_spec, const HalSpec& new_spec);

  void NotifyCameraConnected(int id, bool connected);

  bool IsCameraIdValid(int id);

  bool SetUpCamera(int id, const CameraSpec& config);
  void TearDownCamera(int id);

  // Used to report camera info at anytime.
  base::flat_map<int, android::CameraMetadata> static_metadata_;
  base::flat_map<int, android::CameraMetadata> request_template_;

  // The key is camera id.
  base::flat_map<int, std::unique_ptr<CameraClient>> cameras_;

  std::unique_ptr<ReloadableConfigFile> config_file_;

  HalSpec hal_spec_;

  const camera_module_callbacks_t* callbacks_ = nullptr;

  // Used to post CloseDevice to run on the same thread.
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // Mojo manager token which is used for Mojo communication.
  CameraMojoChannelManagerToken* mojo_manager_token_;

  // All methods of this class should be run on the same thread.
  SEQUENCE_CHECKER(sequence_checker_);
};

// Callback for camera_device.common.close().
int camera_device_close(struct hw_device_t* hw_device);

}  // namespace cros

extern camera_module_t HAL_MODULE_INFO_SYM;

#endif  // CAMERA_HAL_FAKE_CAMERA_HAL_H_
