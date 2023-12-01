/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_CAMERA_HAL_H_
#define CAMERA_HAL_USB_CAMERA_HAL_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <base/task/single_thread_task_runner.h>
#include <base/threading/thread_checker.h>
#include <hardware/camera_common.h>

#include "cros-camera/camera_metrics.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/cros_camera_hal.h"
#include "cros-camera/device_config.h"
#include "cros-camera/future.h"
#include "cros-camera/udev_watcher.h"
#include "hal/usb/camera_characteristics.h"
#include "hal/usb/camera_client.h"
#include "hal/usb/camera_privacy_switch_monitor.h"
#include "hal/usb/common_types.h"

namespace cros {

// This class is not thread-safe. All functions in camera_module_t are called by
// one mojo thread which is in hal adapter. The hal adapter makes sure these
// functions are not called concurrently. The hal adapter also has different
// dedicated threads to handle camera_module_callbacks_t, camera3_device_ops_t,
// and camera3_callback_ops_t.
class CameraHal : public UdevWatcher::Observer {
 public:
  CameraHal();
  CameraHal(const CameraHal&) = delete;
  CameraHal& operator=(const CameraHal&) = delete;

  ~CameraHal() override;

  static CameraHal& GetInstance();

  CameraMojoChannelManagerToken* GetMojoManagerToken();

  // Implementations for camera_module_t.
  int GetNumberOfCameras() const;
  int GetCameraInfo(int id, camera_info* info);
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
  int GetCameraInfo(int camera_id,
                    struct camera_info* info,
                    ClientType client_type);
  void SetPrivacySwitchState(bool on);

  // Runs on device ops thread. Post a task to the thread which is used for
  // OpenDevice.
  void CloseDeviceOnOpsThread(int id);

 private:
  void CloseDevice(int id, scoped_refptr<cros::Future<void>> future);

  bool IsValidCameraId(int id);

  // Implementation of UdevWatcher::Observer.
  void OnDeviceAdded(ScopedUdevDevicePtr dev) override;
  void OnDeviceRemoved(ScopedUdevDevicePtr dev) override;

  // Monitors HW camera privacy switch state changes. The HW privacy switch is
  // available on some devices.
  CameraPrivacySwitchMonitor hw_privacy_switch_monitor_;

  // SW privacy switch state. The SW privacy switch is set by OS and independent
  // from the HW privacy switch that some devices have.
  bool sw_privacy_switch_on_ = false;

  // Cache device information because querying the information is very slow.
  std::map<int, DeviceInfo> device_infos_;

  // The key is camera id.
  std::map<int, std::unique_ptr<CameraClient>> cameras_;

  const camera_module_callbacks_t* callbacks_;

  // All methods of this class should be run on the same thread.
  base::ThreadChecker thread_checker_;

  // Used to report camera info at anytime.
  std::map<int, ScopedCameraMetadata> static_metadata_;
  // Android may need more restriction metadata for CTS.
  std::map<int, ScopedCameraMetadata> static_metadata_android_;
  std::map<int, ScopedCameraMetadata> request_template_;
  std::map<int, ScopedCameraMetadata> request_template_android_;

  // Used to post CloseDevice to run on the same thread.
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  // Used to query informations stored in
  // /etc/camera/camera_characteristics.conf.
  CameraCharacteristics characteristics_;

  // Used to watch (un)plug events of external cameras.
  std::unique_ptr<UdevWatcher> udev_watcher_;

  // Used to access to the main configuration for Chrome OS.
  std::optional<DeviceConfig> cros_device_config_;

  // Map from device path to camera id.
  std::map<std::string, int> path_to_id_;

  // The number of built-in cameras.  Use |int| instead of |size_t| here to
  // avoid casting everywhere since we also use it as an upper bound of built-in
  // camera id.
  int num_builtin_cameras_ = 0;

  // The next id for newly plugged external camera, which is starting from
  // |num_builtin_cameras_|.
  int next_external_camera_id_;

  // The map from the model of a disconnected external camera to the set camera
  // ids it used previously.  We would try to reuse the same id for the same
  // external camera according to this map.  Note that there might be multiple
  // external cameras with the same model, so we maintain a set instead of an
  // integer here, and use the smallest free id when the camera is reconnected.
  std::map<std::string, std::set<int>> previous_ids_;

  // Mojo manager token which is used for Mojo communication.
  CameraMojoChannelManagerToken* mojo_manager_token_;

  // Metrics that used to record face ae metrics.
  std::unique_ptr<CameraMetrics> camera_metrics_;
};

// Callback for camera_device.common.close().
int camera_device_close(struct hw_device_t* hw_device);

}  // namespace cros

extern camera_module_t HAL_MODULE_INFO_SYM;

#endif  // CAMERA_HAL_USB_CAMERA_HAL_H_
