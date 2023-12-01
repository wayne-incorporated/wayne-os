/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_ADAPTER_CAMERA_HAL_ADAPTER_H_
#define CAMERA_HAL_ADAPTER_CAMERA_HAL_ADAPTER_H_

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hardware/camera3.h>

#include <base/containers/flat_set.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/thread.h>
#include <base/timer/elapsed_timer.h>
#include <mojo/public/cpp/bindings/pending_associated_remote.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "camera/mojo/camera3.mojom.h"
#include "camera/mojo/camera_common.mojom.h"
#include "common/stream_manipulator.h"
#include "common/vendor_tag_manager.h"
#include "cros-camera/camera_metrics.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/cros_camera_hal.h"
#include "ml_core/dlc/dlc_client.h"

namespace cros {

class CameraDeviceAdapter;

class CameraModuleDelegate;

class CameraModuleCallbacksAssociatedDelegate;

class VendorTagOpsDelegate;

class CameraHalAdapter;

struct CameraModuleCallbacksAux : camera_module_callbacks_t {
  int module_id;
  CameraHalAdapter* adapter;
};

class CameraHalAdapter {
 public:
  using CameraActivityCallback = base::RepeatingCallback<void(
      int32_t, bool, cros::mojom::CameraClientType)>;

  CameraHalAdapter(std::vector<std::pair<camera_module_t*, cros_camera_hal_t*>>
                       camera_interfaces,
                   CameraMojoChannelManagerToken* token,
                   CameraActivityCallback activity_callback);

  CameraHalAdapter(const CameraHalAdapter&) = delete;
  CameraHalAdapter& operator=(const CameraHalAdapter&) = delete;

  virtual ~CameraHalAdapter();

  // Starts the camera HAL adapter.  This method must be called before calling
  // any other methods.
  bool Start();

  // Creates the CameraModule Mojo connection from |camera_module_receiver|.
  void OpenCameraHal(
      mojo::PendingReceiver<mojom::CameraModule> camera_module_receiver,
      mojom::CameraClientType camera_client_type);

  // Callback interface for CameraModuleDelegate.
  // These methods are callbacks for |module_delegate_| and are executed on
  // the mojo IPC handler thread in |module_delegate_|.
  virtual int32_t OpenDevice(
      int32_t camera_id,
      mojo::PendingReceiver<mojom::Camera3DeviceOps> device_ops_receiver,
      mojom::CameraClientType camera_client_type);

  virtual int32_t GetNumberOfCameras();

  virtual int32_t GetCameraInfo(int32_t camera_id,
                                mojom::CameraInfoPtr* camera_info,
                                mojom::CameraClientType camera_client_type);

  virtual int32_t SetTorchMode(int32_t camera_id, bool enabled);

  int32_t Init();

  void GetVendorTagOps(
      mojo::PendingReceiver<mojom::VendorTagOps> vendor_tag_ops_request);

  // A callback for the camera devices opened in OpenDevice().  Used to run
  // CloseDevice() on the same thread that OpenDevice() runs on.
  void CloseDeviceCallback(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      int32_t camera_id,
      mojom::CameraClientType camera_client_type);

  // We use associated remote here to ensure that CameraModuleCallbacks runs
  // with the same message pipe as CameraModule which guarantees FIFO order. See
  // b/169324225 for context.
  int32_t SetCallbacks(
      mojo::PendingAssociatedRemote<mojom::CameraModuleCallbacks> callbacks);

  void SetAutoFramingState(mojom::CameraAutoFramingState enabled);

  mojom::CameraPrivacySwitchState GetCameraSWPrivacySwitchState();

  void SetCameraSWPrivacySwitchState(mojom::CameraPrivacySwitchState state);

  mojom::SetEffectResult SetCameraEffect(mojom::EffectsConfigPtr config);

 protected:
  // Convert the unified public |camera_id| into the corresponding camera
  // module and its internal id. Returns (nullptr, 0) if not found.
  std::pair<camera_module_t*, int> GetInternalModuleAndId(int camera_id);

  // Initialize all underlying camera HALs on |camera_module_thread_| and
  // build the mapping table for camera id.
  virtual void StartOnThread(base::OnceCallback<void(bool)> callback);

  virtual void NotifyCameraDeviceStatusChange(
      CameraModuleCallbacksAssociatedDelegate* delegate,
      int camera_id,
      camera_device_status_t status);

  virtual void NotifyTorchModeStatusChange(
      CameraModuleCallbacksAssociatedDelegate* delegate,
      int camera_id,
      torch_mode_status_t status);

 private:
  // The static methods implement camera_module_callbacks_t, which will delegate
  // to the corresponding instance methods.
  static void camera_device_status_change(
      const camera_module_callbacks_t* callbacks,
      int camera_id,
      int new_status);

  static void torch_mode_status_change(
      const camera_module_callbacks_t* callbacks,
      const char* camera_id,
      int new_status);

  std::optional<mojom::CameraPrivacySwitchState>
  LoadCachedCameraSWPrivacySwitchState();
  void CacheCameraSWPrivacySwitchState(mojom::CameraPrivacySwitchState state);
  void SetCameraSWPrivacySwitchStateOnCameraModuleThread(
      mojom::CameraPrivacySwitchState state);

  // Gets the static metadata of a camera given the original static metadata
  // with updated metadata modifications from the camera service such as vendor
  // tags and available request keys.
  const camera_metadata_t* GetUpdatedCameraMetadata(
      int camera_id,
      mojom::CameraClientType camera_client_type,
      const camera_metadata_t* static_metadata);

  void CameraDeviceStatusChange(const CameraModuleCallbacksAux* callbacks,
                                int camera_id,
                                camera_device_status_t new_status);

  void TorchModeStatusChange(const CameraModuleCallbacksAux* callbacks,
                             int camera_id,
                             torch_mode_status_t new_status);

  // Send the latest status to the newly connected client.
  void SendLatestStatus(int callbacks_id);

  // Convert the public |camera_id| to its internal |camera_id|.
  int GetInternalId(int camera_id);

  // Convert the |module_id| and its corresponding internal |camera_id| into the
  // unified public camera id. Returns -1 if not found.
  int GetPublicId(int module_id, int camera_id);

  // Clean up the camera device specified by |camera_id| in |device_adapters_|.
  void CloseDevice(int32_t camera_id,
                   mojom::CameraClientType camera_client_type);

  void ResetModuleDelegateOnThread(uint32_t module_id);
  void ResetCallbacksDelegateOnThread(uint32_t callbacks_id);
  void ResetVendorTagOpsDelegateOnThread(uint32_t vendor_tag_ops_id);

  // camera_module_t: The handles to the camera HALs dlopen()/dlsym()'d on
  //                  process start.
  // cros_camera_hals: Interfaces of Camera HALs.
  std::vector<std::pair<camera_module_t*, cros_camera_hal_t*>>
      camera_interfaces_;

  // The task runner that CameraHalServer runs on.  Used only for serializing
  // exit() call at the moment.
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;

  // The thread that all camera module functions operate on.
  base::Thread camera_module_thread_;

  // The thread that all the Mojo communication of camera module callbacks
  // operate on.
  base::Thread camera_module_callbacks_thread_;

  // The number of built-in cameras.
  int num_builtin_cameras_;

  // The next id for newly plugged external camera, which is starting from
  // |num_builtin_cameras_|.
  int next_external_camera_id_;

  // The mapping tables of internal/public |camera_id|.
  // (public camera id) <=> (module id, internal camera id)
  std::map<int, std::pair<int, int>> camera_id_map_;
  std::vector<std::map<int, int>> camera_id_inverse_map_;

  // A mapping from (camera ID) to their physical camera IDs.
  // A logical multi-camera is mapped to multiple physical cameras. The string
  // to which a camera ID is mapped, is a series of physical camera IDs in
  // string separated by null characters. For example, if a logical multi-camera
  // is backed by physical cameras 2, 3, and 10, the string's data will contain
  // '2', '\0', '3', '\0', '1', '0', '\0'.
  std::map<int, std::string> physical_camera_id_map_;

  // A mapping from camera ID to mapping from camera client type to their
  // static metadata.
  base::flat_map<int,
                 base::flat_map<mojom::CameraClientType,
                                std::unique_ptr<android::CameraMetadata>>>
      static_metadata_map_;

  // We need to keep the status for each camera to send up-to-date information
  // for newly connected client so everyone is in sync.
  // (public camera id) <=> (latest status)
  std::map<int, camera_device_status_t> device_status_map_;
  std::map<int, camera_device_status_t> default_device_status_map_;
  std::map<int, torch_mode_status_t> torch_mode_status_map_;
  std::map<int, torch_mode_status_t> default_torch_mode_status_map_;

  // The callback structs with auxiliary metadata for converting |camera_id|
  // per camera module.
  std::vector<std::unique_ptr<CameraModuleCallbacksAux>> callbacks_auxs_;

  // The delegates that handle the CameraModule mojo IPC.  The key of the map is
  // got from |module_id_|.
  std::map<uint32_t, std::unique_ptr<CameraModuleDelegate>> module_delegates_;

  // The delegates that handle the VendorTagOps mojo IPC. The key of the map is
  // got from |vendor_tag_ops_id_|.
  std::map<uint32_t, std::unique_ptr<VendorTagOpsDelegate>>
      vendor_tag_ops_delegates_;

  // The delegate that handles the CameraModuleCallbacks mojo IPC.  The key of
  // the map is got from |callbacks_id_|.
  std::map<uint32_t, std::unique_ptr<CameraModuleCallbacksAssociatedDelegate>>
      callbacks_delegates_;

  // Protects |module_delegates_|.
  base::Lock module_delegates_lock_;
  // Protects |callbacks_delegates_|.
  base::Lock callbacks_delegates_lock_;

  // Strictly increasing integers used as the key for new CameraModuleDelegate,
  // CameraModuleCallbacksAssociatedDelegate and VendorTagOpsDelegate instances
  // in |module_delegates_|, |callback_delegates_| and
  // |vendor_tag_ops_delegates_|.
  uint32_t module_id_;
  uint32_t callbacks_id_;
  uint32_t vendor_tag_ops_id_;

  // The handles to the opened camera devices.  |device_adapters_| is accessed
  // only in OpenDevice(), CloseDevice() and CameraDeviceStatusChange().  In
  // order to do lock-free access to |device_adapters_|, we run all of them on
  // the same thread (i.e. the mojo IPC handler thread in |module_delegate_|).
  std::map<int32_t, std::unique_ptr<CameraDeviceAdapter>> device_adapters_;

  // The vendor tag manager.
  VendorTagManager vendor_tag_manager_;

  // The map of session start time.
  std::map<int, base::ElapsedTimer> session_timer_map_;

  // Metrics for camera service.
  std::unique_ptr<CameraMetrics> camera_metrics_;

  // Mojo manager token which is used for Mojo communication.
  CameraMojoChannelManagerToken* mojo_manager_token_;

  CameraActivityCallback activity_callback_;

  // TODO(pihsun): Should this be per CameraDeviceAdapter?
  StreamManipulator::RuntimeOptions stream_manipulator_runtime_options_;

  std::unique_ptr<GpuResources> root_gpu_resources_;

  std::unique_ptr<DlcClient> dlc_client_;
};

}  // namespace cros

#endif  // CAMERA_HAL_ADAPTER_CAMERA_HAL_ADAPTER_H_
