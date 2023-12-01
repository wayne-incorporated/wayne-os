/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal_adapter/camera_hal_adapter.h"

#include <algorithm>
#include <iomanip>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/single_thread_task_runner.h>
#include <camera/camera_metadata.h>
#include <system/camera_metadata_hidden.h>

#include "common/stream_manipulator.h"
#include "common/stream_manipulator_manager.h"
#include "common/utils/cros_camera_mojo_utils.h"
#include "cros-camera/camera_metrics.h"
#include "cros-camera/common.h"
#include "cros-camera/constants.h"
#include "cros-camera/future.h"
#include "cros-camera/tracing.h"
#include "features/feature_profile.h"
#include "gpu/gpu_resources.h"
#include "hal_adapter/camera_device_adapter.h"
#include "hal_adapter/camera_module_callbacks_associated_delegate.h"
#include "hal_adapter/camera_module_delegate.h"
#include "hal_adapter/camera_trace_event.h"
#include "hal_adapter/vendor_tag_ops_delegate.h"

namespace cros {

namespace {

// A special id used in ResetModuleDelegateOnThread and
// ResetCallbacksDelegateOnThread to specify all the entries present in the
// |module_delegates_| and |callbacks_delegates_| maps.
const uint32_t kIdAll = 0xFFFFFFFF;

constexpr char kArcvmVendorTagSectionName[] = "com.google.arcvm";
constexpr char kArcvmVendorTagHostTimeTagName[] = "hostSensorTimestamp";
constexpr uint32_t kArcvmVendorTagHostTime = kArcvmVendorTagStart;

const base::FilePath kSWPrivacySwitchFilePath("/run/camera/sw_privacy_switch");
constexpr char kSWPrivacySwitchOn[] = "on";
constexpr char kSWPrivacySwitchOff[] = "off";

}  // namespace

CameraHalAdapter::CameraHalAdapter(
    std::vector<std::pair<camera_module_t*, cros_camera_hal_t*>>
        camera_interfaces,
    CameraMojoChannelManagerToken* token,
    CameraActivityCallback activity_callback)
    : camera_interfaces_(camera_interfaces),
      main_task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
      camera_module_thread_("CameraModuleThread"),
      camera_module_callbacks_thread_("CameraModuleCallbacksThread"),
      module_id_(0),
      callbacks_id_(0),
      vendor_tag_ops_id_(0),
      camera_metrics_(CameraMetrics::New()),
      mojo_manager_token_(token),
      activity_callback_(activity_callback) {}

CameraHalAdapter::~CameraHalAdapter() {
  camera_module_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&CameraHalAdapter::ResetModuleDelegateOnThread,
                                base::Unretained(this), kIdAll));
  camera_module_callbacks_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraHalAdapter::ResetCallbacksDelegateOnThread,
                     base::Unretained(this), kIdAll));
  camera_module_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraHalAdapter::ResetVendorTagOpsDelegateOnThread,
                     base::Unretained(this), kIdAll));
  // We need to destroy the CameraDeviceAdapters on the same thread they were
  // created on to avoid race condition.
  camera_module_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce([](std::map<int32_t, std::unique_ptr<CameraDeviceAdapter>>
                            device_adapters) {},
                     std::move(device_adapters_)));
  camera_module_thread_.Stop();
  camera_module_callbacks_thread_.Stop();
  set_camera_metadata_vendor_ops(nullptr);
}

bool CameraHalAdapter::Start() {
  TRACE_HAL_ADAPTER();

  if (GpuResources::IsSupported()) {
    root_gpu_resources_ = std::make_unique<GpuResources>(
        GpuResourcesOptions{.name = "RootGpuResources"});
    if (!root_gpu_resources_->Initialize()) {
      LOGF(ERROR) << "Failed to initialize root GPU resources";
      root_gpu_resources_ = nullptr;
    }
    DCHECK(root_gpu_resources_);
  }

  if (!camera_module_thread_.Start()) {
    LOGF(ERROR) << "Failed to start CameraModuleThread";
    return false;
  }
  if (!camera_module_callbacks_thread_.Start()) {
    LOGF(ERROR) << "Failed to start CameraCallbacksThread";
    return false;
  }

  if (FeatureProfile().IsEnabled(FeatureProfile::FeatureType::kEffects)) {
    LOGF(INFO) << "Effects are enabled, initiating DLC install.";
    dlc_client_ = DlcClient::Create(
        base::BindOnce(
            [](StreamManipulator::RuntimeOptions* options,
               const base::FilePath& dlc_path) {
              LOGF(INFO) << "DLC Completed (success): Setting DlcRootPath.";
              options->SetDlcRootPath(dlc_path);
            },
            base::Unretained(&stream_manipulator_runtime_options_)),
        base::BindOnce([](const std::string& error_msg) {
          LOGF(ERROR) << "DLC Completed (failed):" << error_msg;
        }));
    dlc_client_->InstallDlc();
  } else {
    LOGF(INFO) << "Effects are not enabled, DLC will not be installed.";
  }

  auto future = cros::Future<bool>::Create(nullptr);
  camera_module_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraHalAdapter::StartOnThread, base::Unretained(this),
                     cros::GetFutureCallback(future)));

  std::optional<mojom::CameraPrivacySwitchState> state =
      LoadCachedCameraSWPrivacySwitchState();
  if (state.has_value()) {
    SetCameraSWPrivacySwitchState(state.value());
  }

  return future->Get();
}

void CameraHalAdapter::OpenCameraHal(
    mojo::PendingReceiver<mojom::CameraModule> camera_module_receiver,
    mojom::CameraClientType camera_client_type) {
  TRACE_HAL_ADAPTER("client_type", camera_client_type);

  auto module_delegate = std::make_unique<CameraModuleDelegate>(
      this, camera_module_thread_.task_runner(), camera_client_type);
  uint32_t module_id = module_id_++;
  module_delegate->Bind(
      std::move(camera_module_receiver),
      base::BindOnce(&CameraHalAdapter::ResetModuleDelegateOnThread,
                     base::Unretained(this), module_id));
  base::AutoLock l(module_delegates_lock_);
  module_delegates_[module_id] = std::move(module_delegate);
  VLOGF(1) << "CameraModule " << module_id << " connected";
}

// Callback interface for camera_module_t APIs.

int32_t CameraHalAdapter::OpenDevice(
    int32_t camera_id,
    mojo::PendingReceiver<mojom::Camera3DeviceOps> device_ops_receiver,
    mojom::CameraClientType camera_client_type) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("client_type", camera_client_type, "camera_id", camera_id);

  session_timer_map_.emplace(std::piecewise_construct,
                             std::forward_as_tuple(camera_id),
                             std::forward_as_tuple());

  camera_module_t* camera_module;
  int internal_camera_id;
  std::tie(camera_module, internal_camera_id) =
      GetInternalModuleAndId(camera_id);

  if (!camera_module) {
    return -EINVAL;
  }

  if (device_adapters_.find(camera_id) != device_adapters_.end()) {
    LOGF(WARNING) << "Multiple calls to OpenDevice on device " << camera_id;
    if (device_adapters_[camera_id]->IsRequestOrResultStalling()) {
      LOGF(WARNING) << "The camera HAL probably hung. Restart camera service "
                       "to recover from bad state (b/155830039).";
      main_task_runner_->PostTask(FROM_HERE, base::BindOnce([]() {
                                    // Exit directly without attempting anything
                                    // else to shutdown cleanly since the HAL
                                    // thread may be wedged already.
                                    exit(ENODEV);
                                  }));
      return -ENODEV;
    }
    return -EBUSY;
  }

  int module_id = camera_id_map_[camera_id].first;
  cros_camera_hal_t* cros_camera_hal = camera_interfaces_[module_id].second;

  // If HAL-level SW privacy switch is not available, force OpenDevice() to
  // fail.
  if (cros_camera_hal && !cros_camera_hal->set_privacy_switch_state &&
      stream_manipulator_runtime_options_.sw_privacy_switch_state() ==
          mojom::CameraPrivacySwitchState::ON) {
    return -ENODEV;
  }

  LOGF(INFO) << camera_client_type << ", camera_id = " << camera_id
             << ", camera_module = " << camera_module->common.name
             << ", internal_camera_id = " << internal_camera_id;

  hw_module_t* common = &camera_module->common;
  camera3_device_t* camera_device;
  int ret;
  if (cros_camera_hal && cros_camera_hal->camera_device_open_ext) {
    ret = cros_camera_hal->camera_device_open_ext(
        common, std::to_string(internal_camera_id).c_str(),
        reinterpret_cast<hw_device_t**>(&camera_device),
        static_cast<ClientType>(camera_client_type));
  } else {
    ret = common->methods->open(
        common, std::to_string(internal_camera_id).c_str(),
        reinterpret_cast<hw_device_t**>(&camera_device));
  }
  if (ret != 0) {
    LOGF(ERROR) << "Failed to open camera device " << camera_id;
    return ret;
  }
  activity_callback_.Run(camera_id, /*opened=*/true, camera_client_type);

  camera_info_t info;
  if (cros_camera_hal && cros_camera_hal->get_camera_info_ext) {
    ret = cros_camera_hal->get_camera_info_ext(
        internal_camera_id, &info, static_cast<ClientType>(camera_client_type));
  } else {
    ret = camera_module->get_camera_info(internal_camera_id, &info);
  }
  if (ret != 0) {
    LOGF(ERROR) << "Failed to get camera info of camera " << camera_id;
    return ret;
  }
  const camera_metadata_t* metadata = GetUpdatedCameraMetadata(
      camera_id, camera_client_type, info.static_camera_characteristics);
  base::RepeatingCallback<int(int)> get_internal_camera_id_callback =
      base::BindRepeating(&CameraHalAdapter::GetInternalId,
                          base::Unretained(this));
  base::RepeatingCallback<int(int)> get_public_camera_id_callback =
      base::BindRepeating(&CameraHalAdapter::GetPublicId,
                          base::Unretained(this), module_id);
  // This method is called by |camera_module_delegate_| on its mojo IPC
  // handler thread.
  // The CameraHalAdapter (and hence |camera_module_delegate_|) must out-live
  // the CameraDeviceAdapters, so it's safe to keep a reference to the task
  // runner of the current thread in the callback functor.
  base::OnceCallback<void()> close_callback = base::BindOnce(
      &CameraHalAdapter::CloseDeviceCallback, base::Unretained(this),
      base::SingleThreadTaskRunner::GetCurrentDefault(), camera_id,
      camera_client_type);
  base::OnceCallback<void(FaceDetectionResultCallback)>
      set_face_detection_result_callback;
  if (cros_camera_hal->set_face_detection_result_callback != nullptr) {
    set_face_detection_result_callback = base::BindOnce(
        [](cros_camera_hal_t* hal, int camera_id,
           FaceDetectionResultCallback cb) {
          hal->set_face_detection_result_callback(camera_id, cb);
        },
        // The |cros_camera_hal| outlives the stream manipulator.
        base::Unretained(cros_camera_hal), internal_camera_id);
  }

  bool do_notify_invalid_capture_request = false;
#if USE_ARCVM
  // b/272432362 ARCVM client will be doing async process_capture_request.
  do_notify_invalid_capture_request =
      camera_client_type == mojom::CameraClientType::ANDROID;
#endif

  device_adapters_[camera_id] = std::make_unique<CameraDeviceAdapter>(
      camera_device, info.device_version, metadata,
      std::move(get_internal_camera_id_callback),
      std::move(get_public_camera_id_callback), std::move(close_callback),
      std::make_unique<StreamManipulatorManager>(
          StreamManipulatorManager::CreateOptions{
              .camera_module_name = camera_module->common.name,
              .set_face_detection_result_callback =
                  std::move(set_face_detection_result_callback),
              .sw_privacy_switch_stream_manipulator_enabled = false},
          &stream_manipulator_runtime_options_, root_gpu_resources_.get(),
          mojo_manager_token_),
      do_notify_invalid_capture_request);

  if (!device_adapters_[camera_id]->Start()) {
    device_adapters_.erase(camera_id);
    return -ENODEV;
  }
  device_adapters_.at(camera_id)->Bind(std::move(device_ops_receiver));
  camera_metrics_->SendCameraFacing(info.facing);
  camera_metrics_->SendOpenDeviceClientType(
      static_cast<int>(camera_client_type));
  camera_metrics_->SendOpenDeviceLatency(
      session_timer_map_[camera_id].Elapsed());

  return 0;
}

void CameraHalAdapter::SetAutoFramingState(
    mojom::CameraAutoFramingState state) {
  stream_manipulator_runtime_options_.SetAutoFramingState(state);
}

mojom::CameraPrivacySwitchState
CameraHalAdapter::GetCameraSWPrivacySwitchState() {
  return stream_manipulator_runtime_options_.sw_privacy_switch_state();
}

void CameraHalAdapter::SetCameraSWPrivacySwitchState(
    mojom::CameraPrivacySwitchState state) {
  // TODO(okuji): Once we migrate to the HAL SW privacy switch, we should change
  // the timing of calling SetSWPrivacySwitchState() since it can be delayed for
  // switch state changes to take effect in HAL. For example, we want to avoid
  // accidentally disabling stream manipulator effects before the SW state
  // change from OFF to ON takes effect.
  stream_manipulator_runtime_options_.SetSWPrivacySwitchState(state);
  camera_module_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &CameraHalAdapter::SetCameraSWPrivacySwitchStateOnCameraModuleThread,
          base::Unretained(this), state));
  CacheCameraSWPrivacySwitchState(state);
}

mojom::SetEffectResult CameraHalAdapter::SetCameraEffect(
    mojom::EffectsConfigPtr config) {
  LOG(INFO) << "CameraHalAdapter::SetCameraEffect:"
            << " blur: " << config->blur_enabled
            << " relight: " << config->relight_enabled
            << " replace: " << config->replace_enabled
            << " blur_level: " << config->blur_level;

  if (!FeatureProfile().IsEnabled(FeatureProfile::FeatureType::kEffects)) {
    return mojom::SetEffectResult::kFeatureDisabled;
  }

  if (stream_manipulator_runtime_options_.GetDlcRootPath() ==
      base::FilePath("")) {
    return mojom::SetEffectResult::kDlcUnavailable;
  }

  stream_manipulator_runtime_options_.SetEffectsConfig(std::move(config));
  return mojom::SetEffectResult::kOk;
}

int32_t CameraHalAdapter::GetNumberOfCameras() {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();
  return num_builtin_cameras_;
}

int32_t CameraHalAdapter::GetCameraInfo(
    int32_t camera_id,
    mojom::CameraInfoPtr* camera_info,
    mojom::CameraClientType camera_client_type) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("client_type", camera_client_type, "camera_id", camera_id);

  camera_module_t* camera_module;
  int internal_camera_id;
  std::tie(camera_module, internal_camera_id) =
      GetInternalModuleAndId(camera_id);

  if (!camera_module) {
    camera_info->reset();
    return -EINVAL;
  }
  int ret;
  int module_id = camera_id_map_[camera_id].first;
  camera_info_t info;
  cros_camera_hal_t* cros_camera_hal = camera_interfaces_[module_id].second;
  if (cros_camera_hal && cros_camera_hal->get_camera_info_ext) {
    ret = cros_camera_hal->get_camera_info_ext(
        internal_camera_id, &info, static_cast<ClientType>(camera_client_type));
  } else {
    ret = camera_module->get_camera_info(internal_camera_id, &info);
  }

  if (ret != 0) {
    LOGF(ERROR) << "Failed to get info of camera " << camera_id;
    camera_info->reset();
    return ret;
  }

  LOGF(INFO) << camera_client_type << " camera_id = " << camera_id
             << ", facing = " << info.facing;

  const camera_metadata_t* metadata = GetUpdatedCameraMetadata(
      camera_id, camera_client_type, info.static_camera_characteristics);

  if (VLOG_IS_ON(2)) {
    dump_camera_metadata(metadata, 2, 3);
  }

  mojom::CameraInfoPtr info_ptr = mojom::CameraInfo::New();
  info_ptr->facing = static_cast<mojom::CameraFacing>(info.facing);
  info_ptr->orientation = info.orientation;
  info_ptr->device_version = info.device_version;
  info_ptr->static_camera_characteristics =
      internal::SerializeCameraMetadata(metadata);
  info_ptr->resource_cost = mojom::CameraResourceCost::New();
  info_ptr->resource_cost->resource_cost = info.resource_cost;

  std::vector<std::string> conflicting_devices;
  for (size_t i = 0; i < info.conflicting_devices_length; i++) {
    int conflicting_id =
        GetPublicId(module_id, atoi(info.conflicting_devices[i]));
    conflicting_devices.push_back(std::to_string(conflicting_id));
  }
  info_ptr->conflicting_devices = std::move(conflicting_devices);

  *camera_info = std::move(info_ptr);
  return 0;
}

int32_t CameraHalAdapter::SetTorchMode(int32_t camera_id, bool enabled) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("camera_id", camera_id);

  camera_module_t* camera_module;
  int internal_camera_id;
  std::tie(camera_module, internal_camera_id) =
      GetInternalModuleAndId(camera_id);

  if (!camera_module) {
    return -EINVAL;
  }

  if (auto fn = camera_module->set_torch_mode) {
    return fn(std::to_string(internal_camera_id).c_str(), enabled);
  }

  return -ENOSYS;
}

int32_t CameraHalAdapter::Init() {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  return 0;
}

void CameraHalAdapter::GetVendorTagOps(
    mojo::PendingReceiver<mojom::VendorTagOps> vendor_tag_ops_receiver) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  auto vendor_tag_ops_delegate = std::make_unique<VendorTagOpsDelegate>(
      camera_module_thread_.task_runner(), &vendor_tag_manager_);
  uint32_t vendor_tag_ops_id = vendor_tag_ops_id_++;
  vendor_tag_ops_delegate->Bind(
      std::move(vendor_tag_ops_receiver),
      base::BindOnce(&CameraHalAdapter::ResetVendorTagOpsDelegateOnThread,
                     base::Unretained(this), vendor_tag_ops_id));
  vendor_tag_ops_delegates_[vendor_tag_ops_id] =
      std::move(vendor_tag_ops_delegate);
  VLOGF(1) << "VendorTagOps " << vendor_tag_ops_id << " connected";
}

void CameraHalAdapter::CloseDeviceCallback(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    int32_t camera_id,
    mojom::CameraClientType camera_client_type) {
  task_runner->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraHalAdapter::CloseDevice, base::Unretained(this),
                     camera_id, camera_client_type));
  task_runner->PostTask(FROM_HERE, base::BindOnce([]() {
                          // Inject an empty event to end the CloseDevice
                          // event. The CameraHalAdapter::CloseDevice event
                          // emitted by the callback above is usually the last
                          // event from the cros-camera process, and there's a
                          // known issue in Perfetto where the last event does
                          // not end.
                          PERFETTO_INTERNAL_ADD_EMPTY_EVENT();
                        }));
}

// static
void CameraHalAdapter::camera_device_status_change(
    const camera_module_callbacks_t* callbacks,
    int internal_camera_id,
    int new_status) {
  auto* aux = static_cast<const CameraModuleCallbacksAux*>(callbacks);
  CameraHalAdapter* self = aux->adapter;
  self->camera_module_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraHalAdapter::CameraDeviceStatusChange,
                     base::Unretained(self), aux, internal_camera_id,
                     static_cast<camera_device_status_t>(new_status)));
}

// static
void CameraHalAdapter::torch_mode_status_change(
    const camera_module_callbacks_t* callbacks,
    const char* internal_camera_id,
    int new_status) {
  auto* aux = static_cast<const CameraModuleCallbacksAux*>(callbacks);
  CameraHalAdapter* self = aux->adapter;
  self->camera_module_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraHalAdapter::TorchModeStatusChange,
                     base::Unretained(self), aux, atoi(internal_camera_id),
                     static_cast<torch_mode_status_t>(new_status)));
}

std::optional<mojom::CameraPrivacySwitchState>
CameraHalAdapter::LoadCachedCameraSWPrivacySwitchState() {
  if (base::PathExists(kSWPrivacySwitchFilePath)) {
    std::string state;
    if (base::ReadFileToString(kSWPrivacySwitchFilePath, &state)) {
      LOGF(INFO) << "Read the SW privacy switch " << std::quoted(state)
                 << " from " << std::quoted(kSWPrivacySwitchFilePath.value());
      if (state == kSWPrivacySwitchOn) {
        return mojom::CameraPrivacySwitchState::ON;
      } else if (state == kSWPrivacySwitchOff) {
        return mojom::CameraPrivacySwitchState::OFF;
      }
    } else {
      LOGF(ERROR) << "Failed to read the SW privacy switch state from "
                  << std::quoted(kSWPrivacySwitchFilePath.value());
    }
  }
  return std::nullopt;
}

void CameraHalAdapter::CacheCameraSWPrivacySwitchState(
    mojom::CameraPrivacySwitchState state) {
  const char* str = state == mojom::CameraPrivacySwitchState::ON
                        ? kSWPrivacySwitchOn
                        : kSWPrivacySwitchOff;
  if (!base::WriteFile(kSWPrivacySwitchFilePath, str)) {
    LOGF(ERROR) << "Failed to write the SW privacy switch state to "
                << std::quoted(kSWPrivacySwitchFilePath.value());
  }
}

void CameraHalAdapter::SetCameraSWPrivacySwitchStateOnCameraModuleThread(
    mojom::CameraPrivacySwitchState state) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  for (int module_id = 0; module_id < camera_interfaces_.size(); ++module_id) {
    cros_camera_hal_t* hal = camera_interfaces_[module_id].second;
    if (hal->set_privacy_switch_state != nullptr) {
      hal->set_privacy_switch_state(state ==
                                    mojom::CameraPrivacySwitchState::ON);
    } else if (state == mojom::CameraPrivacySwitchState::ON) {
      for (const auto& [camera_id, device_adapter] : device_adapters_) {
        if (camera_id_map_[camera_id].first == module_id) {
          device_adapter->ForceClose();
        }
      }
    }
  }
}

const camera_metadata_t* CameraHalAdapter::GetUpdatedCameraMetadata(
    int camera_id,
    mojom::CameraClientType camera_client_type,
    const camera_metadata_t* static_metadata) {
  TRACE_HAL_ADAPTER("client_type", camera_client_type, "camera_id", camera_id);

  auto& metadata = static_metadata_map_[camera_id][camera_client_type];
  if (metadata) {
    return metadata->getAndLock();
  }

  metadata = std::make_unique<android::CameraMetadata>();
  metadata->acquire(clone_camera_metadata(static_metadata));

  if (!StreamManipulator::UpdateStaticMetadata(metadata.get())) {
    LOGF(ERROR)
        << "Failed to update the static metadata from StreamManipulators";
  }

  if (metadata->exists(ANDROID_LOGICAL_MULTI_CAMERA_PHYSICAL_IDS)) {
    auto it = physical_camera_id_map_.find(camera_id);
    if (it == physical_camera_id_map_.end()) {
      LOGF(ERROR) << "Failed to find the physical camera IDs for camera "
                  << camera_id;
    } else {
      if (metadata->update(ANDROID_LOGICAL_MULTI_CAMERA_PHYSICAL_IDS,
                           it->second) != 0) {
        LOGF(ERROR)
            << "Failed to remap ANDROID_LOGICAL_MULTI_CAMERA_PHYSICAL_IDS";
      }
    }
  }
  return metadata->getAndLock();
}

void CameraHalAdapter::CameraDeviceStatusChange(
    const CameraModuleCallbacksAux* aux,
    int internal_camera_id,
    camera_device_status_t new_status) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("camera_id", internal_camera_id, "device_status",
                    new_status);

  int public_camera_id = GetPublicId(aux->module_id, internal_camera_id);

  LOGF(INFO) << "module_id = " << aux->module_id
             << ", internal_camera_id = " << internal_camera_id
             << ", new_status = " << new_status;

  switch (new_status) {
    case CAMERA_DEVICE_STATUS_PRESENT:
      if (public_camera_id == -1) {
        public_camera_id = next_external_camera_id_++;
        camera_id_map_[public_camera_id] =
            std::make_pair(aux->module_id, internal_camera_id);
        camera_id_inverse_map_[aux->module_id][internal_camera_id] =
            public_camera_id;
        device_status_map_[public_camera_id] = CAMERA_DEVICE_STATUS_PRESENT;
        default_device_status_map_[public_camera_id] =
            CAMERA_DEVICE_STATUS_NOT_PRESENT;
        torch_mode_status_map_[public_camera_id] =
            TORCH_MODE_STATUS_NOT_AVAILABLE;
        default_torch_mode_status_map_[public_camera_id] =
            TORCH_MODE_STATUS_NOT_AVAILABLE;
      } else {
        device_status_map_[public_camera_id] = CAMERA_DEVICE_STATUS_PRESENT;
      }
      LOGF(INFO) << "External camera plugged, public_camera_id = "
                 << public_camera_id;
      break;
    case CAMERA_DEVICE_STATUS_NOT_PRESENT:
      if (public_camera_id != -1) {
        device_status_map_[public_camera_id] = CAMERA_DEVICE_STATUS_NOT_PRESENT;
        torch_mode_status_map_[public_camera_id] =
            default_torch_mode_status_map_[public_camera_id];
        auto it = device_adapters_.find(public_camera_id);
        if (it != device_adapters_.end()) {
          device_adapters_.erase(it);
        }
        static_metadata_map_.erase(public_camera_id);
        LOGF(INFO) << "External camera unplugged"
                   << ", public_camera_id = " << public_camera_id;
      } else {
        LOGF(WARNING) << "Ignore nonexistent camera";
      }
      break;
    default:
      // TODO(shik): What about CAMERA_DEVICE_STATUS_ENUMERATING?
      NOTREACHED() << "Unexpected new status " << new_status;
      break;
  }

  base::AutoLock l(callbacks_delegates_lock_);
  for (auto& it : callbacks_delegates_) {
    NotifyCameraDeviceStatusChange(it.second.get(), public_camera_id,
                                   new_status);
  }
}

void CameraHalAdapter::TorchModeStatusChange(
    const CameraModuleCallbacksAux* aux,
    int internal_camera_id,
    torch_mode_status_t new_status) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("camera_id", internal_camera_id);

  int camera_id = GetPublicId(aux->module_id, internal_camera_id);
  if (camera_id == -1) {
    LOGF(WARNING) << "Ignore nonexistent camera"
                  << ", module_id = " << aux->module_id
                  << ", camera_id = " << internal_camera_id;
    return;
  }

  torch_mode_status_map_[camera_id] = new_status;

  base::AutoLock l(callbacks_delegates_lock_);
  for (auto& it : callbacks_delegates_) {
    NotifyTorchModeStatusChange(it.second.get(), camera_id, new_status);
  }
}

void CameraHalAdapter::StartOnThread(base::OnceCallback<void(bool)> callback) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());

  if (!vendor_tag_manager_.Add(kArcvmVendorTagHostTime,
                               kArcvmVendorTagSectionName,
                               kArcvmVendorTagHostTimeTagName, TYPE_INT64)) {
    LOGF(ERROR)
        << "Failed to add the vendor tag for ARCVM timestamp synchronization";
    std::move(callback).Run(false);
    return;
  }
  if (!StreamManipulator::UpdateVendorTags(vendor_tag_manager_)) {
    LOGF(ERROR) << "Failed to add the vendor tags from StreamManipualtors";
    std::move(callback).Run(false);
    return;
  }

  // The setup sequence for each camera HAL:
  //   1. get_vendor_tag_ops()
  //   2. init()
  //   3. get_number_of_cameras()
  //   4. set_callbacks()
  //   5. get_camera_info()
  //
  // Normally, init() is the first invoked method in the sequence.  But init()
  // might manipulate vendor tags with libcamera_metadata, which requires
  // set_camera_metadata_vendor_ops() to be invoked already.  To prepare the
  // aggregated |vendor_tag_ops| for set_camera_metadata_vendor_ops(), we need
  // to collect |vendor_tag_ops| from all camera modules by calling
  // get_vendor_tag_ops() first, which should be fine as it just set some
  // function pointers in the struct.
  //
  // Note that camera HALs MAY run callbacks before set_callbacks() returns.

  for (const auto& interface : camera_interfaces_) {
    camera_module_t* m = interface.first;
    if (m->get_vendor_tag_ops) {
      vendor_tag_ops ops = {};
      m->get_vendor_tag_ops(&ops);
      if (ops.get_tag_count == nullptr) {
        continue;
      }
      if (!vendor_tag_manager_.Add(&ops)) {
        LOGF(ERROR) << "Failed to add the vendor tags of camera module "
                    << (m->common.name ? std::quoted(m->common.name)
                                       : std::quoted("unknown"));
        std::move(callback).Run(false);
        return;
      }
    }
  }

  if (set_camera_metadata_vendor_ops(&vendor_tag_manager_) != 0) {
    LOGF(ERROR) << "Failed to set vendor ops to camera metadata";
  }

  const bool force_start =
      base::PathExists(base::FilePath(constants::kForceStartCrosCameraPath));
  for (auto iter = camera_interfaces_.begin();
       iter != camera_interfaces_.end();) {
    camera_module_t* m = iter->first;
    if (m->init) {
      int ret = m->init();
      if (ret != 0) {
        if (force_start) {
          LOGF(WARNING) << "Disabled camera module "
                        << std::quoted(m->common.name)
                        << " to force start cros-camera";
          iter = camera_interfaces_.erase(iter);
          continue;
        }
        LOGF(ERROR) << "Failed to init camera module "
                    << std::quoted(m->common.name);
        std::move(callback).Run(false);
        return;
      }
    }
    iter++;
  }
  CHECK_GT(camera_interfaces_.size(), 0);

  std::vector<std::tuple<int, int, int>> cameras;
  std::vector<std::vector<bool>> has_flash_unit(camera_interfaces_.size());
  // TODO(b/188111097): The mapping mechanism below is really complicated.
  // Extract the logic to a dedicated class and add unittest coverage.
  std::set<std::tuple<int, int, int>> unexposed_physical_cameras;
  std::vector<std::map<int, std::vector<int>>> internal_physical_camera_id_map(
      camera_interfaces_.size());

  camera_id_inverse_map_.resize(camera_interfaces_.size());
  for (size_t module_id = 0; module_id < camera_interfaces_.size();
       module_id++) {
    camera_module_t* m = camera_interfaces_[module_id].first;

    int n = m->get_number_of_cameras();
    LOGF(INFO) << "Camera module " << std::quoted(m->common.name) << " has "
               << n << " built-in camera(s)";

    auto aux = std::make_unique<CameraModuleCallbacksAux>();
    aux->camera_device_status_change = camera_device_status_change;
    aux->torch_mode_status_change = torch_mode_status_change;
    aux->module_id = module_id;
    aux->adapter = this;
    if (m->set_callbacks(aux.get()) != 0) {
      LOGF(ERROR) << "Failed to set_callbacks on camera module " << module_id;
      std::move(callback).Run(false);
      return;
    }
    callbacks_auxs_.push_back(std::move(aux));

    for (int camera_id = 0; camera_id < n; camera_id++) {
      camera_info_t info;
      if (m->get_camera_info(camera_id, &info) != 0) {
        LOGF(ERROR) << "Failed to get info of camera " << camera_id
                    << " from module " << module_id;
        std::move(callback).Run(false);
        return;
      }

      camera_metadata_ro_entry_t entry;
      if (find_camera_metadata_ro_entry(info.static_camera_characteristics,
                                        ANDROID_FLASH_INFO_AVAILABLE,
                                        &entry) != 0) {
        LOGF(ERROR) << "Failed to get flash info in metadata of camera "
                    << camera_id << " from module " << module_id;
        std::move(callback).Run(false);
        return;
      }

      cameras.emplace_back(info.facing, static_cast<int>(module_id), camera_id);
      has_flash_unit[module_id].push_back(entry.data.u8[0] ==
                                          ANDROID_FLASH_INFO_AVAILABLE_TRUE);

      // Determine if this is a logical multi-camera and create mappings for
      // its physical camera IDs if true.
      if (find_camera_metadata_ro_entry(info.static_camera_characteristics,
                                        ANDROID_REQUEST_AVAILABLE_CAPABILITIES,
                                        &entry) != 0) {
        LOGF(ERROR) << "Failed to find ANDROID_REQUEST_AVAILABLE_CAPABILITIES "
                       "from camera "
                    << camera_id << " from module " << module_id;
        std::move(callback).Run(false);
        return;
      }
      if (std::find(
              entry.data.u8, entry.data.u8 + entry.count,
              ANDROID_REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA) ==
          entry.data.u8 + entry.count) {
        // Not a logical multi-camera.
        continue;
      }
      // Find all the physical camera IDs backing this logical multi-camera.
      if (find_camera_metadata_ro_entry(
              info.static_camera_characteristics,
              ANDROID_LOGICAL_MULTI_CAMERA_PHYSICAL_IDS, &entry) != 0) {
        LOGF(ERROR)
            << "Failed to get the list of physical camera IDs for camera "
            << camera_id;
        std::move(callback).Run(false);
        return;
      }
      auto& physical_camera_ids =
          internal_physical_camera_id_map[module_id][camera_id];
      int start = 0;
      for (int i = 0; i < entry.count; ++i) {
        if (entry.data.u8[i] == '\0') {
          if (start != i) {
            int physical_camera_id;
            const char* physical_camera_id_str =
                reinterpret_cast<const char*>(entry.data.u8) + start;
            if (!base::StringToInt(physical_camera_id_str,
                                   &physical_camera_id)) {
              LOGF(ERROR) << "Invalid physical camera ID: "
                          << physical_camera_id_str;
              std::move(callback).Run(false);
              return;
            }
            physical_camera_ids.push_back(physical_camera_id);
            if (physical_camera_id >= n) {  // unexposed physical camera
              unexposed_physical_cameras.emplace(
                  info.facing, static_cast<int>(module_id), physical_camera_id);
            }
          }
          start = i + 1;
        }
      }
    }
  }

  num_builtin_cameras_ = cameras.size();
  sort(cameras.begin(), cameras.end());
  // Ordering is important here. Unexposed physical camera IDs should be >=
  // |n| where |n| is the number of builtin cameras.
  cameras.insert(cameras.end(), unexposed_physical_cameras.begin(),
                 unexposed_physical_cameras.end());
  for (size_t i = 0; i < cameras.size(); i++) {
    int module_id = std::get<1>(cameras[i]);
    int camera_id = std::get<2>(cameras[i]);
    camera_id_map_[i] = std::make_pair(module_id, camera_id);
    camera_id_inverse_map_[module_id][camera_id] = i;
    device_status_map_[i] = CAMERA_DEVICE_STATUS_PRESENT;
    default_device_status_map_[i] = device_status_map_[i];
    torch_mode_status_map_[i] = has_flash_unit[module_id][camera_id]
                                    ? TORCH_MODE_STATUS_AVAILABLE_OFF
                                    : TORCH_MODE_STATUS_NOT_AVAILABLE;
    default_torch_mode_status_map_[i] = torch_mode_status_map_[i];
  }

  // Now we map internal physical camera IDs to public and store the mappings
  // in |physical_camera_id_map_|.
  for (int module_id = 0; module_id < internal_physical_camera_id_map.size();
       ++module_id) {
    const auto& module_physical_camera_id_map =
        internal_physical_camera_id_map[module_id];
    for (const auto& [internal_camera_id, internal_physical_camera_ids] :
         module_physical_camera_id_map) {
      int camera_id = camera_id_inverse_map_[module_id][internal_camera_id];
      auto& physical_camera_ids = physical_camera_id_map_[camera_id];
      for (int i = 0; i < internal_physical_camera_ids.size(); ++i) {
        std::string physical_camera_id = base::NumberToString(
            camera_id_inverse_map_[module_id][internal_physical_camera_ids[i]]);
        if (i > 0) {
          physical_camera_ids += '\0';
        }
        physical_camera_ids += physical_camera_id;
      }
    }
  }

  next_external_camera_id_ = cameras.size();

  LOGF(INFO) << "SuperHAL started with " << camera_interfaces_.size()
             << " modules, " << num_builtin_cameras_ << " built-in cameras"
             << " and " << unexposed_physical_cameras.size()
             << " unexposed physical cameras";

  std::move(callback).Run(true);
}

void CameraHalAdapter::NotifyCameraDeviceStatusChange(
    CameraModuleCallbacksAssociatedDelegate* delegate,
    int camera_id,
    camera_device_status_t status) {
  delegate->CameraDeviceStatusChange(camera_id, status);
}

void CameraHalAdapter::NotifyTorchModeStatusChange(
    CameraModuleCallbacksAssociatedDelegate* delegate,
    int camera_id,
    torch_mode_status_t status) {
  delegate->TorchModeStatusChange(camera_id, status);
}

std::pair<camera_module_t*, int> CameraHalAdapter::GetInternalModuleAndId(
    int camera_id) {
  if (camera_id_map_.find(camera_id) == camera_id_map_.end()) {
    LOGF(ERROR) << "Invalid camera id: " << camera_id;
    return {};
  }
  std::pair<int, int> idx = camera_id_map_[camera_id];
  return {camera_interfaces_[idx.first].first, idx.second};
}

int CameraHalAdapter::GetInternalId(int camera_id) {
  camera_module_t* camera_module;
  int internal_camera_id;
  std::tie(camera_module, internal_camera_id) =
      GetInternalModuleAndId(camera_id);
  return internal_camera_id;
}

int CameraHalAdapter::GetPublicId(int module_id, int camera_id) {
  if (module_id < 0 ||
      static_cast<size_t>(module_id) >= camera_id_inverse_map_.size()) {
    return -1;
  }

  std::map<int, int>& id_map = camera_id_inverse_map_[module_id];
  auto it = id_map.find(camera_id);
  return it != id_map.end() ? it->second : -1;
}

void CameraHalAdapter::CloseDevice(int32_t camera_id,
                                   mojom::CameraClientType camera_client_type) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("client_type", camera_client_type, "camera_id", camera_id);

  LOGF(INFO) << camera_client_type << ", camera_id = " << camera_id;
  if (device_adapters_.find(camera_id) == device_adapters_.end()) {
    LOGF(ERROR) << "Failed to close camera device " << camera_id
                << ": device is not opened";
    return;
  }
  device_adapters_.erase(camera_id);

  activity_callback_.Run(camera_id, /*opened=*/false, camera_client_type);

  camera_metrics_->SendSessionDuration(session_timer_map_[camera_id].Elapsed());
  session_timer_map_.erase(camera_id);

  if (root_gpu_resources_) {
    root_gpu_resources_->gpu_task_runner()->PostTask(
        FROM_HERE, base::BindOnce([]() {
          // To end the last event posted by the camera device on the GPU thread
          // properly.
          PERFETTO_INTERNAL_ADD_EMPTY_EVENT();
        }));
  }
}

void CameraHalAdapter::ResetModuleDelegateOnThread(uint32_t module_id) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock l(module_delegates_lock_);
  if (module_id == kIdAll) {
    module_delegates_.clear();
  } else {
    module_delegates_.erase(module_id);
  }
}

void CameraHalAdapter::ResetCallbacksDelegateOnThread(uint32_t callbacks_id) {
  DCHECK(
      camera_module_callbacks_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock l(callbacks_delegates_lock_);
  if (callbacks_id == kIdAll) {
    callbacks_delegates_.clear();
  } else {
    callbacks_delegates_.erase(callbacks_id);
  }
}

void CameraHalAdapter::ResetVendorTagOpsDelegateOnThread(
    uint32_t vendor_tag_ops_id) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  base::AutoLock l(module_delegates_lock_);
  if (vendor_tag_ops_id == kIdAll) {
    vendor_tag_ops_delegates_.clear();
  } else {
    vendor_tag_ops_delegates_.erase(vendor_tag_ops_id);
  }
}

int32_t CameraHalAdapter::SetCallbacks(
    mojo::PendingAssociatedRemote<mojom::CameraModuleCallbacks> callbacks) {
  DCHECK(camera_module_thread_.task_runner()->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  auto callbacks_delegate =
      std::make_unique<CameraModuleCallbacksAssociatedDelegate>(
          camera_module_callbacks_thread_.task_runner());
  uint32_t callbacks_id = callbacks_id_++;
  callbacks_delegate->Bind(
      std::move(callbacks),
      base::BindOnce(&CameraHalAdapter::ResetCallbacksDelegateOnThread,
                     base::Unretained(this), callbacks_id));

  // Send latest status to the new client, so all presented external cameras
  // are available to the client after SetCallbacks() returns.
  for (const auto& it : device_status_map_) {
    int camera_id = it.first;
    camera_device_status_t device_status = it.second;
    if (device_status != default_device_status_map_[camera_id]) {
      NotifyCameraDeviceStatusChange(callbacks_delegate.get(), camera_id,
                                     device_status);
    }
    torch_mode_status_t torch_status = torch_mode_status_map_[camera_id];
    if (torch_status != default_torch_mode_status_map_[camera_id]) {
      NotifyTorchModeStatusChange(callbacks_delegate.get(), camera_id,
                                  torch_status);
    }
  }

  base::AutoLock l(callbacks_delegates_lock_);
  callbacks_delegates_[callbacks_id] = std::move(callbacks_delegate);

  return 0;
}

}  // namespace cros
