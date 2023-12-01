/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/camera_hal.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/no_destructor.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>

#include "cros-camera/common.h"
#include "cros-camera/constants.h"
#include "cros-camera/cros_camera_hal.h"
#include "cros-camera/udev_watcher.h"
#include "cros-camera/utils/camera_config.h"
#include "hal/usb/camera_characteristics.h"
#include "hal/usb/common_types.h"
#include "hal/usb/metadata_handler.h"
#include "hal/usb/quirks.h"
#include "hal/usb/stream_format.h"
#include "hal/usb/v4l2_camera_device.h"
#include "hal/usb/vendor_tag.h"

namespace cros {

namespace {

// https://developer.android.com/reference/android/hardware/camera2/CameraCharacteristics#SENSOR_INFO_EXPOSURE_TIME_RANGE
constexpr int64_t kMaxMinExposureTime = 100000;  // 100us

bool FillMetadata(const DeviceInfo& device_info,
                  android::CameraMetadata* static_metadata,
                  android::CameraMetadata* request_metadata) {
  if (MetadataHandler::FillDefaultMetadata(static_metadata, request_metadata) !=
      0) {
    return false;
  }

  if (MetadataHandler::FillMetadataFromDeviceInfo(device_info, static_metadata,
                                                  request_metadata) != 0) {
    return false;
  }

  SupportedFormats supported_formats =
      V4L2CameraDevice::GetDeviceSupportedFormats(device_info.device_path);
  SupportedFormats qualified_formats =
      GetQualifiedFormats(supported_formats, device_info.quirks);
  if (MetadataHandler::FillMetadataFromSupportedFormats(
          qualified_formats, device_info, static_metadata, request_metadata) !=
      0) {
    return false;
  }

  if (!device_info.usb_vid.empty()) {
    static_metadata->update(kVendorTagVendorId, device_info.usb_vid);
  }
  if (!device_info.usb_pid.empty()) {
    static_metadata->update(kVendorTagProductId, device_info.usb_pid);
  }
  static_metadata->update(kVendorTagDevicePath, device_info.device_path);
  static_metadata->update(kVendorTagModelName, V4L2CameraDevice::GetModelName(
                                                   device_info.device_path));

  return true;
}

void AdjustMetadataForAE(android::CameraMetadata* data) {
  camera_metadata_entry_t entry =
      data->find(ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE);
  if (entry.count == 0) {
    return;
  }

  if (entry.data.i64[0] <= kMaxMinExposureTime)
    return;

  LOGF(INFO) << "Remove AE related metadata";

  if (data->erase(ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE) != 0)
    LOGF(WARNING) << "Fail to delete ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE";

  data->update(ANDROID_CONTROL_AE_AVAILABLE_MODES,
               std::vector<uint8_t>{ANDROID_CONTROL_AE_MODE_ON});

  // Remove ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE in
  // ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS
  entry = data->find(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS);
  if (entry.count != 0) {
    std::vector<int32_t> available_characteristics_keys;
    for (size_t i = 0; i < entry.count; i++) {
      if (entry.data.i32[i] == ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE) {
        continue;
      }
      available_characteristics_keys.push_back(entry.data.i32[i]);
    }
    data->update(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS,
                 available_characteristics_keys);
  }
  // Remove ANDROID_SENSOR_EXPOSURE_TIME in
  // ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS
  entry = data->find(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
  if (entry.count != 0) {
    std::vector<int32_t> available_request_keys;
    for (size_t i = 0; i < entry.count; i++) {
      if (entry.data.i32[i] == ANDROID_SENSOR_EXPOSURE_TIME) {
        continue;
      }
      available_request_keys.push_back(entry.data.i32[i]);
    }
    data->update(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
                 available_request_keys);
  }
}

// TODO(mojahsu): Make it work on android side.
void AdjustMetadataForFaceDetection(android::CameraMetadata* data) {
  camera_metadata_entry_t entry =
      data->find(ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES);
  // Only support ANDROID_STATISTICS_FACE_DETECT_MODE_OFF or no such metadata.
  if (entry.count <= 1) {
    return;
  }

  LOGF(INFO) << "Remove Face Detection related metadata";

  data->update(ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES,
               std::vector<uint8_t>{ANDROID_STATISTICS_FACE_DETECT_MODE_OFF});
  data->update(ANDROID_STATISTICS_INFO_MAX_FACE_COUNT, std::vector<int32_t>{0});
}

ScopedCameraMetadata StaticMetadataForAndroid(
    const android::CameraMetadata& static_metadata,
    const DeviceInfo& device_info) {
  android::CameraMetadata data(static_metadata);
  std::vector<int32_t> stream_configurations;

  if (device_info.quirks & kQuirkAndroidExternal) {
    data.update(
        ANDROID_LENS_FACING,
        std::vector<uint8_t>{static_cast<uint8_t>(LensFacing::kExternal)});
    data.update(
        ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL,
        std::vector<uint8_t>{ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL});
  }

  if (device_info.quirks & kQuirkAndroidLegacy) {
    data.update(
        ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL,
        std::vector<uint8_t>{ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY});
  }

  std::unique_ptr<CameraConfig> camera_config =
      CameraConfig::Create(constants::kCrosCameraConfigPathString);
  int max_width =
      camera_config->GetInteger(constants::kCrosUsbAndroidMaxStreamWidth,
                                std::numeric_limits<int>::max());
  int max_height =
      camera_config->GetInteger(constants::kCrosUsbAndroidMaxStreamHeight,
                                std::numeric_limits<int>::max());
  camera_metadata_entry entry =
      data.find(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS);

  for (size_t i = 0; i < entry.count; i += 4) {
    if (entry.data.i32[i] != HAL_PIXEL_FORMAT_BLOB) {
      if (entry.data.i32[i + 1] > max_width ||
          entry.data.i32[i + 2] > max_height) {
        LOGF(INFO) << "Filter Format: 0x" << std::hex << entry.data.i32[i]
                   << std::dec << "-" << entry.data.i32[i + 1] << "x"
                   << entry.data.i32[i + 2] << " for Android";
        continue;
      }
    }
    stream_configurations.push_back(entry.data.i32[i]);
    stream_configurations.push_back(entry.data.i32[i + 1]);
    stream_configurations.push_back(entry.data.i32[i + 2]);
    stream_configurations.push_back(entry.data.i32[i + 3]);
  }
  data.update(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
              stream_configurations);

  AdjustMetadataForAE(&data);
  AdjustMetadataForFaceDetection(&data);

  return ScopedCameraMetadata(data.release());
}

ScopedCameraMetadata RequestTemplateForAndroid(
    const camera_metadata_t* static_metadata,
    const android::CameraMetadata& request_template) {
  android::CameraMetadata data(request_template);

  camera_metadata_ro_entry ae_available_modes_entry;
  int ret = find_camera_metadata_ro_entry(static_metadata,
                                          ANDROID_CONTROL_AE_AVAILABLE_MODES,
                                          &ae_available_modes_entry);
  if (ret == 0) {
    // Only support ANDROID_CONTROL_AE_MODE_ON
    if (ae_available_modes_entry.count == 1) {
      camera_metadata_entry entry = data.find(ANDROID_SENSOR_EXPOSURE_TIME);
      if (entry.count == 1 && data.erase(ANDROID_SENSOR_EXPOSURE_TIME) != 0)
        LOGF(WARNING) << "Failed to delete ANDROID_SENSOR_EXPOSURE_TIME";
    }
  }

  return ScopedCameraMetadata(data.release());
}

bool IsVivid(udev_device* dev) {
  const char* product = udev_device_get_property_value(dev, "ID_V4L_PRODUCT");
  return product && strcmp(product, "vivid") == 0;
}

const char* GetPreferredPath(udev_device* dev) {
  if (IsVivid(dev)) {
    // Multiple vivid devices may have the same symlink at
    // /dev/v4l/by-path/platform-vivid.0-video-index0, so we use /dev/videoX
    // directly for vivid.
    return udev_device_get_devnode(dev);
  }

  const char* found_entry_name = nullptr;
  for (udev_list_entry* entry = udev_device_get_devlinks_list_entry(dev);
       entry != nullptr; entry = udev_list_entry_get_next(entry)) {
    const char* name = udev_list_entry_get_name(entry);

    if (!name) {
      LOGF(WARNING) << "udev_list_entry_get_name failed";
      continue;
    }

    // The symlinks in /dev/v4l/by-path/ are generated by
    // 60-persistent-v4l.rules, and supposed to be persistent for built-in
    // cameras so we can safely reuse it across suspend/resume cycles, without
    // updating |path_to_id_| for them.
    if (!base::StartsWith(name, "/dev/v4l/by-path/",
                          base::CompareCase::SENSITIVE)) {
      continue;
    }

    // There are two kinds of ID path.
    // 1. With USB revision (e.g. {PATH}-usbv{REVISION}-0:{PORT})
    // 2. Without USB revision (e.g. {PATH}-usb-0:{PORT})
    // Always prefer the former one if it presents.
    if (found_entry_name == nullptr ||
        base::StringPiece(name).find("-usbv") != base::StringPiece::npos) {
      found_entry_name = name;
    }
  }
  if (found_entry_name != nullptr) {
    return found_entry_name;
  }
  return udev_device_get_devnode(dev);
}

std::string GetModelId(const DeviceInfo& info) {
  if (info.is_vivid) {
    return "vivid";
  }
  return base::JoinString({info.usb_vid, info.usb_pid}, ":");
}

}  // namespace

CameraHal::CameraHal()
    : task_runner_(nullptr),
      udev_watcher_(std::make_unique<UdevWatcher>(this, "video4linux")),
      cros_device_config_(DeviceConfig::Create()),
      camera_metrics_(CameraMetrics::New()) {
  thread_checker_.DetachFromThread();
}

CameraHal::~CameraHal() {
  udev_watcher_.reset();
}

int CameraHal::GetNumberOfCameras() const {
  return num_builtin_cameras_;
}

CameraHal& CameraHal::GetInstance() {
  static base::NoDestructor<CameraHal> camera_hal;
  return *camera_hal;
}

CameraMojoChannelManagerToken* CameraHal::GetMojoManagerToken() {
  return mojo_manager_token_;
}

int CameraHal::OpenDevice(int id,
                          const hw_module_t* module,
                          hw_device_t** hw_device,
                          ClientType client_type) {
  VLOGFID(1, id);
  DCHECK(thread_checker_.CalledOnValidThread());
  if (!IsValidCameraId(id)) {
    LOGF(ERROR) << "Camera id " << id << " is invalid";
    return -EINVAL;
  }

  if (cameras_.find(id) != cameras_.end()) {
    LOGF(ERROR) << "Camera " << id << " is already opened";
    return -EBUSY;
  }
  if (!cameras_.empty() &&
      (cros_device_config_.has_value() &&
       (cros_device_config_->GetModelName() == "treeya360" ||
        cros_device_config_->GetModelName() == "nuwani360" ||
        cros_device_config_->GetModelName() == "pompom"))) {
    // It cannot open multiple cameras at the same time due to USB bandwidth
    // limitation (b/147333530, b/171856355).
    // TODO(shik): Use |conflicting_devices| to implement this logic after we
    // hook that in the ARC++ camera HAL shim.
    // TODO(b/163436311): Add a new field in the unibuild schema instead of
    // checking model name here.
    LOGF(WARNING) << "Can't open Camera " << id << " because Camera "
                  << cameras_.begin()->first << " is already opened.";
    return -EUSERS;
  }

  camera_metadata_t* static_metadata;
  camera_metadata_t* request_template;
  if (client_type == ClientType::kAndroid) {
    static_metadata = static_metadata_android_[id].get();
    request_template = request_template_android_[id].get();
  } else {
    static_metadata = static_metadata_[id].get();
    request_template = request_template_[id].get();
  }
  const auto& device_info = device_infos_[id];
  // Force disable HW privacy switch if the config doesn't declare it.  This is
  // to block privacy switch signal that is not HW based (b/273675069).
  auto* hw_privacy_switch_monitor_for_client =
      device_info.has_privacy_switch ? &hw_privacy_switch_monitor_ : nullptr;
  cameras_[id] = std::make_unique<CameraClient>(
      id, device_info, *static_metadata, *request_template, module, hw_device,
      hw_privacy_switch_monitor_for_client, client_type, sw_privacy_switch_on_);
  if (cameras_[id]->OpenDevice()) {
    cameras_.erase(id);
    return -ENODEV;
  }
  if (!task_runner_) {
    task_runner_ = base::SingleThreadTaskRunner::GetCurrentDefault();
  }
  return 0;
}

bool CameraHal::IsValidCameraId(int id) {
  return device_infos_.find(id) != device_infos_.end();
}

int CameraHal::GetCameraInfo(int id,
                             struct camera_info* info,
                             ClientType client_type) {
  VLOGFID(1, id);
  DCHECK(thread_checker_.CalledOnValidThread());
  if (!IsValidCameraId(id)) {
    LOGF(ERROR) << "Camera id " << id << " is invalid";
    return -EINVAL;
  }

  switch (device_infos_[id].lens_facing) {
    case LensFacing::kFront:
      info->facing = CAMERA_FACING_FRONT;
      break;
    case LensFacing::kBack:
      info->facing = CAMERA_FACING_BACK;
      break;
    case LensFacing::kExternal:
      info->facing = CAMERA_FACING_EXTERNAL;
      break;
    default:
      LOGF(ERROR) << "Unknown lens facing: "
                  << static_cast<int>(device_infos_[id].lens_facing);
      return -EINVAL;
  }
  info->orientation = device_infos_[id].sensor_orientation;
  info->device_version = CAMERA_DEVICE_API_VERSION_3_5;
  if (client_type == ClientType::kAndroid) {
    info->static_camera_characteristics = static_metadata_android_[id].get();
  } else {
    info->static_camera_characteristics = static_metadata_[id].get();
  }
  info->resource_cost = 0;
  info->conflicting_devices = nullptr;
  info->conflicting_devices_length = 0;
  return 0;
}

void CameraHal::SetPrivacySwitchState(bool on) {
  if (sw_privacy_switch_on_ == on) {
    return;
  }
  sw_privacy_switch_on_ = on;
  for (const auto& [_, camera_client] : cameras_) {
    camera_client->SetPrivacySwitchState(on);
  }
}

int CameraHal::GetCameraInfo(int id, struct camera_info* info) {
  return GetCameraInfo(id, info, ClientType::kChrome);
}

int CameraHal::SetCallbacks(const camera_module_callbacks_t* callbacks) {
  VLOGF(1) << "New callbacks = " << callbacks;
  DCHECK(thread_checker_.CalledOnValidThread());

  callbacks_ = callbacks;

  // Some external cameras might be detected before SetCallbacks, we should
  // enumerate existing devices again after setting the callbacks.
  if (!udev_watcher_->EnumerateExistingDevices()) {
    LOGF(ERROR) << "Failed to EnumerateExistingDevices()";
  }

  return 0;
}

int CameraHal::Init() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!cros_device_config_.has_value()) {
    LOGF(WARNING) << "Failed to initialize CrOS device config, camera HAL may "
                     "function incorrectly";
  }

  if (!udev_watcher_->Start(
          base::SingleThreadTaskRunner::GetCurrentDefault())) {
    LOGF(ERROR) << "Failed to Start()";
    return -ENODEV;
  }

  if (!udev_watcher_->EnumerateExistingDevices()) {
    LOGF(ERROR) << "Failed to EnumerateExistingDevices()";
    return -ENODEV;
  }

  // TODO(shik): Some unibuild devices like vayne may have only user-facing
  // camera as "camera1" in |characteristics_|. It's a workaround for them until
  // we revise our config format. (b/111770440)
  if (device_infos_.size() == 1 && device_infos_.cbegin()->first == 1 &&
      num_builtin_cameras_ == 1) {
    LOGF(INFO) << "Renumber camera1 to camera0";

    device_infos_.emplace(0, std::move(device_infos_[1]));
    device_infos_.erase(1);
    device_infos_[0].camera_id = 0;

    DCHECK_EQ(path_to_id_.size(), 1);
    DCHECK_EQ(path_to_id_.begin()->second, 1);
    path_to_id_.begin()->second = 0;

    DCHECK_EQ(static_metadata_.size(), 1);
    DCHECK_EQ(static_metadata_.begin()->first, 1);
    static_metadata_.emplace(0, std::move(static_metadata_[1]));
    static_metadata_.erase(1);

    DCHECK_EQ(static_metadata_android_.size(), 1);
    DCHECK_EQ(static_metadata_android_.begin()->first, 1);
    static_metadata_android_.emplace(0, std::move(static_metadata_android_[1]));
    static_metadata_android_.erase(1);

    DCHECK_EQ(request_template_.size(), 1);
    DCHECK_EQ(request_template_.begin()->first, 1);
    request_template_.emplace(0, std::move(request_template_[1]));
    request_template_.erase(1);

    DCHECK_EQ(request_template_android_.size(), 1);
    DCHECK_EQ(request_template_android_.begin()->first, 1);
    request_template_android_.emplace(0,
                                      std::move(request_template_android_[1]));
    request_template_android_.erase(1);
  }

  bool enough_camera_probed = true;
  std::optional<int> num_builtin_cameras_from_config;
  if (cros_device_config_) {
    num_builtin_cameras_from_config = cros_device_config_->GetCameraCount(
        Interface::kUsb, /*detachable=*/false);
  }
  if (num_builtin_cameras_from_config.has_value()) {
    if (num_builtin_cameras_ != *num_builtin_cameras_from_config) {
      LOGF(ERROR) << "Expected " << *num_builtin_cameras_from_config
                  << " cameras from cros_config, found "
                  << num_builtin_cameras_;
      enough_camera_probed = false;
    }
  } else if (CameraCharacteristics::ConfigFileExists() &&
             num_builtin_cameras_ == 0) {
    // TODO(shik): possible race here. We may have 2 built-in cameras but just
    // detect one.
    LOGF(ERROR) << "Expect to find at least one camera if config file exists";
    enough_camera_probed = false;
  }
  if (!enough_camera_probed) {
    if (base::PathExists(
            base::FilePath(constants::kForceStartCrosCameraPath))) {
      LOGF(WARNING) << "Force starting cros-camera: Ignore missing built-in "
                    << "camera error to allow external camera usage";
    } else {
      return -ENODEV;
    }
  }

  for (int i = 0; i < num_builtin_cameras_; i++) {
    if (!IsValidCameraId(i)) {
      LOGF(ERROR)
          << "The camera devices should be numbered 0 through N-1, but id = "
          << i << " is missing";
      return -ENODEV;
    }
  }

  next_external_camera_id_ = num_builtin_cameras_;
  return 0;
}

void CameraHal::SetUp(CameraMojoChannelManagerToken* token) {
  mojo_manager_token_ = token;
}

void CameraHal::TearDown() {
  mojo_manager_token_ = nullptr;
}

void CameraHal::SetPrivacySwitchCallback(
    PrivacySwitchStateChangeCallback callback) {
  hw_privacy_switch_monitor_.RegisterCallback(std::move(callback));
}

void CameraHal::CloseDeviceOnOpsThread(int id) {
  DCHECK(task_runner_);
  auto future = cros::Future<void>::Create(nullptr);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&CameraHal::CloseDevice, base::Unretained(this),
                                id, base::RetainedRef(future)));
  future->Wait();
}

void CameraHal::CloseDevice(int id, scoped_refptr<cros::Future<void>> future) {
  VLOGFID(1, id);
  DCHECK(thread_checker_.CalledOnValidThread());

  if (cameras_.find(id) == cameras_.end()) {
    LOGF(ERROR) << "Failed to close camera device " << id
                << ": device is not opened";
    future->Set();
    return;
  }
  cameras_.erase(id);
  future->Set();
}

void CameraHal::OnDeviceAdded(ScopedUdevDevicePtr dev) {
  const char* path = GetPreferredPath(dev.get());
  if (!path) {
    LOGF(ERROR) << "udev_device_get_devnode failed";
    return;
  }

  const char* vid = "";
  const char* pid = "";
  const char* bcdDevice = "";

  bool is_vivid = IsVivid(dev.get());
  if (!is_vivid) {
    udev_device* parent_dev = udev_device_get_parent_with_subsystem_devtype(
        dev.get(), "usb", "usb_device");
    if (!parent_dev) {
      VLOGF(2) << "Non USB device is ignored";
      return;
    }

    vid = udev_device_get_sysattr_value(parent_dev, "idVendor");
    if (!vid) {
      LOGF(ERROR) << "Failed to get vid";
      return;
    }

    pid = udev_device_get_sysattr_value(parent_dev, "idProduct");
    if (!pid) {
      LOGF(ERROR) << "Failed to get pid";
      return;
    }

    // Usually, this attribute corresponds to the firmware version, but it
    // might not be set properly on all modules currently. We may have a better
    // way to determine the firmware version after landing the new USB camera
    // firmware update requirements.
    bcdDevice = udev_device_get_sysattr_value(parent_dev, "bcdDevice");
    if (!bcdDevice) {
      LOGF(ERROR) << "Failed to get bcdDevice";
      return;
    }
  }

  {
    // We have to check this because of:
    //  1. Limitation of libudev
    //  2. Reenumeration after SetCallbacks()
    //  3. Suspend/Resume
    auto it = path_to_id_.find(path);
    if (it != path_to_id_.end()) {
      int id = it->second;
      const DeviceInfo& info = device_infos_[id];
      if (info.usb_vid == vid && info.usb_pid == pid) {
        VLOGF(1) << "Ignore " << path << " since it's already connected";
      } else {
        LOGF(ERROR) << "Device path conflict: " << path;
      }
      return;
    }
  }

  if (!V4L2CameraDevice::IsCameraDevice(path)) {
    VLOGF(1) << path << " is not a camera device";
    return;
  }

  DeviceInfo info;
  bool is_external = true;
  if (const DeviceInfo* info_ptr = characteristics_.Find(vid, pid)) {
    is_external = false;
    info = *info_ptr;
    const CrosConfigCameraInfo* cros_config_info =
        cros_device_config_
            ? cros_device_config_->GetCrosConfigInfoFromFacing(info.lens_facing)
            : nullptr;
    if (cros_config_info) {
      info.sensor_orientation = cros_config_info->orientation;
      info.is_detachable = cros_config_info->detachable;
      info.has_privacy_switch = cros_config_info->has_privacy_switch;
    }
    if (info.constant_framerate_unsupported) {
      LOGF(WARNING) << "Camera module " << vid << ":" << pid
                    << " does not support constant frame rate";
    }
  }

  if (is_vivid) {
    LOGF(INFO) << "New vivid camera device at " << path;
  } else {
    LOGF(INFO) << "New "
               << (is_external
                       ? "external"
                       : (info.is_detachable ? "detachable" : "built-in"))
               << " camera device " << V4L2CameraDevice::GetModelName(path)
               << ", vid:pid = " << vid << ":" << pid
               << ", bcdDevice = " << bcdDevice << " at " << path;
  }
  if ((is_external || info.is_detachable) && !callbacks_) {
    VLOGF(1) << "No callbacks set, ignore it for now";
    return;
  }

  info.device_path = path;
  info.usb_vid = vid;
  info.usb_pid = pid;
  info.is_vivid = is_vivid;
  info.constant_framerate_unsupported |=
      !V4L2CameraDevice::IsControlSupported(path, kControlExposureAutoPriority);
  RoiControl roi_control;
  info.region_of_interest_supported =
      V4L2CameraDevice::IsRegionOfInterestSupported(path, &roi_control);

  if (info.region_of_interest_supported) {
    if (!info.enable_face_detection) {
      camera_metrics_->SendFaceAeFunction(FaceAeFunction::kNotEnabled);
    } else if (base::PathExists(
                   base::FilePath(constants::kForceDisableFaceAePath))) {
      camera_metrics_->SendFaceAeFunction(FaceAeFunction::kForceDisabled);
    } else {
      camera_metrics_->SendFaceAeFunction(FaceAeFunction::kEnabled);
    }
  } else {
    camera_metrics_->SendFaceAeFunction(FaceAeFunction::kUnsupported);
  }
  // The force control path is managed by chrome flag, there should be only one
  // file.
  if (base::PathExists(base::FilePath(constants::kForceEnableFaceAePath))) {
    LOGF(INFO) << "force enable face ae";
    info.enable_face_detection = true;
  }
  if (base::PathExists(base::FilePath(constants::kForceDisableFaceAePath))) {
    LOGF(INFO) << "force disable face ae";
    info.enable_face_detection = false;
  }
  if (!is_vivid) {
    info.quirks |= GetQuirks(vid, pid);
  }

  if (info.quirks & kQuirkInfrared) {
    LOGF(INFO) << "Ignoring infrared camera";
    return;
  }

  // Mark the camera as v1 if it is a built-in camera and the CrOS device is
  // marked as a v1 device.
  if (!is_external && cros_device_config_.has_value() &&
      cros_device_config_->IsV1Device()) {
    info.quirks |= kQuirkV1Device;
  }

  // Treats detachable camera as external.
  if (is_external || info.is_detachable) {
    info.lens_facing = LensFacing::kExternal;

    // Try to reuse the same id for the same camera.
    std::string model_id = GetModelId(info);
    std::set<int>& preferred_ids = previous_ids_[model_id];
    if (!preferred_ids.empty()) {
      info.camera_id = *preferred_ids.begin();
      previous_ids_.erase(previous_ids_.begin());
      VLOGF(1) << "Use the previous id " << info.camera_id << " for camera "
               << model_id;
    } else {
      info.camera_id = next_external_camera_id_++;
      VLOGF(1) << "Use a new id " << info.camera_id << " for camera "
               << model_id;
    }

    // Uses software timestamp from userspace for external cameras, because the
    // hardware timestamp is not reliable and sometimes even jump backwards.
    // Exclude detachable camera modules on some devices.
    if (!info.is_detachable) {
      info.quirks |= kQuirkUserSpaceTimestamp;
    }
  }

  android::CameraMetadata static_metadata, request_template;
  if (!FillMetadata(info, &static_metadata, &request_template)) {
    if (info.lens_facing == LensFacing::kExternal) {
      LOGF(ERROR) << "FillMetadata failed, the new external "
                     "camera would be ignored";
      return;
    } else {
      LOGF(ERROR) << "FillMetadata failed for a built-in "
                     "camera, please check your camera config";
      return;
    }
  }

  if (info.lens_facing != LensFacing::kExternal) {
    num_builtin_cameras_++;
  }

  path_to_id_[info.device_path] = info.camera_id;
  device_infos_[info.camera_id] = info;
  static_metadata_android_[info.camera_id] =
      StaticMetadataForAndroid(static_metadata, info);
  request_template_android_[info.camera_id] = RequestTemplateForAndroid(
      static_metadata_android_[info.camera_id].get(), request_template);
  static_metadata_[info.camera_id] =
      ScopedCameraMetadata(static_metadata.release());
  request_template_[info.camera_id] =
      ScopedCameraMetadata(request_template.release());

  if (info.has_privacy_switch) {
    hw_privacy_switch_monitor_.TrySubscribe(info.camera_id, info.device_path);
  }

  if (info.lens_facing == LensFacing::kExternal) {
    callbacks_->camera_device_status_change(callbacks_, info.camera_id,
                                            CAMERA_DEVICE_STATUS_PRESENT);
  }
}

void CameraHal::OnDeviceRemoved(ScopedUdevDevicePtr dev) {
  const char* path = GetPreferredPath(dev.get());
  if (!path) {
    LOGF(ERROR) << "udev_device_get_devnode failed";
    return;
  }

  auto it = path_to_id_.find(path);
  if (it == path_to_id_.end()) {
    VLOGF(1) << "Cannot found id for " << path << ", ignore it";
    return;
  }

  int id = it->second;

  if (id < num_builtin_cameras_) {
    VLOGF(1) << "Camera " << id << " is a built-in camera, ignore it";
    return;
  }

  hw_privacy_switch_monitor_.Unsubscribe(id);

  LOGF(INFO) << "Camera " << id << " at " << path << " removed";

  // TODO(shik): Handle this more gracefully, sometimes it even trigger a kernel
  // panic.
  if (cameras_.find(id) != cameras_.end()) {
    LOGF(WARNING)
        << "Unplug an opening camera, exit the camera service to cleanup";
    // Upstart will start the service again.
    _exit(EIO);
  }

  previous_ids_[GetModelId(device_infos_[id])].insert(id);

  path_to_id_.erase(it);
  device_infos_.erase(id);
  static_metadata_.erase(id);
  static_metadata_android_.erase(id);
  request_template_.erase(id);
  request_template_android_.erase(id);

  if (callbacks_) {
    callbacks_->camera_device_status_change(callbacks_, id,
                                            CAMERA_DEVICE_STATUS_NOT_PRESENT);
  }
}

static int camera_device_open_ext(const hw_module_t* module,
                                  const char* name,
                                  hw_device_t** device,
                                  ClientType client_type) {
  // Make sure hal adapter loads the correct symbol.
  if (module != &HAL_MODULE_INFO_SYM.common) {
    LOGF(ERROR) << std::hex << "Invalid module 0x" << module << " expected 0x"
                << &HAL_MODULE_INFO_SYM.common << std::dec;
    return -EINVAL;
  }

  char* nameEnd;
  int id = strtol(name, &nameEnd, 10);
  if (*nameEnd != '\0') {
    LOGF(ERROR) << "Invalid camera name " << name;
    return -EINVAL;
  }

  return CameraHal::GetInstance().OpenDevice(id, module, device, client_type);
}

static int camera_device_open(const hw_module_t* module,
                              const char* name,
                              hw_device_t** device) {
  return camera_device_open_ext(module, name, device, ClientType::kChrome);
}

static int get_number_of_cameras() {
  return CameraHal::GetInstance().GetNumberOfCameras();
}

static int get_camera_info(int id, struct camera_info* info) {
  return CameraHal::GetInstance().GetCameraInfo(id, info);
}

static int set_callbacks(const camera_module_callbacks_t* callbacks) {
  return CameraHal::GetInstance().SetCallbacks(callbacks);
}

static void get_vendor_tag_ops(vendor_tag_ops_t* ops) {
  ops->get_all_tags = VendorTagOps::GetAllTags;
  ops->get_tag_count = VendorTagOps::GetTagCount;
  ops->get_section_name = VendorTagOps::GetSectionName;
  ops->get_tag_name = VendorTagOps::GetTagName;
  ops->get_tag_type = VendorTagOps::GetTagType;
}

static int open_legacy(const struct hw_module_t* /*module*/,
                       const char* /*id*/,
                       uint32_t /*halVersion*/,
                       struct hw_device_t** /*device*/) {
  return -ENOSYS;
}

static int set_torch_mode(const char* /*camera_id*/, bool /*enabled*/) {
  return -ENOSYS;
}

static int init() {
  return CameraHal::GetInstance().Init();
}

static void set_up(CameraMojoChannelManagerToken* token) {
  CameraHal::GetInstance().SetUp(token);
}

static void tear_down() {
  CameraHal::GetInstance().TearDown();
}

static void set_privacy_switch_callback(
    PrivacySwitchStateChangeCallback callback) {
  CameraHal::GetInstance().SetPrivacySwitchCallback(std::move(callback));
}

static int get_camera_info_ext(int id,
                               struct camera_info* info,
                               ClientType client_type) {
  return CameraHal::GetInstance().GetCameraInfo(id, info, client_type);
}

static void set_privacy_switch_state(bool on) {
  CameraHal::GetInstance().SetPrivacySwitchState(on);
}

int camera_device_close(struct hw_device_t* hw_device) {
  camera3_device_t* cam_dev = reinterpret_cast<camera3_device_t*>(hw_device);
  CameraClient* cam = static_cast<CameraClient*>(cam_dev->priv);
  if (!cam) {
    LOGF(ERROR) << "Camera device is NULL";
    return -EIO;
  }
  cam_dev->priv = NULL;
  int ret = cam->CloseDevice();
  CameraHal::GetInstance().CloseDeviceOnOpsThread(cam->GetId());
  return ret;
}

}  // namespace cros

static hw_module_methods_t gCameraModuleMethods = {
    .open = cros::camera_device_open};

camera_module_t HAL_MODULE_INFO_SYM CROS_CAMERA_EXPORT = {
    .common = {.tag = HARDWARE_MODULE_TAG,
               .module_api_version = CAMERA_MODULE_API_VERSION_2_4,
               .hal_api_version = HARDWARE_HAL_API_VERSION,
               .id = CAMERA_HARDWARE_MODULE_ID,
               .name = "V4L2 UVC Camera HAL v3",
               .author = "The ChromiumOS Authors",
               .methods = &gCameraModuleMethods,
               .dso = NULL,
               .reserved = {0}},
    .get_number_of_cameras = cros::get_number_of_cameras,
    .get_camera_info = cros::get_camera_info,
    .set_callbacks = cros::set_callbacks,
    .get_vendor_tag_ops = cros::get_vendor_tag_ops,
    .open_legacy = cros::open_legacy,
    .set_torch_mode = cros::set_torch_mode,
    .init = cros::init,
    .reserved = {0}};

cros::cros_camera_hal_t CROS_CAMERA_HAL_INFO_SYM CROS_CAMERA_EXPORT = {
    .set_up = cros::set_up,
    .tear_down = cros::tear_down,
    .set_privacy_switch_callback = cros::set_privacy_switch_callback,
    .camera_device_open_ext = cros::camera_device_open_ext,
    .get_camera_info_ext = cros::get_camera_info_ext,
    .set_privacy_switch_state = cros::set_privacy_switch_state};
