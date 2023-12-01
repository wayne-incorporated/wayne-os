/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/fake/camera_hal.h"

#include <algorithm>
#include <memory>
#include <utility>

#include <base/containers/contains.h>
#include <base/no_destructor.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/sequenced_task_runner.h>

#include "cros-camera/common.h"
#include "cros-camera/cros_camera_hal.h"

#include "hal/fake/metadata_handler.h"

namespace cros {

namespace {
// The default fake hal spec file. The file should contain a JSON that is
// parsed to HalSpec struct.
constexpr const char kDefaultFakeHalSpecFile[] = "/etc/camera/fake_hal.json";
constexpr const char kOverrideFakeHalSpecFile[] = "/run/camera/fake_hal.json";

int camera_device_open_ext(const hw_module_t* module,
                           const char* name,
                           hw_device_t** device,
                           ClientType client_type) {
  // Make sure hal adapter loads the correct symbol.
  if (module != &HAL_MODULE_INFO_SYM.common) {
    LOGF(ERROR) << "Invalid module " << module << " expected "
                << &HAL_MODULE_INFO_SYM.common;
    return -EINVAL;
  }

  int id;
  if (!base::StringToInt(name, &id)) {
    LOGF(ERROR) << "Invalid camera name " << name;
    return -EINVAL;
  }
  return CameraHal::GetInstance().OpenDevice(id, module, device, client_type);
}

int get_camera_info_ext(int id,
                        struct camera_info* info,
                        ClientType client_type) {
  return CameraHal::GetInstance().GetCameraInfo(id, info, client_type);
}

int camera_device_open(const hw_module_t* module,
                       const char* name,
                       hw_device_t** device) {
  return camera_device_open_ext(module, name, device, ClientType::kChrome);
}

int get_number_of_cameras() {
  return CameraHal::GetInstance().GetNumberOfCameras();
}

int get_camera_info(int id, struct camera_info* info) {
  return get_camera_info_ext(id, info, ClientType::kChrome);
}

int set_callbacks(const camera_module_callbacks_t* callbacks) {
  return CameraHal::GetInstance().SetCallbacks(callbacks);
}

int init() {
  return CameraHal::GetInstance().Init();
}

void set_up(CameraMojoChannelManagerToken* token) {
  CameraHal::GetInstance().SetUp(token);
}

void tear_down() {
  CameraHal::GetInstance().TearDown();
}

void set_privacy_switch_callback(PrivacySwitchStateChangeCallback callback) {
  CameraHal::GetInstance().SetPrivacySwitchCallback(callback);
}

int open_legacy(const struct hw_module_t* module,
                const char* id,
                uint32_t halVersion,
                struct hw_device_t** device) {
  return -ENOSYS;
}

int set_torch_mode(const char* camera_id, bool enabled) {
  return -ENOSYS;
}

}  // namespace

CameraHal::CameraHal() {
  // The constructor is first called by set_up which is not on the same
  // sequence as the other methods this class is run on.
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

CameraHal::~CameraHal() = default;

CameraHal& CameraHal::GetInstance() {
  // Leak the static camera HAL here, since it has a non-trivial destructor
  // (from ReloadableConfigFile -> base::FilePathWatcher).
  static base::NoDestructor<CameraHal> camera_hal;
  return *camera_hal;
}

int CameraHal::GetNumberOfCameras() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  return 0;
}

int CameraHal::SetCallbacks(const camera_module_callbacks_t* callbacks) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  callbacks_ = callbacks;
  ApplySpec({}, hal_spec_);

  return 0;
}

int CameraHal::Init() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  task_runner_ = base::SequencedTaskRunner::GetCurrentDefault();
  config_file_ = std::make_unique<ReloadableConfigFile>(
      ReloadableConfigFile::Options{base::FilePath(kDefaultFakeHalSpecFile),
                                    base::FilePath(kOverrideFakeHalSpecFile)});
  config_file_->SetCallback(
      base::BindRepeating(&CameraHal::OnSpecUpdated, base::Unretained(this)));

  return 0;
}

void CameraHal::SetUp(CameraMojoChannelManagerToken* token) {
  mojo_manager_token_ = token;
}

void CameraHal::TearDown() {}

void CameraHal::SetPrivacySwitchCallback(
    PrivacySwitchStateChangeCallback callback) {}

int CameraHal::OpenDevice(int id,
                          const hw_module_t* module,
                          hw_device_t** hw_device,
                          ClientType client_type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  VLOGFID(1, id);

  if (!IsCameraIdValid(id)) {
    LOGF(ERROR) << "Camera ID " << id << " is invalid";
    return -ENODEV;
  }

  auto it = std::find_if(hal_spec_.cameras.begin(), hal_spec_.cameras.end(),
                         [id](const auto& spec) { return spec.id == id; });
  CHECK(it != hal_spec_.cameras.end());

  cameras_[id] = std::make_unique<CameraClient>(
      id, static_metadata_[id], request_template_[id], module, hw_device, *it);

  int ret = cameras_[id]->OpenDevice();
  if (ret != 0) {
    cameras_.erase(id);
    return -ENODEV;
  }

  return 0;
}

bool CameraHal::IsCameraIdValid(int id) {
  return base::Contains(hal_spec_.cameras, id,
                        [](const auto& spec) { return spec.id; });
}

int CameraHal::GetCameraInfo(int id,
                             struct camera_info* info,
                             ClientType client_type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  VLOGFID(1, id);

  if (!IsCameraIdValid(id)) {
    LOGF(ERROR) << "Camera ID " << id << " is invalid";
    return -EINVAL;
  }

  info->facing = CAMERA_FACING_EXTERNAL;
  info->orientation = 0;
  info->device_version = CAMERA_DEVICE_API_VERSION_3_5;
  info->static_camera_characteristics = static_metadata_[id].getAndLock();
  info->resource_cost = 0;
  info->conflicting_devices = nullptr;
  info->conflicting_devices_length = 0;
  return 0;
}

void CameraHal::OnSpecUpdated(const base::Value::Dict& json_values) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto hal_spec = ParseHalSpecFromJsonValue(json_values);
  if (!hal_spec.has_value()) {
    LOGF(WARNING) << "config file is not formatted correctly, ignored.";
    return;
  }

  ApplySpec(hal_spec_, hal_spec.value());
  hal_spec_ = hal_spec.value();
}

bool CameraHal::SetUpCamera(int id, const CameraSpec& spec) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  android::CameraMetadata static_metadata, request_template;

  if (!FillDefaultMetadata(&static_metadata, &request_template, spec).ok()) {
    return false;
  }

  static_metadata_[id] = std::move(static_metadata);
  request_template_[id] = std::move(request_template);

  return true;
}

void CameraHal::TearDownCamera(int id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  static_metadata_.erase(id);
  request_template_.erase(id);
}

void CameraHal::NotifyCameraConnected(int id, bool connected) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(callbacks_ != nullptr);

  callbacks_->camera_device_status_change(
      callbacks_, id,
      connected ? CAMERA_DEVICE_STATUS_PRESENT
                : CAMERA_DEVICE_STATUS_NOT_PRESENT);
}

void CameraHal::ApplySpec(const HalSpec& old_spec, const HalSpec& new_spec) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (callbacks_ == nullptr) {
    // Spec will be applied when callback is set.
    return;
  }

  for (const auto& old_camera_spec : old_spec.cameras) {
    int id = old_camera_spec.id;
    auto it = std::find_if(new_spec.cameras.begin(), new_spec.cameras.end(),
                           [&](const auto& spec) { return spec.id == id; });
    // TODO(pihsun): Might need to close the camera if some currently opened
    // camera is removed in spec.
    if (it == new_spec.cameras.end()) {
      // Camera entry removed.
      if (old_camera_spec.connected) {
        VLOGF(1) << "Removing camera " << id;
        NotifyCameraConnected(id, false);
        TearDownCamera(id);
      }
    } else {
      if (it->connected != old_camera_spec.connected) {
        // Device connected state changed.
        VLOGF(1) << "Camera " << id << " connected state changed "
                 << old_camera_spec.connected << "->" << it->connected;
        NotifyCameraConnected(id, it->connected);
      } else if (it->connected) {
        if (it->supported_formats != old_camera_spec.supported_formats) {
          VLOGF(1) << "Camera " << id << " supported formats changed";
          NotifyCameraConnected(id, false);
          TearDownCamera(id);

          // TODO(b:261682032): Sleep here to make sure the disconnect /
          // teardown event is properly propagated.
          base::PlatformThread::Sleep(base::Microseconds(300));

          // Supported format changes change static metadata, so we need to
          // regenerate static metadata here.
          if (!SetUpCamera(id, *it)) {
            // TODO(pihsun): Better handle error? We should at least remove the
            // entry from the new spec.
            LOGF(WARNING) << "Error when setting up camera id " << id;
            continue;
          }
          NotifyCameraConnected(id, true);
        } else if (it->frames != old_camera_spec.frames) {
          // TODO(pihsun): For frames spec change it's possible to just start
          // returning new frames in the CameraClient instead of simulating
          // unplug / plug the camera.
          VLOGF(1) << "Camera " << id << " frames spec changed";
          NotifyCameraConnected(id, false);
          NotifyCameraConnected(id, true);
        }
      }
    }
  }
  for (const auto& camera_spec : new_spec.cameras) {
    int id = camera_spec.id;
    if (std::none_of(old_spec.cameras.begin(), old_spec.cameras.end(),
                     [&](const auto& spec) { return spec.id == id; })) {
      // New device.
      VLOGF(1) << "Adding camera " << id;
      if (!SetUpCamera(id, camera_spec)) {
        // TODO(pihsun): Better handle error? We should at least remove the
        // entry from the new spec.
        LOGF(WARNING) << "Error when setting up camera id " << id;
        continue;
      }
      NotifyCameraConnected(id, camera_spec.connected);
    }
  }
}

void CameraHal::CloseDevice(int id) {
  VLOGFID(1, id);
  DCHECK(task_runner_);
  // The CameraHal is Singleton with NoDestructor so base::Unretained(this)
  // will always be valid.
  // Most of the work, like stopping the request handler thread, is done in
  // CameraClient::CloseDevice, and this only removes the CameraClient from the
  // CameraHal.
  task_runner_->PostTask(FROM_HERE,
                         base::BindOnce(&CameraHal::CloseDeviceOnHalThread,
                                        base::Unretained(this), id));
}

void CameraHal::CloseDeviceOnHalThread(int id) {
  VLOGFID(1, id);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  cameras_.erase(id);
}

int camera_device_close(struct hw_device_t* hw_device) {
  camera3_device_t* cam_dev = reinterpret_cast<camera3_device_t*>(hw_device);
  CameraClient* cam = static_cast<CameraClient*>(cam_dev->priv);
  if (!cam) {
    LOGF(ERROR) << "Camera device is NULL";
    return -EIO;
  }
  cam_dev->priv = nullptr;
  int ret = cam->CloseDevice();
  CameraHal::GetInstance().CloseDevice(cam->GetId());
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
               // TODO(pihsun): Extract the module name to a constant if more
               // tests needs to have special case for fake HAL.
               .name = "Fake Camera HAL",
               .author = "The ChromiumOS Authors",
               .methods = &gCameraModuleMethods,
               .dso = nullptr,
               .reserved = {}},
    .get_number_of_cameras = cros::get_number_of_cameras,
    .get_camera_info = cros::get_camera_info,
    .set_callbacks = cros::set_callbacks,
    // TODO(pihsun): Implement faking vendor tags.
    .get_vendor_tag_ops = nullptr,
    .open_legacy = cros::open_legacy,
    .set_torch_mode = cros::set_torch_mode,
    .init = cros::init,
    .reserved = {}};

cros::cros_camera_hal_t CROS_CAMERA_HAL_INFO_SYM CROS_CAMERA_EXPORT = {
    .set_up = cros::set_up,
    .tear_down = cros::tear_down,
    .set_privacy_switch_callback = cros::set_privacy_switch_callback,
    .camera_device_open_ext = cros::camera_device_open_ext,
    .get_camera_info_ext = cros::get_camera_info_ext};
