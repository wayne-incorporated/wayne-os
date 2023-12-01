/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/cros_camera_hal.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <utility>

#include <base/functional/bind.h>
#include <base/files/scoped_file.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/dbus/dbus_connection.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/platform/platform_channel.h>

#include "cros-camera/common.h"
#include "cros-camera/export.h"
#include "dbus_proxies/dbus-proxies.h"
#include "hal/ip/camera_hal.h"
#include "hal/ip/metadata_handler.h"

namespace cros {

CameraHal::CameraHal()
    : receiver_(this),
      next_camera_id_(0),
      callbacks_set_(base::WaitableEvent::ResetPolicy::MANUAL,
                     base::WaitableEvent::InitialState::NOT_SIGNALED),
      callbacks_(nullptr) {}

CameraHal::~CameraHal() {
  auto return_val = Future<void>::Create(nullptr);
  mojo::core::GetIOTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(&CameraHal::DestroyOnIpcThread,
                                base::Unretained(this), return_val));
  return_val->Wait();
}

CameraHal& CameraHal::GetInstance() {
  static CameraHal camera_hal;
  return camera_hal;
}

CameraMojoChannelManagerToken* CameraHal::GetMojoManagerToken() {
  return mojo_manager_token_;
}

int CameraHal::OpenDevice(int id,
                          const hw_module_t* module,
                          hw_device_t** hw_device) {
  base::AutoLock l(camera_map_lock_);

  if (cameras_.find(id) == cameras_.end()) {
    LOGF(ERROR) << "Camera " << id << " is invalid";
    return -EINVAL;
  }

  if (open_cameras_.find(id) != open_cameras_.end()) {
    LOGF(ERROR) << "Camera " << id << " is already open";
    return -EBUSY;
  }

  open_cameras_[id] = cameras_[id];
  cameras_[id]->Open(module, hw_device);

  return 0;
}

int CameraHal::CloseDevice(int id) {
  base::AutoLock l(camera_map_lock_);

  if (open_cameras_.find(id) == open_cameras_.end()) {
    LOGF(ERROR) << "Camera " << id << " is not open";
    return -EINVAL;
  }

  open_cameras_[id]->Close();
  open_cameras_.erase(id);

  return 0;
}

int CameraHal::GetNumberOfCameras() const {
  // Should always return 0, only built-in cameras are counted here
  return 0;
}

int CameraHal::GetCameraInfo(int id, struct camera_info* info) {
  base::AutoLock l(camera_map_lock_);
  auto it = cameras_.find(id);
  if (it == cameras_.end()) {
    LOGF(ERROR) << "Camera id " << id << " is not valid";
    return -EINVAL;
  }

  info->facing = CAMERA_FACING_EXTERNAL;
  info->orientation = 0;
  info->device_version = CAMERA_DEVICE_API_VERSION_3_3;
  info->static_camera_characteristics =
      it->second->GetStaticMetadata()->getAndLock();
  info->resource_cost = 0;
  info->conflicting_devices = nullptr;
  info->conflicting_devices_length = 0;
  return 0;
}

int CameraHal::SetCallbacks(const camera_module_callbacks_t* callbacks) {
  callbacks_ = callbacks;
  callbacks_set_.Signal();
  return 0;
}

int CameraHal::Init() {
  if (initialized_.IsSet()) {
    LOGF(ERROR) << "Init called more than once";
    return -EBUSY;
  }

  brillo::CrosConfig config;
  std::string has_poe_peripheral_support;
  if (!config.GetString("/hardware-properties", "has-poe-peripheral-support",
                        &has_poe_peripheral_support) ||
      has_poe_peripheral_support.compare("true")) {
    // Do not try to connect to the IP peripheral on devices where support does
    // not exist.
    LOGF(INFO) << "IP peripherals not supported, IP cameras won't work";
    return 0;
  }

  auto return_val = Future<int>::Create(nullptr);
  mojo::core::GetIOTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(&CameraHal::InitOnIpcThread,
                                base::Unretained(this), return_val));
  int ret = return_val->Get();
  initialized_.Set();
  return ret;
}

void CameraHal::SetUp(CameraMojoChannelManagerToken* token) {
  mojo_manager_token_ = token;
}

void CameraHal::TearDown() {
  mojo_manager_token_ = nullptr;
}

void CameraHal::InitOnIpcThread(scoped_refptr<Future<int>> return_val) {
  brillo::DBusConnection dbus_connection;
  org::chromium::IpPeripheralService::CameraDetectorProxy proxy(
      dbus_connection.Connect(), "org.chromium.IpPeripheralService");

  mojo::PlatformChannel channel;
  base::ScopedFD handle =
      channel.TakeRemoteEndpoint().TakePlatformHandle().TakeFD();

  if (!proxy.BootstrapMojoConnection(handle, nullptr)) {
    LOGF(ERROR) << "Failed to send handle over DBus";
    return_val->Set(-ENODEV);
    return;
  }

  isolated_connection_ = std::make_unique<mojo::IsolatedConnection>();
  mojo::ScopedMessagePipeHandle pipe =
      isolated_connection_->Connect(channel.TakeLocalEndpoint());

  detector_.Bind(
      mojo::PendingRemote<mojom::IpCameraDetector>(std::move(pipe), 0u));
  detector_.set_disconnect_handler(
      base::BindOnce(&CameraHal::OnConnectionError, base::Unretained(this)));

  mojo::PendingRemote<IpCameraConnectionListener> listener =
      receiver_.BindNewPipeAndPassRemote();
  receiver_.set_disconnect_handler(
      base::BindOnce(&CameraHal::OnConnectionError, base::Unretained(this)));

  detector_->RegisterConnectionListener(std::move(listener));
  return_val->Set(0);
}

void CameraHal::DestroyOnIpcThread(scoped_refptr<Future<void>> return_val) {
  receiver_.reset();
  detector_.reset();

  {
    base::AutoLock l(camera_map_lock_);
    cameras_.clear();
  }

  isolated_connection_ = nullptr;
  return_val->Set();
}

void CameraHal::OnConnectionError() {
  receiver_.reset();
  detector_.reset();

  {
    base::AutoLock l(camera_map_lock_);
    while (!ip_to_id_.empty()) {
      const std::string ip = ip_to_id_.begin()->first;

      base::AutoUnlock u(camera_map_lock_);
      OnDeviceDisconnected(ip);
    }
  }

  isolated_connection_ = nullptr;

  LOGF(FATAL) << "Lost connection to IP peripheral server";
}

void CameraHal::OnDeviceConnected(
    const std::string& ip,
    const std::string& name,
    mojo::PendingRemote<mojom::IpCameraDevice> device_remote,
    std::vector<mojom::IpCameraStreamPtr> streams) {
  int id = -1;
  {
    base::AutoLock l(camera_map_lock_);
    id = next_camera_id_;

    auto device = std::make_shared<CameraDevice>(id);
    if (device->Init(std::move(device_remote), ip, name, std::move(streams))) {
      LOGF(ERROR) << "Error creating camera device";
      return;
    }

    next_camera_id_++;
    ip_to_id_[ip] = id;
    cameras_[id] = std::move(device);
  }

  callbacks_set_.Wait();
  callbacks_->camera_device_status_change(callbacks_, id,
                                          CAMERA_DEVICE_STATUS_PRESENT);
}

void CameraHal::OnDeviceDisconnected(const std::string& ip) {
  callbacks_set_.Wait();

  int id = -1;
  {
    base::AutoLock l(camera_map_lock_);
    auto ip_mapping = ip_to_id_.find(ip);
    if (ip_mapping == ip_to_id_.end()) {
      LOGF(ERROR) << "Camera ip " << ip << " is invalid";
      return;
    }
    id = ip_mapping->second;

    if (cameras_.find(id) == cameras_.end()) {
      LOGF(ERROR) << "Camera id " << id << " is invalid";
      return;
    }

    if (open_cameras_.find(id) != open_cameras_.end()) {
      cameras_[id]->Flush();
    }
  }

  callbacks_->camera_device_status_change(callbacks_, id,
                                          CAMERA_DEVICE_STATUS_NOT_PRESENT);

  {
    base::AutoLock l(camera_map_lock_);

    ip_to_id_.erase(ip);
    cameras_.erase(id);
  }
}

static int camera_device_open(const hw_module_t* module,
                              const char* name,
                              hw_device_t** device) {
  if (module != &HAL_MODULE_INFO_SYM.common) {
    LOGF(ERROR) << std::hex << std::showbase << "Invalid module " << module
                << " expected " << &HAL_MODULE_INFO_SYM.common;
    return -EINVAL;
  }

  int id;
  if (!base::StringToInt(name, &id)) {
    LOGF(ERROR) << "Invalid camera name " << name;
    return -EINVAL;
  }

  return CameraHal::GetInstance().OpenDevice(id, module, device);
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

static void get_vendor_tag_ops(vendor_tag_ops_t* /*ops*/) {}

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

}  // namespace cros

static hw_module_methods_t gCameraModuleMethods = {
    .open = cros::camera_device_open};

camera_module_t HAL_MODULE_INFO_SYM CROS_CAMERA_EXPORT = {
    .common = {.tag = HARDWARE_MODULE_TAG,
               .module_api_version = CAMERA_MODULE_API_VERSION_2_4,
               .hal_api_version = HARDWARE_HAL_API_VERSION,
               .id = CAMERA_HARDWARE_MODULE_ID,
               .name = "IP Camera HAL v3",
               .author = "The ChromiumOS Authors",
               .methods = &gCameraModuleMethods,
               .dso = nullptr,
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
    .set_up = cros::set_up, .tear_down = cros::tear_down};
