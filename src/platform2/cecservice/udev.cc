// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cecservice/udev.h"

#include <base/functional/bind.h>
#include <base/logging.h>

namespace {

struct UdevDeviceDeleter {
  void operator()(udev_device* device) const { udev_device_unref(device); }
};

struct UdevEnumerateDeleter {
  void operator()(udev_enumerate* enumerate) const {
    udev_enumerate_unref(enumerate);
  }
};

}  // namespace

namespace cecservice {

UdevImpl::UdevImpl() = default;

bool UdevImpl::Init(const DeviceCallback& device_added_callback,
                    const DeviceCallback& device_removed_callback) {
  device_added_callback_ = device_added_callback;
  device_removed_callback_ = device_removed_callback;

  udev_.reset(udev_new());
  if (!udev_) {
    LOG(ERROR) << "Failed to create libudev instance";
    return false;
  }

  monitor_.reset(udev_monitor_new_from_netlink(udev_.get(), "udev"));
  if (!monitor_) {
    LOG(ERROR) << "Failed to create udev monitor";
    return false;
  }

  if (udev_monitor_filter_add_match_subsystem_devtype(monitor_.get(), "cec",
                                                      nullptr) < 0) {
    LOG(ERROR) << "Failed to create udev filter for cec devices";
    return false;
  }

  if (udev_monitor_enable_receiving(monitor_.get()) < 0) {
    LOG(ERROR) << "Failed to enable receiving on udev monitor";
    return false;
  }

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      udev_monitor_get_fd(monitor_.get()),
      base::BindRepeating(&UdevImpl::OnDeviceAction,
                          weak_factory_.GetWeakPtr()));
  if (!watcher_) {
    LOG(ERROR) << "Failed to register listener on udev descriptor";
    return false;
  }

  return true;
}

UdevImpl::~UdevImpl() = default;

bool UdevImpl::EnumerateDevices(
    std::vector<base::FilePath>* devices_out) const {
  DCHECK(udev_) << "Udev not initialized";

  std::unique_ptr<udev_enumerate, UdevEnumerateDeleter> enumerate(
      udev_enumerate_new(udev_.get()));
  if (!enumerate) {
    LOG(ERROR) << "Failed to create udev enumeration";
    return false;
  }

  if (udev_enumerate_add_match_subsystem(enumerate.get(), "cec") < 0) {
    LOG(ERROR) << "Failed to add subsytem filter to udev enumeration";
    return false;
  }

  if (udev_enumerate_scan_devices(enumerate.get()) < 0) {
    LOG(ERROR) << "Failed to scan devices with udev";
    return false;
  }

  udev_list_entry* entry;
  udev_list_entry* devices_list =
      udev_enumerate_get_list_entry(enumerate.get());
  udev_list_entry_foreach(entry, devices_list) {
    const char* name = udev_list_entry_get_name(entry);
    if (!name) {
      LOG(WARNING) << "Failed to get entry name";
      continue;
    }

    std::unique_ptr<udev_device, UdevDeviceDeleter> device(
        udev_device_new_from_syspath(udev_.get(), name));
    if (!device) {
      PLOG(WARNING) << "Failed to create device from syspath:" << name;
      continue;
    }

    const char* path = udev_device_get_devnode(device.get());
    if (path) {
      devices_out->push_back(base::FilePath(path));
    } else {
      LOG(WARNING) << "Failed to get device node for:" << name;
    }
  }

  return true;
}

void UdevImpl::OnDeviceAction() {
  std::unique_ptr<udev_device, UdevDeviceDeleter> device(
      udev_monitor_receive_device(monitor_.get()));
  if (!device) {
    return;
  }

  const char* action = udev_device_get_action(device.get());
  if (!action) {
    LOG(WARNING) << "Failed to get device action";
    return;
  }

  const char* path = udev_device_get_devnode(device.get());
  base::FilePath file_path;
  if (path) {
    file_path = base::FilePath(path);
  } else {
    LOG(WARNING) << "Failed to get device path";
    return;
  }

  if (!strcmp(action, "add")) {
    device_added_callback_.Run(file_path);
  } else if (!strcmp(action, "remove")) {
    device_removed_callback_.Run(file_path);
  }
}

void UdevImpl::UdevDeleter::operator()(udev* udev) const {
  udev_unref(udev);
}

void UdevImpl::UdevMonitorDeleter::operator()(udev_monitor* udev) const {
  udev_monitor_unref(udev);
}

UdevFactory::~UdevFactory() = default;

UdevFactoryImpl::UdevFactoryImpl() = default;

UdevFactoryImpl::~UdevFactoryImpl() = default;

std::unique_ptr<Udev> UdevFactoryImpl::Create(
    const Udev::DeviceCallback& device_added_callback,
    const Udev::DeviceCallback& device_removed_callback) const {
  auto udev = std::make_unique<UdevImpl>();
  if (!udev->Init(device_added_callback, device_removed_callback)) {
    return nullptr;
  }

  return udev;
}

}  // namespace cecservice
