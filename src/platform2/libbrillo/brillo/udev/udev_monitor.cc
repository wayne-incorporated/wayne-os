// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <brillo/udev/udev_monitor.h>

#include <libudev.h>

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/udev/udev_device.h>

using base::StringPrintf;

namespace brillo {

UdevMonitor::UdevMonitor() : monitor_(nullptr) {}

UdevMonitor::UdevMonitor(udev_monitor* monitor) : monitor_(monitor) {
  CHECK(monitor_);

  udev_monitor_ref(monitor_);
}

UdevMonitor::~UdevMonitor() {
  if (monitor_) {
    udev_monitor_unref(monitor_);
    monitor_ = nullptr;
  }
}

bool UdevMonitor::EnableReceiving() {
  int result = udev_monitor_enable_receiving(monitor_);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf("udev_monitor_enable_receiving(%p) returned %d.",
                          monitor_, result);
  return false;
}

int UdevMonitor::GetFileDescriptor() const {
  int file_descriptor = udev_monitor_get_fd(monitor_);
  if (file_descriptor >= 0)
    return file_descriptor;

  VLOG(2) << StringPrintf("udev_monitor_get_fd(%p) returned %d.", monitor_,
                          file_descriptor);
  return kInvalidFileDescriptor;
}

std::unique_ptr<UdevDevice> UdevMonitor::ReceiveDevice() {
  udev_device* received_device = udev_monitor_receive_device(monitor_);
  if (received_device) {
    auto device = std::make_unique<UdevDeviceImpl>(received_device);
    // udev_monitor_receive_device increases the reference count of the returned
    // udev_device struct, while UdevDevice also holds a reference count of the
    // udev_device struct. Thus, decrease the reference count of the udev_device
    // struct.
    udev_device_unref(received_device);
    return device;
  }

  VLOG(2) << StringPrintf("udev_monitor_receive_device(%p) returned nullptr.",
                          monitor_);
  return nullptr;
}

bool UdevMonitor::FilterAddMatchSubsystemDeviceType(const char* subsystem,
                                                    const char* device_type) {
  int result = udev_monitor_filter_add_match_subsystem_devtype(
      monitor_, subsystem, device_type);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_monitor_filter_add_match_subsystem_devtype (%p, \"%s\", \"%s\") "
      "returned %d.",
      monitor_, subsystem, device_type, result);
  return false;
}

bool UdevMonitor::FilterAddMatchTag(const char* tag) {
  int result = udev_monitor_filter_add_match_tag(monitor_, tag);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_monitor_filter_add_tag (%p, \"%s\") returned %d.", monitor_, tag,
      result);
  return false;
}

bool UdevMonitor::FilterUpdate() {
  int result = udev_monitor_filter_update(monitor_);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf("udev_monitor_filter_update(%p) returned %d.",
                          monitor_, result);
  return false;
}

bool UdevMonitor::FilterRemove() {
  int result = udev_monitor_filter_remove(monitor_);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf("udev_monitor_filter_remove(%p) returned %d.",
                          monitor_, result);
  return false;
}

}  // namespace brillo
