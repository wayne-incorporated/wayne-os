// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <brillo/udev/udev_enumerate.h>

#include <libudev.h>

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/udev/udev_device.h>

using base::StringPrintf;

namespace brillo {

UdevEnumerate::UdevEnumerate() : enumerate_(nullptr) {}

UdevEnumerate::UdevEnumerate(udev_enumerate* enumerate)
    : enumerate_(enumerate) {
  CHECK(enumerate_);

  udev_enumerate_ref(enumerate_);
}

UdevEnumerate::~UdevEnumerate() {
  if (enumerate_) {
    udev_enumerate_unref(enumerate_);
    enumerate_ = nullptr;
  }
}

bool UdevEnumerate::AddMatchSubsystem(const char* subsystem) {
  int result = udev_enumerate_add_match_subsystem(enumerate_, subsystem);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_enumerate_add_match_subsystem (%p, \"%s\") returned %d.",
      enumerate_, subsystem, result);
  return false;
}

bool UdevEnumerate::AddNoMatchSubsystem(const char* subsystem) {
  int result = udev_enumerate_add_nomatch_subsystem(enumerate_, subsystem);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_enumerate_add_nomatch_subsystem (%p, \"%s\") returned %d.",
      enumerate_, subsystem, result);
  return false;
}

bool UdevEnumerate::AddMatchSysAttribute(const char* attribute,
                                         const char* value) {
  int result = udev_enumerate_add_match_sysattr(enumerate_, attribute, value);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_enumerate_add_match_sysattr (%p, \"%s\", \"%s\") returned %d.",
      enumerate_, attribute, value, result);
  return false;
}

bool UdevEnumerate::AddNoMatchSysAttribute(const char* attribute,
                                           const char* value) {
  int result = udev_enumerate_add_nomatch_sysattr(enumerate_, attribute, value);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_enumerate_add_nomatch_sysattr (%p, \"%s\", \"%s\") returned %d.",
      enumerate_, attribute, value, result);
  return false;
}

bool UdevEnumerate::AddMatchProperty(const char* property, const char* value) {
  int result = udev_enumerate_add_match_property(enumerate_, property, value);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_enumerate_add_match_property (%p, \"%s\", \"%s\") returned %d.",
      enumerate_, property, value, result);
  return false;
}

bool UdevEnumerate::AddMatchSysName(const char* sys_name) {
  int result = udev_enumerate_add_match_sysname(enumerate_, sys_name);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_enumerate_add_match_sysname (%p, \"%s\") returned %d.", enumerate_,
      sys_name, result);
  return false;
}

bool UdevEnumerate::AddMatchTag(const char* tag) {
  int result = udev_enumerate_add_match_tag(enumerate_, tag);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_enumerate_add_match_tag (%p, \"%s\") returned %d.", enumerate_, tag,
      result);
  return false;
}

bool UdevEnumerate::AddMatchIsInitialized() {
  int result = udev_enumerate_add_match_is_initialized(enumerate_);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf(
      "udev_enumerate_add_match_is_initialized (%p) returned %d.", enumerate_,
      result);
  return false;
}

bool UdevEnumerate::AddSysPath(const char* sys_path) {
  int result = udev_enumerate_add_syspath(enumerate_, sys_path);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf("udev_enumerate_add_syspath(%p, \"%s\") returned %d.",
                          enumerate_, sys_path, result);
  return false;
}

bool UdevEnumerate::ScanDevices() {
  int result = udev_enumerate_scan_devices(enumerate_);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf("udev_enumerate_scan_devices(%p) returned %d.",
                          enumerate_, result);
  return false;
}

bool UdevEnumerate::ScanSubsystems() {
  int result = udev_enumerate_scan_subsystems(enumerate_);
  if (result == 0)
    return true;

  VLOG(2) << StringPrintf("udev_enumerate_scan_subsystems(%p) returned %d.",
                          enumerate_, result);
  return false;
}

std::unique_ptr<UdevListEntry> UdevEnumerate::GetListEntry() const {
  udev_list_entry* list_entry = udev_enumerate_get_list_entry(enumerate_);
  return list_entry ? std::make_unique<UdevListEntryImpl>(list_entry) : nullptr;
}

}  // namespace brillo
