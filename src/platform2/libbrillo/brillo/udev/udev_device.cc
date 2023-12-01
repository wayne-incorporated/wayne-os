// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <brillo/udev/udev_device.h>

#include <libudev.h>

#include <base/logging.h>

namespace brillo {

UdevDeviceImpl::UdevDeviceImpl(udev_device* device) : device_(device) {
  CHECK(device_);

  udev_device_ref(device_);
}

UdevDeviceImpl::~UdevDeviceImpl() {
  if (device_) {
    udev_device_unref(device_);
    device_ = nullptr;
  }
}

std::unique_ptr<UdevDevice> UdevDeviceImpl::GetParent() const {
  // udev_device_get_parent does not increase the reference count of the
  // returned udev_device struct.
  udev_device* parent_device = udev_device_get_parent(device_);
  return parent_device ? std::make_unique<UdevDeviceImpl>(parent_device)
                       : nullptr;
}

std::unique_ptr<UdevDevice> UdevDeviceImpl::GetParentWithSubsystemDeviceType(
    const char* subsystem, const char* device_type) const {
  // udev_device_get_parent_with_subsystem_devtype does not increase the
  // reference count of the returned udev_device struct.
  udev_device* parent_device = udev_device_get_parent_with_subsystem_devtype(
      device_, subsystem, device_type);
  return parent_device ? std::make_unique<UdevDeviceImpl>(parent_device)
                       : nullptr;
}

bool UdevDeviceImpl::IsInitialized() const {
  return udev_device_get_is_initialized(device_);
}

uint64_t UdevDeviceImpl::GetMicrosecondsSinceInitialized() const {
  return udev_device_get_usec_since_initialized(device_);
}

uint64_t UdevDeviceImpl::GetSequenceNumber() const {
  return udev_device_get_seqnum(device_);
}

const char* UdevDeviceImpl::GetDevicePath() const {
  return udev_device_get_devpath(device_);
}

const char* UdevDeviceImpl::GetDeviceNode() const {
  return udev_device_get_devnode(device_);
}

dev_t UdevDeviceImpl::GetDeviceNumber() const {
  return udev_device_get_devnum(device_);
}

const char* UdevDeviceImpl::GetDeviceType() const {
  return udev_device_get_devtype(device_);
}

const char* UdevDeviceImpl::GetDriver() const {
  return udev_device_get_driver(device_);
}

const char* UdevDeviceImpl::GetSubsystem() const {
  return udev_device_get_subsystem(device_);
}

const char* UdevDeviceImpl::GetSysPath() const {
  return udev_device_get_syspath(device_);
}

const char* UdevDeviceImpl::GetSysName() const {
  return udev_device_get_sysname(device_);
}

const char* UdevDeviceImpl::GetSysNumber() const {
  return udev_device_get_sysnum(device_);
}

const char* UdevDeviceImpl::GetAction() const {
  return udev_device_get_action(device_);
}

std::unique_ptr<UdevListEntry> UdevDeviceImpl::GetDeviceLinksListEntry() const {
  udev_list_entry* list_entry = udev_device_get_devlinks_list_entry(device_);
  return list_entry ? std::make_unique<UdevListEntryImpl>(list_entry) : nullptr;
}

std::unique_ptr<UdevListEntry> UdevDeviceImpl::GetPropertiesListEntry() const {
  udev_list_entry* list_entry = udev_device_get_properties_list_entry(device_);
  return list_entry ? std::make_unique<UdevListEntryImpl>(list_entry) : nullptr;
}

const char* UdevDeviceImpl::GetPropertyValue(const char* key) const {
  return udev_device_get_property_value(device_, key);
}

std::unique_ptr<UdevListEntry> UdevDeviceImpl::GetTagsListEntry() const {
  udev_list_entry* list_entry = udev_device_get_tags_list_entry(device_);
  return list_entry ? std::make_unique<UdevListEntryImpl>(list_entry) : nullptr;
}

std::unique_ptr<UdevListEntry> UdevDeviceImpl::GetSysAttributeListEntry()
    const {
  udev_list_entry* list_entry = udev_device_get_sysattr_list_entry(device_);
  return list_entry ? std::make_unique<UdevListEntryImpl>(list_entry) : nullptr;
}

const char* UdevDeviceImpl::GetSysAttributeValue(const char* attribute) const {
  return udev_device_get_sysattr_value(device_, attribute);
}

std::unique_ptr<UdevDevice> UdevDeviceImpl::Clone() {
  return std::make_unique<UdevDeviceImpl>(device_);
}

}  // namespace brillo
