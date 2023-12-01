// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/udev_stub.h"

#include "power_manager/powerd/system/udev_subsystem_observer.h"
#include "power_manager/powerd/system/udev_tagged_device_observer.h"

#include <base/check.h>
#include <base/containers/contains.h>

namespace power_manager::system {

bool UdevStub::HasSubsystemObserver(const std::string& subsystem,
                                    UdevSubsystemObserver* observer) const {
  const auto it = subsystem_observers_.find(subsystem);
  return it != subsystem_observers_.end() && it->second->HasObserver(observer);
}

void UdevStub::NotifySubsystemObservers(const UdevEvent& event) {
  auto it = subsystem_observers_.find(event.device_info.subsystem);
  if (it != subsystem_observers_.end()) {
    for (UdevSubsystemObserver& observer : *it->second)
      observer.OnUdevEvent(event);
  }
}

void UdevStub::TaggedDeviceChanged(const std::string& syspath,
                                   const base::FilePath& wakeup_device_path,
                                   const std::string& tags) {
  tagged_devices_[syspath] = TaggedDevice(syspath, wakeup_device_path, tags);
  const TaggedDevice& device = tagged_devices_[syspath];
  for (UdevTaggedDeviceObserver& observer : tagged_device_observers_)
    observer.OnTaggedDeviceChanged(device);
}

void UdevStub::TaggedDeviceRemoved(const std::string& syspath) {
  TaggedDevice device = tagged_devices_[syspath];
  tagged_devices_.erase(syspath);
  for (UdevTaggedDeviceObserver& observer : tagged_device_observers_)
    observer.OnTaggedDeviceRemoved(device);
}

void UdevStub::stop_accepting_sysattr_for_testing() {
  stop_accepting_sysattr_for_testing_ = true;
}

void UdevStub::RemoveSysattr(const std::string& syspath,
                             const std::string& sysattr) {
  map_.erase(make_pair(syspath, sysattr));
}

void UdevStub::AddSubsystemDevice(const std::string& subsystem,
                                  const UdevDeviceInfo& udev_device,
                                  std::initializer_list<std::string> dlinks) {
  subsystem_devices_[subsystem].push_back(udev_device);
  devlinks_.emplace(udev_device.syspath, dlinks);
}

void UdevStub::AddSubsystemObserver(const std::string& subsystem,
                                    UdevSubsystemObserver* observer) {
  DCHECK(observer);
  auto it = subsystem_observers_.find(subsystem);
  if (it == subsystem_observers_.end()) {
    it = subsystem_observers_
             .emplace(
                 subsystem,
                 std::make_unique<base::ObserverList<UdevSubsystemObserver>>())
             .first;
  }
  it->second->AddObserver(observer);
}

void UdevStub::RemoveSubsystemObserver(const std::string& subsystem,
                                       UdevSubsystemObserver* observer) {
  DCHECK(observer);
  auto it = subsystem_observers_.find(subsystem);
  if (it != subsystem_observers_.end())
    it->second->RemoveObserver(observer);
}

void UdevStub::AddTaggedDeviceObserver(UdevTaggedDeviceObserver* observer) {
  tagged_device_observers_.AddObserver(observer);
}

void UdevStub::RemoveTaggedDeviceObserver(UdevTaggedDeviceObserver* observer) {
  tagged_device_observers_.RemoveObserver(observer);
}

std::vector<TaggedDevice> UdevStub::GetTaggedDevices() {
  std::vector<TaggedDevice> devices;
  devices.reserve(tagged_devices_.size());
  for (const std::pair<std::string, TaggedDevice> pair : tagged_devices_)
    devices.push_back(pair.second);
  return devices;
}

bool UdevStub::GetSubsystemDevices(const std::string& subsystem,
                                   std::vector<UdevDeviceInfo>* devices_out) {
  DCHECK(devices_out);
  const auto it = subsystem_devices_.find(subsystem);
  if (it != subsystem_devices_.end())
    *devices_out = it->second;
  else
    devices_out->clear();
  return true;
}

bool UdevStub::HasSysattr(const std::string& syspath,
                          const std::string& sysattr) {
  std::string unused;

  return GetSysattr(syspath, sysattr, &unused);
}

bool UdevStub::GetSysattr(const std::string& syspath,
                          const std::string& sysattr,
                          std::string* value) {
  SysattrMap::iterator it = map_.find(std::make_pair(syspath, sysattr));
  if (it == map_.end())
    return false;
  *value = it->second;
  return true;
}

bool UdevStub::SetSysattr(const std::string& syspath,
                          const std::string& sysattr,
                          const std::string& value) {
  SysattrMap::iterator it = map_.find(std::make_pair(syspath, sysattr));
  if (it == map_.end() && stop_accepting_sysattr_for_testing_)
    return false;
  map_[std::make_pair(syspath, sysattr)] = value;
  return true;
}

bool UdevStub::GetDevlinks(const std::string& syspath,
                           std::vector<std::string>* out) {
  auto iter = devlinks_.find(syspath);
  if (iter == devlinks_.end())
    return false;

  *out = iter->second;
  return true;
}

void UdevStub::SetPowerdRole(const std::string& syspath,
                             const std::string& role) {
  powerd_roles_.emplace(std::make_pair(syspath, role));
}

bool UdevStub::HasPowerdRole(const std::string& syspath,
                             const std::string& role) {
  return base::Contains(powerd_roles_, syspath) &&
         powerd_roles_[syspath] == role;
}

}  // namespace power_manager::system
