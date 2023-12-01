// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/udev.h"

#include <libudev.h>

#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <base/strings/string_util.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/udev_subsystem_observer.h"
#include "power_manager/powerd/system/udev_tagged_device_observer.h"

namespace power_manager::system {

namespace {

const char kChromeOSClassPath[] = "/sys/class/chromeos/";
const char kFingerprintSysfsPath[] = "/sys/class/chromeos/cros_fp";
const char kBluetoothHciSysfsPrefix[] = "/sys/class/bluetooth/hci";
const char kBluetoothIdentityFileName[] = "identity";
// Search space for hci devices. i.e. hci0, hci1, etc. Only allow hci0 for now.
constexpr int kBluetoothMaxHci = 1;
const char kBluetoothPhysVar[] = "phys";
const char kPowerdRoleCrosFP[] = "cros_fingerprint";
const char kPowerdRoleCrosBT[] = "cros_bluetooth";
const char kPowerdRoleVar[] = "POWERD_ROLE";
const char kPowerdUdevTag[] = "powerd";
const char kPowerdTagsVar[] = "POWERD_TAGS";
// Udev device type for USB devices.
const char kUSBDevice[] = "usb_device";

// Returns true iff `device` is tagged with `role` in its udev properties.
// Powerd role tags are applied to devices by the udev rules which are installed
// with powerd.
bool DeviceHasPowerdRole(struct udev_device* device, const std::string& role) {
  const char* role_cstr =
      udev_device_get_property_value(device, kPowerdRoleVar);
  const std::string device_role = role_cstr ? role_cstr : "";
  return role == device_role;
}

UdevEvent::Action StrToAction(const char* action_str) {
  if (!action_str)
    return UdevEvent::Action::UNKNOWN;
  else if (strcmp(action_str, "add") == 0)
    return UdevEvent::Action::ADD;
  else if (strcmp(action_str, "remove") == 0)
    return UdevEvent::Action::REMOVE;
  else if (strcmp(action_str, "change") == 0)
    return UdevEvent::Action::CHANGE;
  else if (strcmp(action_str, "online") == 0)
    return UdevEvent::Action::ONLINE;
  else if (strcmp(action_str, "offline") == 0)
    return UdevEvent::Action::OFFLINE;
  else
    return UdevEvent::Action::UNKNOWN;
}

struct UdevDeviceDeleter {
  void operator()(udev_device* dev) {
    if (dev)
      udev_device_unref(dev);
  }
};

// Find the hci path where the identity matches the phys addr of the peer
// device. This enforces that the tagged input device actually is correlated to
// a Bluetooth hci device. For example, checks that
// /sys/class/bluetooth/hci0/identity matches given address [00:11:22:33:44:55].
std::string FindHciPathWithAddress(const std::string& addr) {
  std::string hci_path;
  if (addr.empty())
    return hci_path;

  for (int i = 0; i < kBluetoothMaxHci; ++i) {
    std::string hci_id;
    base::FilePath tmp_path(
        base::JoinString({kBluetoothHciSysfsPrefix, std::to_string(i), "/",
                          kBluetoothIdentityFileName},
                         ""));
    if (base::ReadFileToStringWithMaxSize(tmp_path, &hci_id, addr.size())) {
      if (hci_id == addr) {
        hci_path =
            base::JoinString({kBluetoothHciSysfsPrefix, std::to_string(i)}, "");
        break;
      }
    }
  }

  return hci_path;
}

};  // namespace

Udev::~Udev() {
  if (udev_monitor_)
    udev_monitor_unref(udev_monitor_);
  if (udev_)
    udev_unref(udev_);
}

bool Udev::Init() {
  udev_ = udev_new();
  if (!udev_) {
    PLOG(ERROR) << "udev_new() failed";
    return false;
  }

  udev_monitor_ = udev_monitor_new_from_netlink(udev_, "udev");
  if (!udev_monitor_) {
    PLOG(ERROR) << "udev_monitor_new_from_netlink() failed";
    return false;
  }

  if (udev_monitor_filter_add_match_tag(udev_monitor_, kPowerdUdevTag))
    LOG(ERROR) << "udev_monitor_filter_add_match_tag failed";
  if (udev_monitor_filter_update(udev_monitor_))
    LOG(ERROR) << "udev_monitor_filter_update failed";

  udev_monitor_enable_receiving(udev_monitor_);

  int fd = udev_monitor_get_fd(udev_monitor_);
  controller_ = base::FileDescriptorWatcher::WatchReadable(
      fd, base::BindRepeating(&Udev::OnFileCanReadWithoutBlocking,
                              base::Unretained(this)));
  LOG(INFO) << "Watching FD " << fd << " for udev events";

  EnumerateTaggedDevices();

  return true;
}

void Udev::AddSubsystemObserver(const std::string& subsystem,
                                UdevSubsystemObserver* observer) {
  DCHECK(udev_) << "Object uninitialized";
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

void Udev::RemoveSubsystemObserver(const std::string& subsystem,
                                   UdevSubsystemObserver* observer) {
  DCHECK(observer);
  auto it = subsystem_observers_.find(subsystem);
  if (it != subsystem_observers_.end())
    it->second->RemoveObserver(observer);
}

void Udev::AddTaggedDeviceObserver(UdevTaggedDeviceObserver* observer) {
  tagged_device_observers_.AddObserver(observer);
}

void Udev::RemoveTaggedDeviceObserver(UdevTaggedDeviceObserver* observer) {
  tagged_device_observers_.RemoveObserver(observer);
}

std::vector<TaggedDevice> Udev::GetTaggedDevices() {
  std::vector<TaggedDevice> devices;
  devices.reserve(tagged_devices_.size());
  for (const std::pair<std::string, TaggedDevice> pair : tagged_devices_)
    devices.push_back(pair.second);
  return devices;
}

bool Udev::GetSubsystemDevices(const std::string& subsystem,
                               std::vector<UdevDeviceInfo>* devices_out) {
  DCHECK(udev_);
  DCHECK(devices_out);
  struct udev_enumerate* enumerate = udev_enumerate_new(udev_);
  if (!enumerate) {
    LOG(ERROR) << "udev_enumerate_new failed";
    return false;
  }
  int ret = udev_enumerate_add_match_subsystem(enumerate, subsystem.c_str());
  if (ret != 0) {
    LOG(ERROR) << "udev_enumerate_add_match_subsystem failed. Error: "
               << strerror(-ret);
    udev_enumerate_unref(enumerate);
    return false;
  }
  ret = udev_enumerate_scan_devices(enumerate);
  if (ret != 0) {
    LOG(ERROR) << "udev_enumerate_scan_devices failed. Error: "
               << strerror(-ret);
    udev_enumerate_unref(enumerate);
    return false;
  }

  devices_out->clear();

  for (struct udev_list_entry* list_entry =
           udev_enumerate_get_list_entry(enumerate);
       list_entry != nullptr;
       list_entry = udev_list_entry_get_next(list_entry)) {
    const char* syspath = udev_list_entry_get_name(list_entry);
    struct udev_device* device = udev_device_new_from_syspath(udev_, syspath);
    if (!device) {
      LOG(ERROR) << "Enumeration of device with syspath " << syspath
                 << " failed";
      continue;
    }
    UdevDeviceInfo device_info;
    if (GetDeviceInfo(device, &device_info)) {
      devices_out->push_back(std::move(device_info));
    } else {
      LOG(ERROR) << "Could not retrieve Udev info for the device with syspath "
                 << syspath;
    }
    udev_device_unref(device);
  }

  udev_enumerate_unref(enumerate);
  return true;
}

bool Udev::GetSysattr(const std::string& syspath,
                      const std::string& sysattr,
                      std::string* value) {
  DCHECK(udev_);
  DCHECK(value);
  value->clear();

  struct udev_device* device =
      udev_device_new_from_syspath(udev_, syspath.c_str());
  if (!device) {
    LOG(WARNING) << "Failed to open udev device: " << syspath;
    return false;
  }
  const char* value_cstr =
      udev_device_get_sysattr_value(device, sysattr.c_str());
  if (value_cstr)
    *value = value_cstr;
  udev_device_unref(device);
  return value_cstr != nullptr;
}

bool Udev::HasSysattr(const std::string& syspath, const std::string& sysattr) {
  std::string value;

  return GetSysattr(syspath, sysattr, &value);
}

bool Udev::SetSysattr(const std::string& syspath,
                      const std::string& sysattr,
                      const std::string& value) {
  DCHECK(udev_);

  struct udev_device* device =
      udev_device_new_from_syspath(udev_, syspath.c_str());
  if (!device) {
    LOG(WARNING) << "Failed to open udev device: " << syspath;
    return false;
  }
  // udev can modify this value, hence we copy it first.
  std::unique_ptr<char, base::FreeDeleter> value_mutable(strdup(value.c_str()));
  int rv = udev_device_set_sysattr_value(device, sysattr.c_str(),
                                         value_mutable.get());
  udev_device_unref(device);
  if (rv != 0) {
    LOG(WARNING) << "Failed to set sysattr '" << sysattr << "' on device "
                 << syspath << ": " << strerror(-rv);
    return false;
  }
  return true;
}

base::FilePath Udev::FindParentWithSysattr(const std::string& syspath,
                                           const std::string& sysattr,
                                           const std::string& stop_at_devtype) {
  DCHECK(udev_);

  struct udev_device* device =
      udev_device_new_from_syspath(udev_, syspath.c_str());
  if (!device) {
    LOG(WARNING) << "Failed to open udev device: " << syspath;
    return base::FilePath();
  }

  struct udev_device* parent = device;
  while (parent) {
    const char* value = udev_device_get_sysattr_value(parent, sysattr.c_str());
    const char* devtype = udev_device_get_devtype(parent);
    if (value)
      break;
    // Go up one level unless the devtype matches stop_at_devtype.
    if (devtype && strcmp(stop_at_devtype.c_str(), devtype) == 0) {
      parent = nullptr;
    } else {
      // Returns a pointer to the parent device. No additional reference to
      // the device is acquired, but the child device owns a reference to the
      // parent device.
      parent = udev_device_get_parent(parent);
    }
  }
  base::FilePath parent_syspath;
  if (parent)
    parent_syspath = base::FilePath(udev_device_get_syspath(parent));
  udev_device_unref(device);
  return parent_syspath;
}

base::FilePath Udev::FindWakeCapableParent(const std::string& syspath) {
  base::FilePath wakeup_device_path;
  struct udev_device* device =
      udev_device_new_from_syspath(udev_, syspath.c_str());
  if (!device)
    return wakeup_device_path;

  // Returns a pointer to the parent device. No additional reference to
  // the |device| is acquired, but the |device| owns a reference to the
  // |parent|.
  struct udev_device* parent = udev_device_get_parent(device);
  // We assign powerd roles to the input device. In case |syspath| points to
  // a event device, look also at the parent device to see if it has
  // |kPowerdRoleCrosFP| role.
  if (DeviceHasPowerdRole(device, kPowerdRoleCrosFP) ||
      DeviceHasPowerdRole(parent, kPowerdRoleCrosFP)) {
    base::FilePath actual_fp_path;
    if (!base::ReadSymbolicLink(base::FilePath(kFingerprintSysfsPath),
                                &actual_fp_path)) {
      PLOG(ERROR) << "Failed to read symlink " << kFingerprintSysfsPath
                  << " for fingerprint device";
    } else {
      std::string wakeup_path =
          base::FilePath(kChromeOSClassPath).Append(actual_fp_path).value();
      wakeup_device_path =
          FindParentWithSysattr(wakeup_path, kPowerWakeup, kUSBDevice);
    }
  } else if (DeviceHasPowerdRole(device, kPowerdRoleCrosBT)) {
    // Check if the input device is assigned the |kPowerdRoleCrosBT| role. If it
    // has this role, then its wakeup path will be a parent of the hci sysfs
    // path and not the input device itself.
    const char* phys = udev_device_get_sysattr_value(device, kBluetoothPhysVar);
    if (!phys)
      phys = udev_device_get_sysattr_value(parent, kBluetoothPhysVar);

    std::string hci_path = FindHciPathWithAddress(phys ? phys : "");
    if (!hci_path.empty()) {
      wakeup_device_path =
          FindParentWithSysattr(hci_path, kPowerWakeup, kUSBDevice);
    }
  } else {
    wakeup_device_path =
        FindParentWithSysattr(syspath, kPowerWakeup, kUSBDevice);
  }
  udev_device_unref(device);
  return wakeup_device_path;
}

bool Udev::GetDeviceInfo(struct udev_device* dev,
                         UdevDeviceInfo* device_info_out) {
  DCHECK(device_info_out);

  const char* subsystem = udev_device_get_subsystem(dev);
  if (!subsystem)
    return false;

  device_info_out->subsystem = subsystem;

  const char* devtype = udev_device_get_devtype(dev);
  if (devtype)
    device_info_out->devtype = devtype;

  const char* sysname = udev_device_get_sysname(dev);
  if (sysname)
    device_info_out->sysname = sysname;

  const char* syspath = udev_device_get_syspath(dev);
  if (syspath)
    device_info_out->syspath = syspath;

  device_info_out->wakeup_device_path = FindWakeCapableParent(syspath);

  return true;
}

bool Udev::GetDevlinks(const std::string& syspath,
                       std::vector<std::string>* out) {
  DCHECK(udev_);
  DCHECK(out);

  std::unique_ptr<udev_device, UdevDeviceDeleter> device(
      udev_device_new_from_syspath(udev_, syspath.c_str()));
  if (!device) {
    PLOG(WARNING) << "Failed to open udev device: " << syspath;
    return false;
  }

  out->clear();

  // TODO(egranata): maybe write a wrapper around udev_list to support
  // for(entry : list) {...}
  struct udev_list_entry* devlink =
      udev_device_get_devlinks_list_entry(device.get());
  while (devlink) {
    const char* name = udev_list_entry_get_name(devlink);
    if (name)
      out->push_back(name);
    devlink = udev_list_entry_get_next(devlink);
  }

  return true;
}

bool Udev::HasPowerdRole(const std::string& syspath, const std::string& role) {
  DCHECK(udev_);

  std::unique_ptr<udev_device, UdevDeviceDeleter> device(
      udev_device_new_from_syspath(udev_, syspath.c_str()));

  return DeviceHasPowerdRole(device.get(), role);
}

void Udev::OnFileCanReadWithoutBlocking() {
  struct udev_device* dev = udev_monitor_receive_device(udev_monitor_);
  if (!dev)
    return;

  const char* subsystem = udev_device_get_subsystem(dev);
  const char* sysname = udev_device_get_sysname(dev);
  const char* action_str = udev_device_get_action(dev);
  UdevEvent::Action action = StrToAction(action_str);

  VLOG(1) << "Received event: subsystem=" << subsystem << " sysname=" << sysname
          << " action=" << action_str;

  HandleSubsystemEvent(action, dev);
  HandleTaggedDevice(action, dev);

  udev_device_unref(dev);
}

void Udev::HandleSubsystemEvent(UdevEvent::Action action,
                                struct udev_device* dev) {
  UdevEvent event;
  if (!GetDeviceInfo(dev, &(event.device_info)))
    return;
  event.action = action;
  auto it = subsystem_observers_.find(event.device_info.subsystem);
  if (it != subsystem_observers_.end()) {
    for (UdevSubsystemObserver& observer : *it->second)
      observer.OnUdevEvent(event);
  }
}

void Udev::HandleTaggedDevice(UdevEvent::Action action,
                              struct udev_device* dev) {
  if (!udev_device_has_tag(dev, kPowerdUdevTag))
    return;

  const char* syspath = udev_device_get_syspath(dev);
  const char* tags = udev_device_get_property_value(dev, kPowerdTagsVar);

  switch (action) {
    case UdevEvent::Action::ADD:
    case UdevEvent::Action::CHANGE:
      TaggedDeviceChanged(syspath, FindWakeCapableParent(syspath),
                          tags ? tags : "");
      break;

    case UdevEvent::Action::REMOVE:
      TaggedDeviceRemoved(syspath);
      break;

    default:
      break;
  }
}

void Udev::TaggedDeviceChanged(const std::string& syspath,
                               const base::FilePath& wakeup_device_path,
                               const std::string& tags) {
  if (!tags.empty()) {
    LOG(INFO) << (tagged_devices_.count(syspath) ? "Updating" : "Adding")
              << " device " << syspath << " with tags " << tags;
  }

  // Replace existing device with same syspath.
  tagged_devices_[syspath] = TaggedDevice(syspath, wakeup_device_path, tags);
  const TaggedDevice& device = tagged_devices_[syspath];
  for (UdevTaggedDeviceObserver& observer : tagged_device_observers_)
    observer.OnTaggedDeviceChanged(device);
}

void Udev::TaggedDeviceRemoved(const std::string& syspath) {
  TaggedDevice device = tagged_devices_[syspath];
  if (!device.tags().empty())
    LOG(INFO) << "Removing device " << syspath;
  tagged_devices_.erase(syspath);
  for (UdevTaggedDeviceObserver& observer : tagged_device_observers_)
    observer.OnTaggedDeviceRemoved(device);
}

bool Udev::EnumerateTaggedDevices() {
  DCHECK(udev_);

  struct udev_enumerate* enumerate = udev_enumerate_new(udev_);
  if (!enumerate) {
    LOG(ERROR) << "udev_enumerate_new failed";
    return false;
  }
  if (udev_enumerate_add_match_tag(enumerate, kPowerdUdevTag) != 0) {
    LOG(ERROR) << "udev_enumerate_add_match_tag failed";
    udev_enumerate_unref(enumerate);
    return false;
  }
  if (udev_enumerate_scan_devices(enumerate) != 0) {
    LOG(ERROR) << "udev_enumerate_scan_devices failed";
    udev_enumerate_unref(enumerate);
    return false;
  }

  tagged_devices_.clear();

  struct udev_list_entry* entry = nullptr;
  udev_list_entry_foreach(entry, udev_enumerate_get_list_entry(enumerate)) {
    const char* syspath = udev_list_entry_get_name(entry);
    struct udev_device* device = udev_device_new_from_syspath(udev_, syspath);
    if (!device) {
      LOG(ERROR) << "Enumerated device does not exist: " << syspath;
      continue;
    }
    const char* tags_cstr =
        udev_device_get_property_value(device, kPowerdTagsVar);
    const std::string tags = tags_cstr ? tags_cstr : "";
    if (!tags.empty())
      LOG(INFO) << "Adding device " << syspath << " with tags " << tags;
    tagged_devices_[syspath] =
        TaggedDevice(syspath, FindWakeCapableParent(syspath), tags);
    udev_device_unref(device);
  }
  udev_enumerate_unref(enumerate);
  return true;
}

}  // namespace power_manager::system
