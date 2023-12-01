// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_UDEV_H_
#define POWER_MANAGER_POWERD_SYSTEM_UDEV_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/observer_list.h>

#include "power_manager/powerd/system/tagged_device.h"

struct udev;
struct udev_device;
struct udev_monitor;

namespace power_manager::system {

class TaggedDevice;
class UdevSubsystemObserver;
class UdevTaggedDeviceObserver;

struct UdevDeviceInfo {
  std::string subsystem;
  std::string devtype;
  std::string sysname;
  std::string syspath;
  // Directory (of itself/ancestor) with power/wakeup property.
  base::FilePath wakeup_device_path;
};

// UdevEvent describes a udev event.
struct UdevEvent {
  enum class Action {
    ADD = 0,
    REMOVE,
    CHANGE,
    ONLINE,
    OFFLINE,
    UNKNOWN,
  };
  UdevDeviceInfo device_info;
  Action action;
};

// Watches the udev manager for device-related events (e.g. hotplug).
class UdevInterface {
 public:
  UdevInterface() = default;
  virtual ~UdevInterface() = default;

  // Adds or removes an observer for watching |subsystem|. To receive events,
  // this subsystem must also be given a "powerd" tag by
  // udev/94-powerd-late.rules.
  virtual void AddSubsystemObserver(const std::string& subsystem,
                                    UdevSubsystemObserver* observer) = 0;
  virtual void RemoveSubsystemObserver(const std::string& subsystem,
                                       UdevSubsystemObserver* observer) = 0;

  // Adds/removes an observer that will receive events for tagged devices.
  virtual void AddTaggedDeviceObserver(UdevTaggedDeviceObserver* observer) = 0;
  virtual void RemoveTaggedDeviceObserver(
      UdevTaggedDeviceObserver* observer) = 0;

  // Retrieves a list of all known tagged devices.
  virtual std::vector<TaggedDevice> GetTaggedDevices() = 0;

  // Retrieves the list of existing devices that belong to the given subsystem.
  virtual bool GetSubsystemDevices(
      const std::string& subsystem,
      std::vector<UdevDeviceInfo>* devices_out) = 0;

  // Reads the sysfs attribute |sysattr| from the device specified by |syspath|.
  // Returns true on success. |syspath| is the syspath of a device as returned
  // by libudev, e.g.
  // "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/input/input22".
  virtual bool GetSysattr(const std::string& syspath,
                          const std::string& sysattr,
                          std::string* value) = 0;

  virtual bool HasSysattr(const std::string& syspath,
                          const std::string& sysattr) = 0;

  // Sets the value of a sysfs attribute. Returns true on success.
  virtual bool SetSysattr(const std::string& syspath,
                          const std::string& sysattr,
                          const std::string& value) = 0;

  // For the device specified by |syspath|, finds all the devlinks that
  // udev configured, and stores their paths in |out|.
  virtual bool GetDevlinks(const std::string& syspath,
                           std::vector<std::string>* out) = 0;

  // For the device specified by |syspath|, check if it has the specified powerd
  // role.
  virtual bool HasPowerdRole(const std::string& syspath,
                             const std::string& role) = 0;
};

// Actual implementation of UdevInterface.
class Udev : public UdevInterface {
 public:
  Udev() = default;
  Udev(const Udev&) = delete;
  Udev& operator=(const Udev&) = delete;

  ~Udev() override;

  // Initializes the object to listen for events. Returns true on success.
  bool Init();

  // UdevInterface implementation:
  void AddSubsystemObserver(const std::string& subsystem,
                            UdevSubsystemObserver* observer) override;
  void RemoveSubsystemObserver(const std::string& subsystem,
                               UdevSubsystemObserver* observer) override;
  void AddTaggedDeviceObserver(UdevTaggedDeviceObserver* observer) override;
  void RemoveTaggedDeviceObserver(UdevTaggedDeviceObserver* observer) override;
  std::vector<TaggedDevice> GetTaggedDevices() override;
  bool GetSubsystemDevices(const std::string& subsystem,
                           std::vector<UdevDeviceInfo>* devices_out) override;
  bool HasSysattr(const std::string& syspath,
                  const std::string& sysattr) override;
  bool GetSysattr(const std::string& syspath,
                  const std::string& sysattr,
                  std::string* value) override;
  bool SetSysattr(const std::string& syspath,
                  const std::string& sysattr,
                  const std::string& value) override;
  bool GetDevlinks(const std::string& syspath,
                   std::vector<std::string>* out) override;
  bool HasPowerdRole(const std::string& syspath,
                     const std::string& role) override;

  void OnFileCanReadWithoutBlocking();

 private:
  void HandleSubsystemEvent(UdevEvent::Action action, struct udev_device* dev);
  void HandleTaggedDevice(UdevEvent::Action action, struct udev_device* dev);
  void TaggedDeviceChanged(const std::string& syspath,
                           const base::FilePath& wakeup_device_path,
                           const std::string& tags);
  void TaggedDeviceRemoved(const std::string& syspath);

  // Populates |tagged_devices_| with currently-existing devices.
  bool EnumerateTaggedDevices();

  // For the udev_device specified by |syspath|, finds the first parent device
  // which has a sysattr named |sysattr|, and returns the parent's syspath.
  // If |stop_at_devtype| is a nonempty string, then no parent devices will be
  // considered beyond the first device matching |stop_at_devtype|. Returns
  // syspath of the parent with the |sysattr| on success, or an empty path
  // when no matching parent device was found.
  base::FilePath FindParentWithSysattr(const std::string& syspath,
                                       const std::string& sysattr,
                                       const std::string& stop_at_devtype);

  // Returns the first ancestor which is wake capable (i.e has power/wakeup
  // property). If the passed device with sysfs path |syspath| is wake capable,
  // returns the same.
  // For input devices controlled by 'crosec' which are not wake capable
  // by themselves, this function is expected to travel the hierarchy to find
  // crosec which is wake capable.
  // For USB devices, the input device does not have a power/wakeup property
  // itself, but the corresponding USB device does. If the matching device does
  // not have a power/wakeup property, we thus fall back to the first ancestor
  // that has one. Conflicts should not arise, since real-world USB input
  // devices typically only expose one input interface anyway. However, crawling
  // up sysfs should only reach the first "usb_device" node, because
  // higher-level nodes include USB hubs, and enabling wakeups on those isn't a
  // good idea.
  base::FilePath FindWakeCapableParent(const std::string& syspath);

  bool GetDeviceInfo(struct udev_device* dev, UdevDeviceInfo* device_info_out);
  struct udev* udev_ = nullptr;
  struct udev_monitor* udev_monitor_ = nullptr;

  // Maps from a subsystem name to the corresponding observers.
  std::map<std::string,
           std::unique_ptr<base::ObserverList<UdevSubsystemObserver>>>
      subsystem_observers_;

  base::ObserverList<UdevTaggedDeviceObserver> tagged_device_observers_;

  // Maps a syspath to the corresponding TaggedDevice.
  std::map<std::string, TaggedDevice> tagged_devices_;

  // Controller for watching |udev_monitor_|'s FD for readability.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> controller_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_UDEV_H_
