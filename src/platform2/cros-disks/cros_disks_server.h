// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_CROS_DISKS_SERVER_H_
#define CROS_DISKS_CROS_DISKS_SERVER_H_

#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/ref_counted.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/bus.h>

#include "cros-disks/dbus_adaptors/org.chromium.CrosDisks.h"
#include "cros-disks/device_event_dispatcher_interface.h"
#include "cros-disks/device_event_queue.h"
#include "cros-disks/disk.h"
#include "cros-disks/format_manager_observer_interface.h"
#include "cros-disks/mount_point.h"
#include "cros-disks/rename_manager_observer_interface.h"
#include "cros-disks/session_manager_observer_interface.h"

namespace cros_disks {

class DiskMonitor;
class FormatManager;
class MountManager;
class PartitionManager;
class Platform;
class RenameManager;

struct DeviceEvent;

class CrosDisksServer : public org::chromium::CrosDisksAdaptor,
                        public org::chromium::CrosDisksInterface,
                        public DeviceEventDispatcherInterface,
                        public FormatManagerObserverInterface,
                        public SessionManagerObserverInterface,
                        public RenameManagerObserverInterface {
 public:
  CrosDisksServer(scoped_refptr<dbus::Bus> bus,
                  Platform* platform,
                  DiskMonitor* disk_monitor,
                  FormatManager* format_manager,
                  PartitionManager* partition_manager,
                  RenameManager* rename_manager);
  ~CrosDisksServer() override = default;

  // Registers the D-Bus object and interfaces.
  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  // Registers a mount manager.
  void RegisterMountManager(MountManager* mount_manager);

  // Implementation of org::chromium::CrosDisks:

  // A method for formatting a device specified by |path|.
  // On completion, a FormatCompleted signal is emitted to indicate whether
  // the operation succeeded or failed using a FormatErrorType enum value.
  void Format(const std::string& path,
              const std::string& filesystem_type,
              const std::vector<std::string>& options) override;

  // Partitions a device into a single partition taking up the whole drive.
  // Returns error code to indicate whether operation succeeded or failed using
  // a PartitionErrorType enum value.
  void SinglePartitionFormat(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<uint32_t>>
          response,
      const std::string& path) override;

  // A method for renaming a device specified by |path|.
  // On completion, a RenameCompleted signal is emitted to indicate whether
  // the operation succeeded or failed using a RenameErrorType enum value.
  void Rename(const std::string& path, const std::string& volume_name) override;

  // Mounts a source when invoked.
  void Mount(const std::string& source,
             const std::string& filesystem_type,
             const std::vector<std::string>& options) override;

  // Unmounts a path when invoked.
  uint32_t Unmount(const std::string& path,
                   const std::vector<std::string>& options) override;

  // Unmounts all paths mounted by Mount() when invoked.
  void UnmountAll() override;

  // Returns a list of device sysfs paths for all disk devices attached to
  // the system.
  std::vector<std::string> EnumerateDevices() override;

  // Returns a list of mount entries (<error type, source path, source type,
  // mount path, read only>) that are currently managed by cros-disks.
  using MountEntry =
      std::tuple<uint32_t, std::string, uint32_t, std::string, bool>;
  using MountEntries = std::vector<MountEntry>;
  MountEntries EnumerateMountEntries() override;

  // Returns properties of a disk device attached to the system.
  bool GetDeviceProperties(brillo::ErrorPtr* error,
                           const std::string& device_path,
                           brillo::VariantDictionary* properties) override;

  // Used in tests to allow loopback devices to be used for operations.
  // |device_path| specifies the syspath of the device (e.g. /sys/devices/...).
  void AddDeviceToAllowlist(const std::string& device_path) override;
  void RemoveDeviceFromAllowlist(const std::string& device_path) override;

  // Implements the FormatManagerObserverInterface interface to handle
  // the event when a formatting operation has completed.
  void OnFormatCompleted(const std::string& device_path,
                         FormatError error_type) override;

  void OnMountProgress(const MountPoint* mount_point);

  void OnMountCompleted(const std::string& source,
                        MountSourceType source_type,
                        const std::string& filesystem_type,
                        const std::string& mount_path,
                        MountError error,
                        bool read_only);

  // The callback called when a partitioning operation has completed.
  void OnPartitionCompleted(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<uint32_t>>
          response,
      const base::FilePath& device_path,
      PartitionError error_type);

  // Implements the RenameManagerObserverInterface interface to handle
  // the event when a renaming operation has completed.
  void OnRenameCompleted(const std::string& device_path,
                         RenameError error_type) override;

  // Implements the SessionManagerObserverInterface interface to handle
  // the event when the screen is locked.
  void OnScreenIsLocked() override;

  // Implements the SessionManagerObserverInterface interface to handle
  // the event when the screen is unlocked.
  void OnScreenIsUnlocked() override;

  // Implements the SessionManagerObserverInterface interface to handle
  // the event when the session has been started.
  void OnSessionStarted() override;

  // Implements the SessionManagerObserverInterface interface to handle
  // the event when the session has been stopped.
  void OnSessionStopped() override;

 private:
  // Implements the DeviceEventDispatcherInterface to dispatch a device event
  // by emitting the corresponding D-Bus signal.
  void DispatchDeviceEvent(const DeviceEvent& event) override;

  // Finds and returns a mounter which can mount |source_path|, or nullptr if no
  // one can.
  MountManager* FindMounter(const std::string& source_path) const;

  brillo::dbus_utils::DBusObject dbus_object_;
  Platform* platform_;
  DiskMonitor* disk_monitor_;
  FormatManager* format_manager_;
  PartitionManager* partition_manager_;
  RenameManager* rename_manager_;
  std::vector<MountManager*> mount_managers_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_CROS_DISKS_SERVER_H_
