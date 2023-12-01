// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_DISK_MANAGER_H_
#define CROS_DISKS_DISK_MANAGER_H_

#include <libudev.h>

#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/functional/callback.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/disk.h"
#include "cros-disks/mount_manager.h"

namespace cros_disks {

class DeviceEjector;
class DiskMonitor;
class Mounter;
class Platform;
class SandboxedProcessFactory;

// The DiskManager is responsible for mounting removable media.
//
// This class is designed to run within a single-threaded GMainLoop application
// and should not be considered thread safe.
class DiskManager : public MountManager {
 public:
  DiskManager(const std::string& mount_root,
              Platform* platform,
              Metrics* metrics,
              brillo::ProcessReaper* process_reaper,
              DiskMonitor* disk_monitor,
              DeviceEjector* device_ejector,
              const SandboxedProcessFactory* test_sandbox_factory = nullptr);
  DiskManager(const DiskManager&) = delete;
  DiskManager& operator=(const DiskManager&) = delete;

  ~DiskManager() override;

  // Initializes the disk manager and registers default filesystems.
  // Returns true on success.
  bool Initialize() override;

  // Returns true if mounting |source_path| is supported.
  bool CanMount(const std::string& source_path) const override;

  MountSourceType GetMountSourceType() const final {
    return MOUNT_SOURCE_REMOVABLE_DEVICE;
  }

  // Unmounts all mounted paths.
  void UnmountAll() override;

 protected:
  // Mounts |source_path| to |mount_path| as |filesystem_type| with |options|.
  std::unique_ptr<MountPoint> DoMount(const std::string& source_path,
                                      const std::string& filesystem_type,
                                      const std::vector<std::string>& options,
                                      const base::FilePath& mount_path,
                                      MountError* error) override;

  // Returns a suggested mount path for a source path.
  std::string SuggestMountPath(const std::string& source_path) const override;

  // Returns true to reserve a mount path on errors due to unknown or
  // unsupported filesystems.
  bool ShouldReserveMountPathOnError(MountError error_type) const override;

 private:
  // Ejects media for the device |device_file|. Return true if the eject process
  // has started or |eject_device_on_unmount_| is false, or false if the eject
  // process failed.
  bool EjectDevice(const std::string& device_file);

  // If |disk| is an optical disk, wrap |mount_point| in a wrapper that ejects
  // the disk on a successful unmount. If |disk| is not an optical disk, returns
  // |mount_point|. This is exposed as a function to allow ejecting behaviour to
  // be tested.
  std::unique_ptr<MountPoint> MaybeWrapMountPointForEject(
      std::unique_ptr<MountPoint> mount_point, const Disk& disk);

  DiskMonitor* const disk_monitor_;
  DeviceEjector* const device_ejector_;
  const SandboxedProcessFactory* const test_sandbox_factory_;

  // Set to true if devices should be ejected upon unmount.
  bool eject_device_on_unmount_;

  // Mapping of filesystem types to corresponding mounters.
  std::unordered_map<std::string, std::unique_ptr<Mounter>> mounters_;

  FRIEND_TEST(DiskManagerTest, DoMountDiskWithNonexistentSourcePath);
  FRIEND_TEST(DiskManagerTest, EjectDevice);
  FRIEND_TEST(DiskManagerTest, EjectDeviceWhenUnmountFailed);
  FRIEND_TEST(DiskManagerTest, EjectDeviceWhenExplicitlyDisabled);
  FRIEND_TEST(DiskManagerTest, EjectDeviceWhenReleased);
};

}  // namespace cros_disks

#endif  // CROS_DISKS_DISK_MANAGER_H_
