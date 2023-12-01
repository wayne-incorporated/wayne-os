// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/disk_manager.h"

#include <errno.h>
#include <inttypes.h>
#include <libudev.h>
#include <string.h>
#include <sys/mount.h>
#include <time.h>

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>

#include "cros-disks/device_ejector.h"
#include "cros-disks/disk_monitor.h"
#include "cros-disks/fuse_mounter.h"
#include "cros-disks/metrics.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/mount_point.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"
#include "cros-disks/system_mounter.h"
#include "dbus/cros-disks/dbus-constants.h"

namespace cros_disks {

namespace {

// Options passed to the mount syscall for various filesystem types.
constexpr char kMountOptionFlush[] = "flush";
constexpr char kMountOptionUtf8[] = "utf8";

// Options passed to the FUSE module for various filesystem types.
constexpr char kFUSEOptionDirSync[] = "dirsync";
constexpr char kFUSEOptionDmask[] = "dmask=0027";  // directory permissions 0750
constexpr char kFUSEOptionFmask[] = "fmask=0027";  // file permissions 0750

// Implementation of FUSEMounter aimed at removable storage with
// exFAT or NTFS filesystems.
class DiskFUSEMounter : public FUSEMounter {
 public:
  DiskFUSEMounter(const Platform* platform,
                  brillo::ProcessReaper* reaper,
                  std::string filesystem_type,
                  const SandboxedProcessFactory* upstream_factory,
                  SandboxedExecutable executable,
                  OwnerUser run_as,
                  std::vector<std::string> options)
      : FUSEMounter(platform, reaper, std::move(filesystem_type), {}),
        upstream_factory_(upstream_factory),
        sandbox_factory_(platform, std::move(executable), run_as),
        options_(std::move(options)) {}

 private:
  // FUSEMounter overrides:
  bool CanMount(const std::string& source,
                const std::vector<std::string>& params,
                base::FilePath* suggested_name) const override {
    if (suggested_name)
      *suggested_name = base::FilePath("disk");
    return true;
  }

  std::unique_ptr<SandboxedProcess> PrepareSandbox(
      const std::string& source,
      const base::FilePath&,
      std::vector<std::string>,
      MountError* error) const override {
    auto device = base::FilePath(source);

    if (!device.IsAbsolute() || device.ReferencesParent() ||
        !base::StartsWith(device.value(), "/dev/",
                          base::CompareCase::SENSITIVE)) {
      LOG(ERROR) << "Device path " << quote(device) << " is invalid";
      *error = MountError::kInvalidArgument;
      return nullptr;
    }

    if (!platform()->PathExists(device.value())) {
      PLOG(ERROR) << "Cannot access device " << quote(device);
      *error = MountError::kInvalidDevicePath;
      return nullptr;
    }

    // Make sure the FUSE user can read-write to the device.
    if (!platform()->SetOwnership(device.value(), getuid(),
                                  sandbox_factory_.run_as().gid) ||
        !platform()->SetPermissions(source,
                                    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) {
      PLOG(ERROR) << "Cannot set up permissions on device " << quote(source);
      *error = MountError::kInsufficientPermissions;
      return nullptr;
    }

    std::unique_ptr<SandboxedProcess> sandbox;
    // For tests we use injected factory.
    if (upstream_factory_) {
      sandbox = upstream_factory_->CreateSandboxedProcess();
      sandbox->AddArgument(sandbox_factory_.executable().value());
    } else {
      sandbox = sandbox_factory_.CreateSandboxedProcess();
    }

    // Bind-mount the device into the sandbox.
    if (!sandbox->BindMount(device.value(), device.value(), true, false)) {
      PLOG(ERROR) << "Cannot bind-mount device " << quote(device)
                  << " into the sandbox";
      *error = MountError::kInternalError;
      return nullptr;
    }

    if (!options_.empty()) {
      std::string options;
      if (!JoinParamsIntoOptions(options_, &options)) {
        *error = MountError::kInvalidMountOptions;
        return nullptr;
      }
      sandbox->AddArgument("-o");
      sandbox->AddArgument(options);
    }

    sandbox->AddArgument(device.value());

    *error = MountError::kSuccess;
    return sandbox;
  }

  // Used to inject mocks for testing.
  const SandboxedProcessFactory* const upstream_factory_;

  const FUSESandboxedProcessFactory sandbox_factory_;
  const std::vector<std::string> options_;
};

// Specialization of a system mounter which deals with FAT-specific
// mount options.
class FATMounter : public SystemMounter {
 public:
  FATMounter(const Platform* platform, std::vector<std::string> options)
      : SystemMounter(
            platform, "vfat", /* read_only= */ false, std::move(options)) {}

 private:
  MountError ParseParams(
      std::vector<std::string> params,
      std::vector<std::string>* mount_options) const override {
    // FAT32 stores times as local time instead of UTC. By default, the vfat
    // kernel module will use the kernel's time zone, which is set using
    // settimeofday(), to interpret time stamps as local time. However, time
    // zones are complicated and generally a user-space concern in modern Linux.
    // The man page for {get,set}timeofday comments that the |timezone| fields
    // of these functions is obsolete. Chrome OS doesn't appear to set these
    // either. Instead, we pass the time offset explicitly as a mount option so
    // that the user can see file time stamps as local time. This mirrors what
    // the user will see in other operating systems.
    time_t now = base::Time::Now().ToTimeT();
    struct tm timestruct;
    // The time zone might have changed since cros-disks was started. Force a
    // re-read of the time zone to ensure the local time is what the user
    // expects.
    tzset();
    localtime_r(&now, &timestruct);
    // tm_gmtoff is a glibc extension.
    int64_t offset_minutes = static_cast<int64_t>(timestruct.tm_gmtoff) / 60;
    std::string offset_option =
        base::StringPrintf("time_offset=%" PRId64, offset_minutes);

    mount_options->push_back(offset_option);

    return SystemMounter::ParseParams(std::move(params), mount_options);
  }
};

}  // namespace

DiskManager::DiskManager(const std::string& mount_root,
                         Platform* platform,
                         Metrics* metrics,
                         brillo::ProcessReaper* process_reaper,
                         DiskMonitor* disk_monitor,
                         DeviceEjector* device_ejector,
                         const SandboxedProcessFactory* test_sandbox_factory)
    : MountManager(mount_root, platform, metrics, process_reaper),
      disk_monitor_(disk_monitor),
      device_ejector_(device_ejector),
      test_sandbox_factory_(test_sandbox_factory),
      eject_device_on_unmount_(true) {}

DiskManager::~DiskManager() {
  UnmountAll();
}

bool DiskManager::Initialize() {
  OwnerUser run_as_exfat;
  if (!platform()->GetUserAndGroupId("fuse-exfat", &run_as_exfat.uid,
                                     &run_as_exfat.gid)) {
    PLOG(ERROR) << "Cannot resolve fuse-exfat user";
    return false;
  }
  OwnerUser run_as_ntfs;
  if (!platform()->GetUserAndGroupId("ntfs-3g", &run_as_ntfs.uid,
                                     &run_as_ntfs.gid)) {
    PLOG(ERROR) << "Cannot resolve ntfs-3g user";
    return false;
  }

  std::string uid = base::StringPrintf("uid=%d", kChronosUID);
  std::string gid = base::StringPrintf("gid=%d", kChronosAccessGID);

  // FAT32 - typical USB stick/SD card filesystem.
  mounters_["vfat"] = std::make_unique<FATMounter>(
      platform(), std::vector<std::string>{kMountOptionFlush, "shortname=mixed",
                                           kMountOptionUtf8, uid, gid});

  // Fancier newer version of FAT used for new big SD cards and USB sticks.
  mounters_["exfat"] = std::make_unique<DiskFUSEMounter>(
      platform(), process_reaper(), "exfat", test_sandbox_factory_,
      SandboxedExecutable{base::FilePath("/usr/sbin/mount.exfat-fuse")},
      run_as_exfat,
      std::vector<std::string>{kFUSEOptionDirSync, kFUSEOptionDmask,
                               kFUSEOptionFmask, uid, gid});

  // External drives and some big USB sticks would likely have NTFS.
  mounters_["ntfs"] = std::make_unique<DiskFUSEMounter>(
      platform(), process_reaper(), "ntfs", test_sandbox_factory_,
      SandboxedExecutable{base::FilePath("/usr/bin/ntfs-3g")}, run_as_ntfs,
      std::vector<std::string>{kFUSEOptionDirSync, kFUSEOptionDmask,
                               kFUSEOptionFmask, uid, gid});

  // Typical CD/DVD filesystem. Inherently read-only.
  mounters_["iso9660"] = std::make_unique<SystemMounter>(
      platform(), "iso9660", true,
      std::vector<std::string>{kMountOptionUtf8, uid, gid});

  // Newer DVD filesystem. Inherently read-only.
  mounters_["udf"] = std::make_unique<SystemMounter>(
      platform(), "udf", true,
      std::vector<std::string>{kMountOptionUtf8, uid, gid});

  // MacOS's HFS+ is not properly/officially supported, but sort of works,
  // although with severe limitaions.
  mounters_["hfsplus"] = std::make_unique<SystemMounter>(
      platform(), "hfsplus", false, std::vector<std::string>{uid, gid});

  // Have no reasonable explanation why would one have external media
  // with a native Linux, filesystem and use CrOS to access it, given
  // all the problems and limitations they would face, but for compatibility
  // with previous versions we keep it unofficially supported.
  mounters_["ext4"] = std::make_unique<SystemMounter>(
      platform(), "ext4", false, std::vector<std::string>{});
  mounters_["ext3"] = std::make_unique<SystemMounter>(
      platform(), "ext3", false, std::vector<std::string>{});
  mounters_["ext2"] = std::make_unique<SystemMounter>(
      platform(), "ext2", false, std::vector<std::string>{});

  return MountManager::Initialize();
}

bool DiskManager::CanMount(const std::string& source_path) const {
  // The following paths can be mounted:
  //     /sys/...
  //     /devices/...
  //     /dev/...
  return base::StartsWith(source_path, "/sys/", base::CompareCase::SENSITIVE) ||
         base::StartsWith(source_path, "/devices/",
                          base::CompareCase::SENSITIVE) ||
         base::StartsWith(source_path, "/dev/", base::CompareCase::SENSITIVE);
}

std::unique_ptr<MountPoint> DiskManager::DoMount(
    const std::string& source_path,
    const std::string& filesystem_type,
    const std::vector<std::string>& options,
    const base::FilePath& mount_path,
    MountError* error) {
  CHECK(!source_path.empty()) << "Invalid source path argument";
  CHECK(!mount_path.empty()) << "Invalid mount path argument";

  Disk disk;
  if (!disk_monitor_->GetDiskByDevicePath(base::FilePath(source_path), &disk)) {
    LOG(ERROR) << quote(source_path) << " is not a valid device";
    *error = MountError::kInvalidDevicePath;
    return nullptr;
  }

  if (disk.is_on_boot_device) {
    LOG(ERROR) << quote(source_path)
               << " is on boot device and not allowed to mount";
    *error = MountError::kInvalidDevicePath;
    return nullptr;
  }

  if (disk.device_file.empty()) {
    LOG(ERROR) << quote(source_path) << " does not have a device file";
    *error = MountError::kInvalidDevicePath;
    return nullptr;
  }

  if (!platform()->PathExists(disk.device_file)) {
    PLOG(ERROR) << quote(source_path) << " has device file "
                << quote(disk.device_file) << " which is missing";
    *error = MountError::kInvalidDevicePath;
    return nullptr;
  }

  const std::string fstype =
      filesystem_type.empty() ? disk.filesystem_type : filesystem_type;
  metrics()->RecordDeviceMediaType(disk.media_type);
  metrics()->RecordFilesystemType(fstype);
  if (fstype.empty()) {
    LOG(ERROR) << "Cannot determine filesystem type of device "
               << quote(source_path);
    *error = MountError::kUnknownFilesystem;
    return nullptr;
  }

  const auto it = mounters_.find(fstype);
  if (it == mounters_.end()) {
    LOG(ERROR) << "Cannot handle filesystem type " << quote(fstype)
               << " of device " << quote(source_path);
    *error = MountError::kUnsupportedFilesystem;
    return nullptr;
  }

  const Mounter* const mounter = it->second.get();
  DCHECK(mounter);

  auto applied_options = options;
  if (const bool media_read_only = disk.is_read_only || disk.IsOpticalDisk();
      media_read_only && !IsReadOnlyMount(applied_options)) {
    applied_options.push_back("ro");
  }

  std::unique_ptr<MountPoint> mount_point =
      mounter->Mount(disk.device_file, mount_path, applied_options, error);
  if (*error != MountError::kSuccess) {
    DCHECK(!mount_point);
    // Try to mount the filesystem read-only if mounting it read-write failed.
    if (!IsReadOnlyMount(applied_options)) {
      LOG(INFO) << "Trying to mount " << quote(disk.device_file)
                << " again, but in read-only mode this time";
      applied_options.push_back("ro");
      mount_point =
          mounter->Mount(disk.device_file, mount_path, applied_options, error);
      if (*error == MountError::kSuccess) {
        // crbug.com/1366204: Managed to mount the external media in read-only
        // mode after failing to mount it in read-write mode.
        DCHECK(mount_point);
        DCHECK(mount_point->is_read_only());
        LOG(WARNING) << "Mounted " << quote(mount_point->source())
                     << " as read-only " << quote(mount_point->fstype()) << " "
                     << redact(mount_point->path())
                     << " because it could not be mounted in writable mode";
        metrics()->RecordReadOnlyFileSystem(fstype);
      }
    }
  }

  if (*error != MountError::kSuccess) {
    DCHECK(!mount_point);
    return nullptr;
  }

  return MaybeWrapMountPointForEject(std::move(mount_point), disk);
}

std::string DiskManager::SuggestMountPath(
    const std::string& source_path) const {
  Disk disk;
  disk_monitor_->GetDiskByDevicePath(base::FilePath(source_path), &disk);
  // If GetDiskByDevicePath fails, disk.GetPresentationName() returns
  // the fallback presentation name.
  return mount_root().Append(disk.GetPresentationName()).value();
}

bool DiskManager::ShouldReserveMountPathOnError(MountError error_type) const {
  return error_type == MountError::kUnknownFilesystem ||
         error_type == MountError::kUnsupportedFilesystem;
}

bool DiskManager::EjectDevice(const std::string& device_file) {
  if (eject_device_on_unmount_) {
    return device_ejector_->Eject(device_file);
  }
  return true;
}

std::unique_ptr<MountPoint> DiskManager::MaybeWrapMountPointForEject(
    std::unique_ptr<MountPoint> mount_point, const Disk& disk) {
  DCHECK(mount_point);

  if (disk.IsOpticalDisk()) {
    mount_point->SetEject(base::BindOnce(
        [](DiskManager* const disk_manager, const std::string& device_file) {
          if (!disk_manager->EjectDevice(device_file))
            LOG(ERROR) << "Cannot eject device " << quote(device_file);
        },
        this, disk.device_file));
  }

  return mount_point;
}

void DiskManager::UnmountAll() {
  // UnmountAll() is called when a user session ends. We do not want to eject
  // devices in that situation and thus set |eject_device_on_unmount_| to
  // false temporarily to prevent devices from being ejected upon unmount.
  eject_device_on_unmount_ = false;
  MountManager::UnmountAll();
  eject_device_on_unmount_ = true;
}

}  // namespace cros_disks
