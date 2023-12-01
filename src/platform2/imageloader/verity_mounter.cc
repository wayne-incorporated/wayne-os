// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/verity_mounter.h"

#include <algorithm>
#include <memory>
#include <utility>

#include <fcntl.h>
#include <libdevmapper.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <mntent.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>

#include <base/check.h>
#include <base/command_line.h>
#include <base/containers/adapters.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/files/file_util.h>

#include "imageloader/component.h"
#include "imageloader/verity_mounter_impl.h"

namespace imageloader {

namespace {
// Path to devices created by device mapper.
constexpr char kDeviceMapperPath[] = "/dev/mapper";

// Path to the loop control device.
constexpr char kDevLoopControl[] = "/dev/loop-control";

using dm_task_ptr = std::unique_ptr<dm_task, void (*)(dm_task*)>;

enum class MountStatus { FAIL, RETRY, SUCCESS };

constexpr int GET_LOOP_DEVICE_MAX_RETRY = 5;

// Fetches the device mapper table entry with the specified name and writes the
// type and parameters into the provided pointers.
// Returns true on success.
bool MapperGetEntry(const std::string& name,
                    std::string* type,
                    std::string* parameters) {
  auto task = dm_task_ptr(dm_task_create(DM_DEVICE_TABLE), &dm_task_destroy);
  struct dm_info info;

  if (!task) {
    LOG(ERROR) << "dm_task_create failed!";
    return false;
  }

  if (!dm_task_set_name(task.get(), name.c_str())) {
    LOG(ERROR) << "dm_task_set_name failed!";
    return false;
  }

  if (!dm_task_run(task.get())) {
    LOG(ERROR) << "dm_task_run failed!";
    return false;
  }

  if (!dm_task_get_info(task.get(), &info)) {
    LOG(ERROR) << "dm_task_get_info failed!";
    return false;
  }

  void* next = nullptr;
  uint64_t start;
  uint64_t length;
  char* type_cstr;
  char* parameters_cstr;
  next = dm_get_next_target(task.get(), next, &start, &length, &type_cstr,
                            &parameters_cstr);
  if (type != nullptr) {
    *type = std::string(type_cstr);
  }
  if (parameters != nullptr) {
    *parameters = std::string(parameters_cstr);
  }
  return true;
}

// TODO(b/172220337): Consolidate with libbrillo/blkdevutils.
// Executes the equivalent of: dmsetup wipe_table <name>
// Returns true on success.
bool MapperWipeTable(const std::string& name) {
  auto task = dm_task_ptr(dm_task_create(DM_DEVICE_TABLE), &dm_task_destroy);
  struct dm_info info;

  if (!task) {
    LOG(ERROR) << "dm_task_create failed!";
    return false;
  }

  if (!dm_task_set_name(task.get(), name.c_str())) {
    LOG(ERROR) << "dm_task_set_name failed!";
    return false;
  }

  if (!dm_task_run(task.get())) {
    LOG(ERROR) << "dm_task_run failed!";
    return false;
  }

  if (!dm_task_get_info(task.get(), &info)) {
    LOG(ERROR) << "dm_task_get_info failed!";
    return false;
  }

  void* next = nullptr;
  uint64_t start;
  uint64_t length;
  char* type;
  char* parameters;
  do {
    next = dm_get_next_target(task.get(), next, &start, &length, &type,
                              &parameters);
    auto task = dm_task_ptr(dm_task_create(DM_DEVICE_RELOAD), &dm_task_destroy);

    if (!task) {
      LOG(ERROR) << "dm_task_create failed!";
      return false;
    }

    if (!dm_task_set_name(task.get(), name.c_str())) {
      LOG(ERROR) << "dm_task_set_name failed!";
      return false;
    }

    if (!dm_task_add_target(task.get(), 0, length, type, parameters)) {
      LOG(ERROR) << "dm_task_add_target failed!";
      return false;
    }

    if (!dm_task_run(task.get())) {
      LOG(ERROR) << "dm_task_run failed!";
      return false;
    }
  } while (next);

  return true;
}

// Executes the equivalent of: dmsetup remove <name>
// Returns true on success.
bool MapperRemove(const std::string& name, bool deferred = false) {
  auto task = dm_task_ptr(dm_task_create(DM_DEVICE_REMOVE), &dm_task_destroy);

  if (!task) {
    LOG(ERROR) << "dm_task_create failed!";
    return false;
  }

  if (!dm_task_set_name(task.get(), name.c_str())) {
    LOG(ERROR) << "dm_task_set_name failed!";
    return false;
  }

  if (deferred && dm_task_deferred_remove(task.get())) {
    LOG(ERROR) << "dm_task_deferred_remove failed!";
    return false;
  }

  if (!dm_task_run(task.get())) {
    LOG(ERROR) << "dm_task_run failed!";
    return false;
  }
  return true;
}

// |argv| should include all the commands and table to dmsetup, but not
// include the path to the binary.
bool RunDMSetup(const std::vector<std::string>& argv) {
  base::LaunchOptions options;
  options.clear_environment = true;

  std::vector<std::string> full_argv(argv);
  full_argv.insert(full_argv.begin(), "/sbin/dmsetup");

  base::Process process = base::LaunchProcess(full_argv, options);

  if (!process.IsValid()) {
    LOG(ERROR) << "Failed to launch dmsetup process";
    return false;
  }

  int exit_code;
  if (!process.WaitForExitWithTimeout(base::Seconds(kDMSetupTimeoutSeconds),
                                      &exit_code)) {
    LOG(ERROR) << "Failed to wait for dmsetup process.";
    return false;
  }

  return exit_code == 0;
}

bool LaunchDMCreate(const std::string& name, const std::string& table) {
  const std::vector<std::string> argv = {"create", name, "--table",
                                         table.c_str(), "--readonly"};
  return RunDMSetup(argv);
}

// Clear the /dev/mapper/<foo> verity device.
void ClearVerityDevice(const std::string& name) {
  // Per the man page, wipe_table:
  // Wait for any I/O in-flight through the device to complete, then replace the
  // table with a new table that fails any new I/O sent to the device.  If
  // successful, this should release any devices held open by the device's
  // table(s).
  MapperWipeTable(name);
  // Now remove the actual device. Fall back to deferred remove if the device
  // is (unlikely) busy: there is a possibility this can happen if udev is still
  // processing rules associated with the device.
  if (!MapperRemove(name))
    MapperRemove(name, /*deferred=*/true);
}

// Clear the file descriptor behind a loop device.
void ClearLoopDevice(const std::string& device_path, int loop_device_num) {
  base::ScopedFD loop_device_fd(
      open(device_path.c_str(), O_RDONLY | O_CLOEXEC));
  if (loop_device_fd.is_valid())
    ioctl(loop_device_fd.get(), LOOP_CLR_FD, 0);

  base::ScopedFD control(
      open(kDevLoopControl, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK));
  if (!control.is_valid()) {
    PLOG(WARNING) << "Failed to open " << kDevLoopControl;
    return;
  }

  if (ioctl(control.get(), LOOP_CTL_REMOVE, loop_device_num) < 0)
    PLOG(WARNING) << "ioctl LOOP_CTL_REMOVE failed";
}

bool SetupDeviceMapper(const std::string& device_path,
                       const std::string& table,
                       std::string* dev_name) {
  // Now setup the dmsetup table.
  std::string final_table = table;
  if (!VerityMounter::SetupTable(&final_table, device_path))
    return false;

  // Generate a name with a random string of 32 characters: we consider this to
  // have sufficiently low chance of collision to assume the name isn't taken.
  std::vector<uint8_t> rand_bytes(32);
  base::RandBytes(rand_bytes.data(), rand_bytes.size());
  std::string name = base::HexEncode(rand_bytes.data(), rand_bytes.size());

  if (!LaunchDMCreate(name, final_table)) {
    LOG(ERROR) << "Failed to run dmsetup.";
    return false;
  }

  const base::FilePath dev_mapper(kDeviceMapperPath);
  dev_name->assign(dev_mapper.Append(name).value().c_str());
  return true;
}

bool CreateDirectoryWithMode(const base::FilePath& full_path, int mode) {
  std::vector<base::FilePath> subpaths;

  // Collect a list of all parent directories.
  base::FilePath last_path = full_path;
  subpaths.push_back(full_path);
  for (base::FilePath path = full_path.DirName();
       path.value() != last_path.value(); path = path.DirName()) {
    subpaths.push_back(path);
    last_path = path;
  }

  // Iterate through the parents and create the missing ones.
  for (const auto& subpath : base::Reversed(subpaths)) {
    if (base::DirectoryExists(subpath))
      continue;
    if (mkdir(subpath.value().c_str(), mode) == 0)
      continue;
    // Mkdir failed, but it might have failed with EEXIST, or some other error
    // due to the directory appearing out of thin air. This can occur if two
    // processes are trying to create the same file system tree at the same
    // time. Check to see if it exists and make sure it is a directory.
    if (!base::DirectoryExists(subpath)) {
      PLOG(ERROR) << "Failed to create directory: " << subpath.value();
      return false;
    }
  }
  return true;
}

bool CreateMountPointIfNeeded(const base::FilePath& mount_point,
                              bool* already_mounted) {
  *already_mounted = false;
  // Is this mount point somehow already taken?
  struct stat st;
  if (lstat(mount_point.value().c_str(), &st) == 0) {
    if (!S_ISDIR(st.st_mode)) {
      LOG(ERROR) << "Mount point exists but is not a directory.";
      return false;
    }

    base::FilePath mount_parent = mount_point.DirName();
    struct stat st2;
    if (stat(mount_parent.value().c_str(), &st2) != 0) {
      PLOG(ERROR) << "Could not stat the mount point parent";
      return false;
    }
    if (st.st_dev != st2.st_dev) {
      struct statfs st_fs;
      if (statfs(mount_point.value().c_str(), &st_fs) != 0) {
        PLOG(ERROR) << "statfs";
        return false;
      }
      if ((st_fs.f_type != SQUASHFS_MAGIC &&
           st_fs.f_type != EXT4_SUPER_MAGIC) ||
          !(st_fs.f_flags & ST_NODEV) || !(st_fs.f_flags & ST_NOSUID) ||
          !(st_fs.f_flags & ST_RDONLY)) {
        LOG(ERROR) << "File system is not the expected type.";
        return false;
      }
      *already_mounted = true;
      return true;
    }
  } else if (!CreateDirectoryWithMode(mount_point, kComponentDirPerms)) {
    LOG(ERROR) << "Failed to create mount point: " << mount_point.value();
    return false;
  }
  return true;
}

// Reserves a loop device and associates it with |image_fd|. The path to the
// loop device is returned in |device_path_out| and the int value is in
// |loop_device_num|. When the loop device is no
// longer being used, free the resource with ClearLoopDevice().
MountStatus GetLoopDevice(const base::ScopedFD& image_fd,
                          std::string* device_path_out,
                          int* loop_device_num) {
  DCHECK(device_path_out);
  DCHECK(loop_device_num);

  base::ScopedFD loopctl_fd(open("/dev/loop-control", O_RDONLY | O_CLOEXEC));
  if (!loopctl_fd.is_valid()) {
    PLOG(ERROR) << "loopctl_fd";
    return MountStatus::FAIL;
  }
  int device_free_number = ioctl(loopctl_fd.get(), LOOP_CTL_GET_FREE);
  if (device_free_number < 0) {
    PLOG(ERROR) << "ioctl : LOOP_CTL_GET_FREE";
    return MountStatus::FAIL;
  }
  *loop_device_num = device_free_number;

  std::string device_path =
      base::StringPrintf("/dev/loop%d", device_free_number);
  base::ScopedFD loop_device_fd(
      open(device_path.c_str(), O_RDONLY | O_CLOEXEC));
  if (!loop_device_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open loop device: " << device_path;
    return MountStatus::FAIL;
  }

  if (ioctl(loop_device_fd.get(), LOOP_SET_FD, image_fd.get()) == -1) {
    if (errno != EBUSY) {
      PLOG(ERROR) << "ioctl: LOOP_SET_FD";
      ioctl(loop_device_fd.get(), LOOP_CLR_FD, 0);
      return MountStatus::FAIL;
    }
    return MountStatus::RETRY;
  }

  // Support since Linux 4.4, so treat as best effort.
  // The (third) ioctl(2) argument is an unsigned long value.
  // A nonzero represents direct I/O mode.
  if (ioctl(loop_device_fd.get(), LOOP_SET_DIRECT_IO, 1) == -1) {
    PLOG(WARNING) << "ioctl: LOOP_SET_DIRECT_IO";
  }

  device_path_out->assign(device_path);
  return MountStatus::SUCCESS;
}

}  // namespace

// static
bool VerityMounter::SetupTable(std::string* table,
                               const std::string& device_path) {
  // Make sure there is only one entry in the device mapper table.
  if (std::count(table->begin(), table->end(), '\n') > 1)
    return false;

  // Remove all newlines from the table. This is to workaround the server
  // incorrectly inserting a newline when writing out the table.
  table->erase(std::remove(table->begin(), table->end(), '\n'), table->end());
  // Replace in the actual loop device name.
  base::ReplaceSubstringsAfterOffset(table, 0, "ROOT_DEV", device_path);
  base::ReplaceSubstringsAfterOffset(table, 0, "HASH_DEV", device_path);
  // If the table does not specify an error condition, use the default (eio).
  // This is critical because the default behavior is to panic the device and
  // force a system recovery. Do not do this for component corruption.
  if (table->find("error_behavior") == std::string::npos)
    table->append(" error_behavior=eio");

  return true;
}

bool VerityMounter::Mount(const base::ScopedFD& image_fd,
                          const base::FilePath& mount_point,
                          const std::string& fs_type,
                          const std::string& table) {
  // First check if the component is already mounted and avoid unnecessary work.
  bool already_mounted = false;
  if (!CreateMountPointIfNeeded(mount_point, &already_mounted))
    return false;
  if (already_mounted)
    return true;

  int loop_device_num;
  std::string loop_device_path;
  // We need to retry because another program could grap the loop device,
  // resulting in an EBUSY error. If that happens, run again and grab a new
  // device.
  int retries = GET_LOOP_DEVICE_MAX_RETRY;
  while (true) {
    MountStatus status =
        GetLoopDevice(image_fd, &loop_device_path, &loop_device_num);
    if (status == MountStatus::FAIL ||
        (status == MountStatus::RETRY && retries == 0)) {
      LOG(ERROR) << "GetLoopDevice failed, mount_point: "
                 << mount_point.value();
      return false;
    } else if (status == MountStatus::SUCCESS) {
      break;
    }
    --retries;
  }

  std::string dev_name;
  if (!SetupDeviceMapper(loop_device_path, table, &dev_name)) {
    LOG(ERROR) << "mount_point: " << mount_point.value();
    ClearLoopDevice(loop_device_path, loop_device_num);
    return false;
  }

  if (mount(dev_name.c_str(), mount_point.value().c_str(), fs_type.c_str(),
            MS_RDONLY | MS_NOSUID | MS_NODEV, "") < 0) {
    PLOG(ERROR) << "mount, mount_point " << mount_point.value();
    ClearVerityDevice(dev_name);
    ClearLoopDevice(loop_device_path, loop_device_num);
    return false;
  }

  return true;
}

// Takes a device mapper name and determines the loop device number.
bool MapperNameToLoop(const std::string& name, int32_t* loop) {
  std::string type;
  std::string parameters;
  if (!MapperGetEntry(name, &type, &parameters)) {
    return false;
  }

  if (type != "verity") {
    LOG(ERROR) << "Encountered unexpected mapping \"" << type
               << "\" instead of \"verity\".";
    return false;
  }

  return MapperParametersToLoop(parameters, loop);
}

bool Unmount(const base::FilePath& mount_point) {
  return umount(mount_point.value().c_str()) == 0;
}

bool LazyUnmount(const base::FilePath& mount_point) {
  return umount2(mount_point.value().c_str(), MNT_DETACH | UMOUNT_NOFOLLOW) ==
         0;
}

// Returns (mount point, source path) pairs visible to this process. The order
// can be reversed to help with unmounting.
std::vector<std::pair<std::string, std::string>> GetAllMountPaths(
    bool reverse) {
  std::vector<std::pair<std::string, std::string>> mount_paths;
  base::ScopedFILE mountinfo(fopen("/proc/self/mounts", "re"));
  if (!mountinfo) {
    PLOG(ERROR) << "Failed to open \"/proc/self/mounts\".";
    return mount_paths;
  }

  // MNT_LINE_MAX from sys/mnttab.h is 1024, extra bytes are for null
  // termination of strings.
  static char buffer[1024 + 4];
  struct mntent mount_entry;
  while (getmntent_r(mountinfo.get(), &mount_entry, buffer, sizeof(buffer))) {
    mount_paths.emplace(reverse ? mount_paths.end() : mount_paths.begin(),
                        mount_entry.mnt_dir, mount_entry.mnt_fsname);
  }
  return mount_paths;
}

// Performs the a cleanup of a given mount point which should be tied to the
// given source path. This entails unmounting the mount point, removing the
// device mapper table entry, deleting the mount point folder, and freeing the
// loop device.
// Returns true on success.
bool CleanupImpl(const base::FilePath& mount_point,
                 const base::FilePath source_path) {
  const base::FilePath dev_mapper(kDeviceMapperPath);
  if (!IsAncestor(dev_mapper, source_path)) {
    LOG(ERROR) << source_path.value() << " is not device mapped!";
    return false;
  }

  // Lookup loop info.
  int32_t loop = -1;
  if (!MapperNameToLoop(source_path.BaseName().value(), &loop) || loop < 0) {
    LOG(ERROR) << "Unable to determine loop device for " << source_path.value();
    return false;
  }

  // Unmount the image.
  if (!Unmount(mount_point)) {
    PLOG(ERROR) << "Unmount failed; attempting a lazy unmount";

    if (!LazyUnmount(mount_point)) {
      PLOG(ERROR) << "Lazy unmount failed";
      return false;
    }
  }
  // Delete mount target folder
  brillo::DeletePathRecursively(mount_point);

  // Clear Verity device.
  if (!MapperWipeTable(source_path.value())) {
    PLOG(ERROR) << "Device mapper wipe table failed, "
                   "still continuing to remove the device mapper";
    // Do not return here, proceed to remove.
  }
  if (!MapperRemove(source_path.value())) {
    PLOG(ERROR) << "Device mapper remove failed; attempting a deferred removal";
    if (!MapperRemove(source_path.value(), /*deferred=*/true)) {
      PLOG(ERROR) << "Device mapper deferred remove failed.";
      return false;
    }
  }

  // Clear loop device.
  ClearLoopDevice(base::StringPrintf("/dev/loop%d", loop), loop);
  return true;
}

// Unmounts the given path, cleans up the device mapper entry, and frees the
// loop device for the specified mount point.
// Returns true on success.
bool VerityMounter::Cleanup(const base::FilePath& mount_point) {
  bool ret = true;
  for (const auto& mount_path : GetAllMountPaths(true)) {
    if (mount_point.value() == mount_path.first) {
      if (!CleanupImpl(mount_point, base::FilePath(mount_path.second))) {
        ret = false;
      }
    }
  }
  return ret;
}

// Performs a cleanup for all mount points under parent_dir.
// All successfully cleaned up mount points will be appended to "paths".
// Returns false if cleanup fails for any mount point.
bool VerityMounter::CleanupAll(bool dry_run,
                               const base::FilePath& parent_dir,
                               std::vector<base::FilePath>* paths) {
  bool ret = true;
  for (const auto& mount_path : GetAllMountPaths(true)) {
    base::FilePath fp_mount_path(mount_path.first);
    // It is not enough to check if fp_mount_path is a direct child because
    // some mount points, such as printer drivers, are mounted under a sub
    // folder.
    if (IsAncestor(parent_dir, fp_mount_path)) {
      if (dry_run) {
        if (paths) {
          paths->push_back(fp_mount_path);
        }
      } else if (CleanupImpl(fp_mount_path,
                             base::FilePath(mount_path.second))) {
        if (paths) {
          paths->push_back(fp_mount_path);
        }
      } else {
        LOG(ERROR) << "Failed to cleanup \"" << mount_path.first << "\"";
        ret = false;
      }
    }
  }
  return ret;
}

}  // namespace imageloader
