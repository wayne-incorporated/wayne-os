// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/arc_setup_util.h"

#include <fcntl.h>
#include <limits.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <mntent.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <openssl/sha.h>
#include <pwd.h>
#include <selinux/restorecon.h>
#include <selinux/selinux.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <list>
#include <optional>
#include <set>
#include <utility>

#include <base/environment.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <base/values.h>
#include <brillo/file_utils.h>
#include <brillo/files/safe_fd.h>
#include <crypto/sha2.h>
#include <libsegmentation/feature_management.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "arc/setup/xml/android_xml_util.h"

namespace arc {

namespace {

// Name of json field in camera test config specifying whether the front camera
// is enable.
constexpr char kEnableFrontCamera[] = "enable_front_camera";

// Name of json field in camera test config specifying whether the back camera
// is enable.
constexpr char kEnableBackCamera[] = "enable_back_camera";

// Gets the loop device path for a loop device number.
base::FilePath GetLoopDevicePath(int32_t device) {
  return base::FilePath(base::StringPrintf("/dev/loop%d", device));
}

// Immediately removes the loop device from the system.
void RemoveLoopDevice(int control_fd, int32_t device) {
  if (ioctl(control_fd, LOOP_CTL_REMOVE, device) < 0)
    PLOG(ERROR) << "Failed to free /dev/loop" << device;
}

// Disassociates the loop device from any file descriptor.
void DisassociateLoopDevice(int loop_fd,
                            const std::string& source,
                            const base::FilePath& device_path) {
  if (ioctl(loop_fd, LOOP_CLR_FD) < 0) {
    PLOG(ERROR) << "Failed to remove " << source << " from "
                << device_path.value();
  }
}

// A callback function for SELinux restorecon.
PRINTF_FORMAT(2, 3)
int RestoreConLogCallback(int type, const char* fmt, ...) {
  va_list ap;

  std::string message = "restorecon: ";
  va_start(ap, fmt);
  message += base::StringPrintV(fmt, ap);
  va_end(ap);

  // This already has a line feed at the end, so trim it off to avoid
  // empty lines in the log.
  base::TrimString(message, "\r\n", &message);

  if (type == SELINUX_INFO)
    LOG(INFO) << message;
  else
    LOG(ERROR) << message;

  return 0;
}

bool RestoreconInternal(const std::vector<base::FilePath>& paths,
                        bool is_recursive) {
  union selinux_callback cb;
  cb.func_log = RestoreConLogCallback;
  selinux_set_callback(SELINUX_CB_LOG, cb);

  const unsigned int base_flags =
      (is_recursive ? SELINUX_RESTORECON_RECURSE : 0) |
      SELINUX_RESTORECON_REALPATH;

  bool success = true;
  for (const auto& path : paths) {
    unsigned int restorecon_flags = base_flags;
    struct statfs fsinfo;
    if (statfs(path.value().c_str(), &fsinfo) != 0) {
      PLOG(WARNING) << "Failed to statfs for " << path.value();
      // Continue anyway because restorecon should work even if it can't
      // update digests.
    } else if (fsinfo.f_type == TRACEFS_MAGIC ||
               fsinfo.f_type == DEBUGFS_MAGIC) {
      // tracefs and debugfs don't support xattrs, so restorecon can't store
      // digests.
      restorecon_flags |= SELINUX_RESTORECON_SKIP_DIGEST;
    }

    if (selinux_restorecon(path.value().c_str(), restorecon_flags) != 0) {
      LOG(ERROR) << "Error in restorecon of " << path.value();
      success = false;
    }
  }
  return success;
}

// A callback function for GetPropertyFromFile.
bool FindProperty(const std::string& line_prefix_to_find,
                  std::string* out_prop,
                  const std::string& line) {
  if (base::StartsWith(line, line_prefix_to_find,
                       base::CompareCase::SENSITIVE)) {
    *out_prop = line.substr(line_prefix_to_find.length());
    return true;
  }
  return false;
}

// Sets the permission of the given |fd|.
bool SetPermissions(base::PlatformFile fd, mode_t mode) {
  struct stat st;
  if (fstat(fd, &st) < 0) {
    PLOG(ERROR) << "Failed to stat";
    return false;
  }
  if ((st.st_mode & 07000) && ((st.st_mode & 07000) != (mode & 07000))) {
    LOG(INFO) << "Changing permissions from " << (st.st_mode & ~S_IFMT)
              << " to " << (mode & ~S_IFMT);
  }

  if (fchmod(fd, mode) != 0) {
    PLOG(ERROR) << "Failed to fchmod " << mode;
    return false;
  }
  return true;
}

class ArcMounterImpl : public ArcMounter {
 public:
  ArcMounterImpl() = default;
  ~ArcMounterImpl() override = default;

  bool Mount(const std::string& source,
             const base::FilePath& target,
             const char* filesystem_type,
             unsigned long mount_flags,  // NOLINT(runtime/int)
             const char* data) override {
    // The mount call would fail when the |target| is a symlink
    // as we are not calling Realpath() on |target| to prevent
    // mounting to unintended locations.
    if (mount(source.c_str(), target.value().c_str(), filesystem_type,
              mount_flags, data) != 0) {
      PLOG(ERROR) << "Failed to mount " << source << " to " << target.value();
      return false;
    }
    return true;
  }

  bool Remount(const base::FilePath& target_directory,
               unsigned long mount_flags,  // NOLINT(runtime/int)
               const char* data) override {
    return Mount(std::string(),  // ignored
                 target_directory,
                 nullptr,  // ignored
                 mount_flags | MS_REMOUNT, data);
  }

  bool LoopMount(const std::string& source,
                 const base::FilePath& target,
                 unsigned long mount_flags) override {  // NOLINT(runtime/int)
    constexpr size_t kRetryMax = 10;
    for (size_t i = 0; i < kRetryMax; ++i) {
      bool retry = false;
      if (LoopMountInternal(source, target, mount_flags, &retry))
        return true;
      if (!retry)
        break;
      LOG(INFO) << "LoopMountInternal failed with EBUSY. Retrying...";
    }
    return false;
  }

  bool BindMount(const base::FilePath& old_path,
                 const base::FilePath& new_path) override {
    return Mount(old_path.value(), new_path, nullptr, MS_BIND, nullptr);
  }

  bool SharedMount(const base::FilePath& path) override {
    return Mount("none", path, nullptr, MS_SHARED, nullptr);
  }

  bool Umount(const base::FilePath& path) override {
    if (umount(Realpath(path).value().c_str()) != 0) {
      PLOG(ERROR) << "Failed to umount " << path.value();
      return false;
    }
    return true;
  }

  bool UmountIfExists(const base::FilePath& path) override {
    if (umount(Realpath(path).value().c_str()) != 0) {
      // We tolerate nothing mounted on the path (EINVAL) and we tolerate the
      // path not existing (ENOENT)
      if (errno != EINVAL && errno != ENOENT) {
        PLOG(ERROR) << "Mount exists but failed to umount " << path.value();
        return false;
      }
    }
    return true;
  }

  bool LoopUmount(const base::FilePath& path) override {
    if (!LoopUmountInternal(path, /*ignore_missing=*/false)) {
      LOG(ERROR) << "Failed to unmount loop " << path.value();
      return false;
    }
    return true;
  }

  bool LoopUmountIfExists(const base::FilePath& path) override {
    if (!LoopUmountInternal(path, /*ignore_missing=*/true)) {
      LOG(ERROR) << "Mount exists but failed to unmount loop " << path.value();
      return false;
    }
    return true;
  }

 private:
  bool LoopUmountInternal(const base::FilePath& path,
                          const bool ignore_missing) {
    struct stat st;
    if (stat(path.value().c_str(), &st) < 0) {
      if (!ignore_missing || errno != ENOENT) {
        PLOG(ERROR) << "Failed to stat " << path.value();
        return false;
      }
      return true;
    }

    if (major(st.st_dev) != LOOP_MAJOR) {
      if (!ignore_missing) {
        LOG(ERROR) << path.value()
                   << " is not loop-mounted. st_dev=" << st.st_dev;
        return false;
      }
      return true;
    }

    bool autoclear = false;
    const base::FilePath device_path = GetLoopDevicePath(minor(st.st_dev));
    {
      base::ScopedFD scoped_loop_fd(
          open(device_path.value().c_str(), O_RDONLY | O_CLOEXEC));
      if (!scoped_loop_fd.is_valid()) {
        PLOG(ERROR) << "Failed to open " << device_path.value();
        return false;
      }

      struct loop_info64 loop_info;
      if (ioctl(scoped_loop_fd.get(), LOOP_GET_STATUS64, &loop_info) < 0) {
        PLOG(ERROR) << "Failed to get info " << device_path.value();
        return false;
      }
      autoclear = loop_info.lo_flags & LO_FLAGS_AUTOCLEAR;
    }

    if (!Umount(path))
      return false;

    if (!autoclear) {
      base::ScopedFD scoped_loop_fd(
          open(device_path.value().c_str(), O_RDWR | O_CLOEXEC));
      if (!scoped_loop_fd.is_valid()) {
        PLOG(ERROR) << "Failed to open " << device_path.value();
        return false;
      }

      if (ioctl(scoped_loop_fd.get(), LOOP_CLR_FD) < 0) {
        PLOG(ERROR) << "Failed to free " << device_path.value();
        return false;
      }
    }

    return true;
  }

  bool LoopMountInternal(const std::string& source,
                         const base::FilePath& target,
                         unsigned long mount_flags,  // NOLINT(runtime/int)
                         bool* out_retry) {
    constexpr char kLoopControl[] = "/dev/loop-control";

    *out_retry = false;
    base::ScopedFD scoped_control_fd(open(kLoopControl, O_RDONLY));
    if (!scoped_control_fd.is_valid()) {
      PLOG(ERROR) << "Failed to open " << kLoopControl;
      return false;
    }

    const int32_t device_num =
        ioctl(scoped_control_fd.get(), LOOP_CTL_GET_FREE);
    if (device_num < 0) {
      PLOG(ERROR) << "Failed to allocate a loop device";
      return false;
    }

    // Cleanup in case mount fails. This frees |device_num| altogether.
    base::ScopedClosureRunner loop_device_cleanup(
        base::BindOnce(&RemoveLoopDevice, scoped_control_fd.get(), device_num));

    const base::FilePath device_path = GetLoopDevicePath(device_num);
    base::ScopedFD scoped_loop_fd(open(device_path.value().c_str(), O_RDWR));
    if (!scoped_loop_fd.is_valid()) {
      PLOG(ERROR) << "Failed to open " << device_path.value();
      return false;
    }

    const bool is_readonly_mount = mount_flags & MS_RDONLY;
    base::ScopedFD scoped_source_fd(
        open(source.c_str(), is_readonly_mount ? O_RDONLY : O_RDWR));
    if (!scoped_source_fd.is_valid()) {
      // If the open failed because we tried to open a read only file as RW
      // we fallback to opening it with O_RDONLY
      if (!is_readonly_mount && (errno == EROFS || errno == EACCES)) {
        LOG(WARNING) << source << " is write-protected, using read-only";
        scoped_source_fd.reset(open(source.c_str(), O_RDONLY));
      }
      if (!scoped_source_fd.is_valid()) {
        PLOG(ERROR) << "Failed to open " << source;
        return false;
      }
    }

    struct stat source_stat;
    if (fstat(scoped_source_fd.get(), &source_stat) != 0) {
      PLOG(ERROR) << "Failed to stat " << source;
      return false;
    }

    if (ioctl(scoped_loop_fd.get(), LOOP_SET_FD, scoped_source_fd.get()) < 0) {
      PLOG(ERROR) << "Failed to associate " << source << " with "
                  << device_path.value();
      // Set |out_retry| to true if LOOP_SET_FD returns EBUSY. The errno
      // indicates that another process has grabbed the same |device_num|
      // before arc-setup does that.
      *out_retry = (errno == EBUSY);
      return false;
    }

    // Set the autoclear flag on the loop device, which will release it when
    // there are no more references to it.
    struct loop_info64 loop_info = {};
    if (ioctl(scoped_loop_fd.get(), LOOP_GET_STATUS64, &loop_info) < 0) {
      PLOG(ERROR) << "Failed to get loop status for " << device_path.value();
      return false;
    }
    loop_info.lo_flags |= LO_FLAGS_AUTOCLEAR;
    if (ioctl(scoped_loop_fd.get(), LOOP_SET_STATUS64, &loop_info) < 0) {
      PLOG(ERROR) << "Failed to set autoclear loop status for "
                  << device_path.value();
      return false;
    }
    // Substitute the removal of the device number by disassociating |source|
    // from the loop device, such that the autoclear flag on |device_num| can
    // automatically remove the loop device.
    loop_device_cleanup.ReplaceClosure(base::BindOnce(
        &DisassociateLoopDevice, scoped_loop_fd.get(), source, device_path));

    if (Mount(device_path.value(), target, "squashfs", mount_flags, nullptr)) {
      // Expected case, all good.
    } else if (Mount(device_path.value(), target, "ext4", mount_flags,
                     nullptr)) {
      // For development ext4 is allowed.
      LOG(INFO) << "Mounted " << source << " as ext4";
    } else {
      PLOG(ERROR) << "Failed to mount " << source;
      return false;
    }

    loop_device_cleanup.ReplaceClosure(base::DoNothing());

    // Verify that the loop device did not get redirected.
    if (ioctl(scoped_loop_fd.get(), LOOP_GET_STATUS64, &loop_info) == 0) {
      if (loop_info.lo_device == source_stat.st_dev &&
          loop_info.lo_inode == source_stat.st_ino) {
        // We loop mounted the desired backing file.
        return true;
      }
    } else {
      PLOG(ERROR) << "Failed to get loop status for " << device_path.value();
    }

    // We mounted the wrong things, attempt to unmount and fail.
    LOG(ERROR) << "Failed to confirm correct contents mounted on "
               << target.value();
    LoopUmount(target);
    return false;
  }
};

}  // namespace

ScopedMount::ScopedMount(const base::FilePath& path,
                         ArcMounter* mounter,
                         bool is_loop)
    : mounter_(mounter), path_(path), is_loop_(is_loop) {}

ScopedMount::~ScopedMount() {
  if (is_loop_) {
    PLOG_IF(INFO, !mounter_->LoopUmount(path_))
        << "Ignoring failure to umount " << path_.value();
  } else {
    PLOG_IF(INFO, !mounter_->Umount(path_))
        << "Ignoring failure to umount " << path_.value();
  }
}

// static
std::unique_ptr<ScopedMount> ScopedMount::CreateScopedMount(
    ArcMounter* mounter,
    const std::string& source,
    const base::FilePath& target,
    const char* filesystem_type,
    unsigned long mount_flags,  // NOLINT(runtime/int)
    const char* data) {
  if (!mounter->Mount(source, target, filesystem_type, mount_flags, data))
    return nullptr;
  return std::make_unique<ScopedMount>(target, mounter, false /*is_loop*/);
}

// static
std::unique_ptr<ScopedMount> ScopedMount::CreateScopedLoopMount(
    ArcMounter* mounter,
    const std::string& source,
    const base::FilePath& target,
    unsigned long flags) {  // NOLINT(runtime/int)
  if (!mounter->LoopMount(source, target, flags))
    return nullptr;
  return std::make_unique<ScopedMount>(target, mounter, true /*is_loop*/);
}

// static
std::unique_ptr<ScopedMount> ScopedMount::CreateScopedBindMount(
    ArcMounter* mounter,
    const base::FilePath& old_path,
    const base::FilePath& new_path) {
  if (!mounter->BindMount(old_path, new_path))
    return nullptr;
  return std::make_unique<ScopedMount>(new_path, mounter, false /*is_loop*/);
}

base::FilePath Realpath(const base::FilePath& path) {
  // We cannot use base::NormalizeFilePath because the function fails
  // if |path| points to a directory (for Windows compatibility.)
  char buf[PATH_MAX] = {};
  if (!realpath(path.value().c_str(), buf)) {
    if (errno != ENOENT)
      PLOG(WARNING) << "Failed to resolve " << path.value();
    return path;
  }
  return base::FilePath(buf);
}

bool Chown(uid_t uid, gid_t gid, const base::FilePath& path) {
  base::ScopedFD fd(brillo::OpenSafely(path, O_RDONLY, 0));
  if (!fd.is_valid())
    return false;
  return fchown(fd.get(), uid, gid) == 0;
}

bool Chcon(const std::string& context, const base::FilePath& path) {
  if (lsetfilecon(path.value().c_str(), context.c_str()) < 0) {
    PLOG(ERROR) << "Could not label " << path.value() << " with " << context;
    return false;
  }

  return true;
}

bool InstallDirectory(mode_t mode,
                      uid_t uid,
                      gid_t gid,
                      const base::FilePath& path) {
  if (!brillo::MkdirRecursively(path, 0755).is_valid())
    return false;

  base::ScopedFD fd(brillo::OpenSafely(path, O_DIRECTORY | O_RDONLY, 0));
  if (!fd.is_valid())
    return false;

  // Unlike 'mkdir -m mode -p' which does not change modes when the path already
  // exists, 'install -d' always sets modes and owner regardless of whether the
  // path exists or not.
  const bool chown_result = (fchown(fd.get(), uid, gid) == 0);
  const bool chmod_result = SetPermissions(fd.get(), mode);
  return chown_result && chmod_result;
}

bool WriteToFile(const base::FilePath& file_path,
                 mode_t mode,
                 const std::string& content) {
  // Use the same mode as base/files/file_posix.cc's.
  constexpr mode_t kMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

  base::ScopedFD fd(
      brillo::OpenSafely(file_path, O_WRONLY | O_CREAT | O_TRUNC, kMode));
  if (!fd.is_valid())
    return false;
  if (!SetPermissions(fd.get(), mode))
    return false;
  if (content.empty())
    return true;

  // Note: WriteFileDescriptor() makes a best effort to write all data.
  // While-loop for handling partial-write is not needed here.
  return base::WriteFileDescriptor(fd.get(), content);
}

bool GetPropertyFromFile(const base::FilePath& prop_file_path,
                         const std::string& prop_name,
                         std::string* out_prop) {
  const std::string line_prefix_to_find = prop_name + '=';
  if (FindLine(
          prop_file_path,
          base::BindRepeating(&FindProperty, line_prefix_to_find, out_prop))) {
    return true;  // found the line.
  }
  LOG(WARNING) << prop_name << " is not in " << prop_file_path.value();
  return false;
}

bool GetPropertiesFromFile(const base::FilePath& prop_file_path,
                           std::map<std::string, std::string>* out_properties) {
  if (FindLine(prop_file_path,
               base::BindRepeating(&FindAllProperties, out_properties))) {
    // Failed to parse the file.
    out_properties->clear();
    return false;
  }

  return true;
}

bool CreateOrTruncate(const base::FilePath& file_path, mode_t mode) {
  return WriteToFile(file_path, mode, std::string());
}

bool WaitForPaths(std::initializer_list<base::FilePath> paths,
                  const base::TimeDelta& timeout,
                  base::TimeDelta* out_elapsed) {
  const base::TimeDelta sleep_interval = timeout / 20;
  std::list<base::FilePath> left(paths);

  base::ElapsedTimer timer;
  do {
    left.erase(std::remove_if(left.begin(), left.end(), base::PathExists),
               left.end());
    if (left.empty())
      break;  // all paths are found.
    base::PlatformThread::Sleep(sleep_interval);
  } while (timeout >= timer.Elapsed());

  if (out_elapsed)
    *out_elapsed = timer.Elapsed();

  for (const auto& path : left)
    LOG(ERROR) << path.value() << " not found";
  return left.empty();
}

bool LaunchAndWait(const std::vector<std::string>& argv) {
  base::Process process(base::LaunchProcess(argv, base::LaunchOptions()));
  if (!process.IsValid())
    return false;
  int exit_code = -1;
  return process.WaitForExit(&exit_code) && (exit_code == 0);
}

bool RestoreconRecursively(const std::vector<base::FilePath>& directories) {
  return RestoreconInternal(directories, true /* is_recursive */);
}

bool Restorecon(const std::vector<base::FilePath>& paths) {
  return RestoreconInternal(paths, false /* is_recursive */);
}

std::string GenerateFakeSerialNumber(const std::string& chromeos_user,
                                     const std::string& salt) {
  constexpr size_t kMaxHardwareIdLen = 20;
  const std::string hash(crypto::SHA256HashString(chromeos_user + salt));
  return base::HexEncode(hash.data(), hash.length())
      .substr(0, kMaxHardwareIdLen);
}

uint64_t GetArtCompilationOffsetSeed(const std::string& image_build_id,
                                     const std::string& salt) {
  uint64_t result = 0;
  std::string input;
  do {
    input += image_build_id + salt;
    crypto::SHA256HashString(input, &result, sizeof(result));
  } while (!result);
  return result;
}

// Note: This function has to be in sync with Android's arc-boot-type-detector.
bool MoveDirIntoDataOldDir(const base::FilePath& dir,
                           const base::FilePath& android_data_old_dir) {
  if (!base::DirectoryExists(dir)) {
    // Nothing to do.
    return true;
  }

  brillo::SafeFD root = brillo::SafeFD::Root().first;

  brillo::SafeFD source_parent = root.OpenExistingDir(dir.DirName()).first;
  if (!source_parent.is_valid()) {
    LOG(ERROR) << "Cannot open " << dir.DirName().value();
    return false;
  }

  brillo::SafeFD dest_dir_parent =
      root.OpenExistingDir(android_data_old_dir.DirName()).first;
  if (!dest_dir_parent.is_valid()) {
    LOG(ERROR) << "Cannot open " << android_data_old_dir.DirName().value();
    return false;
  }

  brillo::SafeFD dest_dir;
  brillo::SafeFD::Error err;
  std::tie(dest_dir, err) = dest_dir_parent.MakeDir(
      android_data_old_dir.BaseName(), 0700 /*permissions*/);
  if (err == brillo::SafeFD::Error::kWrongType) {
    LOG(INFO) << "Deleting something that is not a directory at "
              << android_data_old_dir.value();
    if (dest_dir_parent.Unlink(android_data_old_dir.BaseName().value()) !=
        brillo::SafeFD::Error::kNoError) {
      LOG(ERROR) << "Failed to delete " << android_data_old_dir.value();
      return false;
    }
    std::tie(dest_dir, err) = dest_dir_parent.MakeDir(
        android_data_old_dir.BaseName(), 0700 /*permissions*/);
  }
  if (!dest_dir.is_valid()) {
    LOG(ERROR) << "Cannot open or create " << android_data_old_dir.value();
    return false;
  }

  // Create a unique directory under android_data_old_dir.
  // TODO(crbug.com/1076654): Add temporary directory create and rename
  // APIs to SafeFD and replace the inline implementation here.
  int seed =
      std::chrono::high_resolution_clock::now().time_since_epoch().count() &
      0xFFFFFF;
  const std::string dest_base = dir.BaseName().value();
  bool moved = false;
  // How many different unique names shall we try? FreeBSD insists on
  // exhaustively trying all 56**5 (2.4e10) combinations to find that last
  // possible free filename. In contrast, glibc "only" tries 300000 times.
  // Conservativelty, we do not expect more than something on the order of
  // 100 names to be taken, but failing to opt-out is pretty bad for the
  // user so we use a safety factor of 1000 to be very sure. At 100000
  // syscalls, will still only block for a second before erroring out.
  constexpr int kMaxTries = 100000;
  for (int i = 0; i < kMaxTries; i++) {
    std::string new_name =
        base::StringPrintf("%s_%06x", dest_base.c_str(), seed);
    if (renameat(source_parent.get(), dir.BaseName().value().c_str(),
                 dest_dir.get(), new_name.c_str()) == 0) {
      moved = true;
      break;
    }
    if (errno != EEXIST && errno != ENOTEMPTY && errno != ENOTDIR) {
      PLOG(ERROR) << "Cannot move" << dir.value() << " to "
                  << android_data_old_dir.Append(new_name).value();
      return false;
    }
    seed = (seed + 1) & 0xFFFFFF;
  }
  if (!moved) {
    LOG(ERROR) << "Giving up, cannot move " << dir.value()
               << " to a directory of the form "
               << android_data_old_dir.Append(dest_base + "_XXXXXX").value();
    return false;
  }

  return true;
}

bool DeleteFilesInDir(const base::FilePath& directory) {
  base::FileEnumerator files(
      directory, true /* recursive */,
      base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS);
  bool retval = true;
  for (base::FilePath file = files.Next(); !file.empty(); file = files.Next()) {
    if (!DeleteFile(file)) {
      LOG(ERROR) << "Failed to delete file " << file.value();
      retval = false;
    }
  }
  return retval;
}

std::unique_ptr<ArcMounter> GetDefaultMounter() {
  return std::make_unique<ArcMounterImpl>();
}

std::string GetChromeOsChannelFromFile(
    const base::FilePath& lsb_release_file_path) {
  constexpr char kChromeOsReleaseTrackProp[] = "CHROMEOS_RELEASE_TRACK";
  const std::set<std::string> kChannels = {
      "beta-channel",    "canary-channel", "dev-channel",
      "dogfood-channel", "stable-channel", "testimage-channel"};
  const std::string kUnknown = "unknown";
  const std::string kChannelSuffix = "-channel";

  // Read the channel property from /etc/lsb-release
  std::string chromeos_channel;
  if (!GetPropertyFromFile(lsb_release_file_path, kChromeOsReleaseTrackProp,
                           &chromeos_channel)) {
    LOG(ERROR) << "Failed to get the ChromeOS channel from "
               << lsb_release_file_path.value();
    return kUnknown;
  }

  if (kChannels.find(chromeos_channel) == kChannels.end()) {
    LOG(WARNING) << "Unknown ChromeOS channel: \"" << chromeos_channel << "\"";
    return kUnknown;
  }
  return chromeos_channel.erase(chromeos_channel.find(kChannelSuffix),
                                kChannelSuffix.size());
}

bool GetOciContainerState(const base::FilePath& path,
                          pid_t* out_container_pid,
                          base::FilePath* out_rootfs) {
  // Read the OCI container state from |path|. Its format is documented in
  // https://github.com/opencontainers/runtime-spec/blob/HEAD/runtime.md#state
  std::string json_str;
  if (!base::ReadFileToString(path, &json_str)) {
    PLOG(ERROR) << "Failed to read json string from " << path.value();
    return false;
  }
  auto container_state = base::JSONReader::ReadAndReturnValueWithError(
      json_str, base::JSON_PARSE_RFC);
  if (!container_state.has_value()) {
    LOG(ERROR) << "Failed to parse json: " << container_state.error().message;
    return false;
  }
  if (!container_state->is_dict()) {
    LOG(ERROR) << "Failed to read container state as dictionary";
    return false;
  }

  // Get the container PID and the rootfs path.
  std::optional<int> pid = container_state->GetDict().FindInt("pid");
  if (!pid) {
    LOG(ERROR) << "Failed to get PID from container state";
    return false;
  }
  *out_container_pid = pid.value();

  const base::Value::Dict* annotations =
      container_state->GetDict().FindDict("annotations");
  if (!annotations) {
    LOG(ERROR) << "Failed to get annotations from container state";
    return false;
  }
  const std::string* container_root_path =
      annotations->FindString("org.chromium.run_oci.container_root");
  if (!container_root_path) {
    LOG(ERROR)
        << "Failed to get org.chromium.run_oci.container_root annotation";
    return false;
  }
  base::FilePath container_root(*container_root_path);
  if (!base::ReadSymbolicLink(
          container_root.Append("mountpoints/container-root"), out_rootfs)) {
    PLOG(ERROR) << "Failed to read container root symlink";
    return false;
  }

  return true;
}

bool IsProcessAlive(pid_t pid) {
  return kill(pid, 0 /* sig */) == 0;
}

bool GetSha1HashOfFiles(const std::vector<base::FilePath>& files,
                        std::string* out_hash) {
  SHA_CTX sha_context;
  SHA1_Init(&sha_context);
  for (const auto& file : files) {
    std::string file_str;
    if (!base::ReadFileToString(file, &file_str))
      return false;
    SHA1_Update(&sha_context, file_str.data(), file_str.size());
  }
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1_Final(hash, &sha_context);
  out_hash->assign(reinterpret_cast<const char*>(hash), sizeof(hash));
  return true;
}

bool SetXattr(const base::FilePath& path,
              const char* name,
              const std::string& value) {
  base::ScopedFD fd(brillo::OpenSafely(path, O_RDONLY, 0));
  if (!fd.is_valid())
    return false;

  if (fsetxattr(fd.get(), name, value.data(), value.size(), 0 /* flags */) !=
      0) {
    PLOG(ERROR) << "Failed to change xattr " << name << " of " << path.value();
    return false;
  }
  return true;
}

bool ShouldDeleteAndroidData(AndroidSdkVersion system_sdk_version,
                             AndroidSdkVersion data_sdk_version) {
  // Initial launch with clean data.
  if (data_sdk_version == AndroidSdkVersion::UNKNOWN)
    return false;
  // Downgraded. (b/80113276)
  if (data_sdk_version > system_sdk_version) {
    LOG(INFO) << "Clearing /data dir because ARC was downgraded from "
              << static_cast<int>(data_sdk_version) << " to "
              << static_cast<int>(system_sdk_version) << ".";
    return true;
  }
  // Skip-upgraded from M to post-P. (b/77591360)
  if (data_sdk_version == AndroidSdkVersion::ANDROID_M &&
      system_sdk_version >= AndroidSdkVersion::ANDROID_P) {
    LOG(INFO) << "Clearing /data dir because ARC was skip-upgraded from M("
              << static_cast<int>(data_sdk_version) << ") to post-P("
              << static_cast<int>(system_sdk_version) << ").";
    return true;
  }
  // Skip-upgraded from N to post-R. (b/167635130)
  if (data_sdk_version == AndroidSdkVersion::ANDROID_N_MR1 &&
      system_sdk_version >= AndroidSdkVersion::ANDROID_R) {
    LOG(INFO) << "Clearing /data dir because ARC was skip-upgraded from N("
              << static_cast<int>(data_sdk_version) << ") to post-R("
              << static_cast<int>(system_sdk_version) << ").";
    return true;
  }
  // Skip-upgraded from P to post-S. (b/187453032)
  if (data_sdk_version == AndroidSdkVersion::ANDROID_P &&
      system_sdk_version >= AndroidSdkVersion::ANDROID_S) {
    LOG(INFO) << "Clearing /data dir because ARC was skip-upgraded from P("
              << static_cast<int>(data_sdk_version) << ") to post-S("
              << static_cast<int>(system_sdk_version) << ").";
    return true;
  }
  // Upgraded to a development version. (b/195035697)
  if (system_sdk_version == AndroidSdkVersion::ANDROID_DEVELOPMENT &&
      data_sdk_version < system_sdk_version) {
    LOG(INFO) << "Clearing /data dir because ARC was upgraded to a development "
                 "version from "
              << static_cast<int>(data_sdk_version) << ".";
    return true;
  }
  return false;
}

bool FindAllProperties(std::map<std::string, std::string>* out_properties,
                       const std::string& line) {
  // Ignore empty lines and comments.
  if (line.empty() || line.at(0) == '#') {
    // Continue reading next lines.
    return false;
  }

  std::string::size_type separator = line.find('=');
  if (separator == std::string::npos) {
    LOG(WARNING) << "Failed to parse: " << line;
    // Stop reading next lines on error.
    return true;
  }

  (*out_properties)[line.substr(0, separator)] = line.substr(separator + 1);
  // Continue reading next lines.
  return false;
}

bool GetUserId(const std::string& user, uid_t* user_id, gid_t* group_id) {
  constexpr int kDefaultPwnameLength = 1024;
  // Load the passwd entry
  long user_name_length = sysconf(_SC_GETPW_R_SIZE_MAX);  // NOLINT long
  if (user_name_length == -1)
    user_name_length = kDefaultPwnameLength;
  passwd user_info;
  passwd* user_infop = nullptr;
  std::vector<char> user_name_buf(user_name_length);
  if (getpwnam_r(user.c_str(), &user_info, user_name_buf.data(),
                 user_name_length, &user_infop)) {
    return false;
  }
  if (!user_infop)
    return false;  // no such user
  *user_id = user_info.pw_uid;
  *group_id = user_info.pw_gid;
  return true;
}

bool SafeCopyFile(const base::FilePath& src_path,
                  brillo::SafeFD src_parent,
                  const base::FilePath& dest_path,
                  brillo::SafeFD dest_parent,
                  mode_t permissions,
                  uid_t uid,
                  gid_t gid) {
  struct stat st;
  ssize_t len, ret;

  if (!src_parent.is_valid()) {
    LOG(ERROR) << "Invalid src_parent fd";
    return false;
  }

  if (!dest_parent.is_valid()) {
    LOG(ERROR) << "Invalid dest_parent fd";
    return false;
  }

  brillo::SafeFD root = brillo::SafeFD::Root().first;
  brillo::SafeFD::SafeFDResult result(
      src_parent.OpenExistingFile(src_path, O_RDONLY | O_CLOEXEC));
  if (brillo::SafeFD::IsError(result.second)) {
    LOG(ERROR) << "Failed to open src path " << src_path;
    return false;
  }
  brillo::SafeFD src_fd(std::move(result.first));

  brillo::SafeFD dest_fd(
      dest_parent.MakeFile(dest_path, permissions, uid, gid).first);
  if (!dest_fd.is_valid()) {
    LOG(ERROR) << "Failed to open dest path " << dest_path;
    return false;
  }

  fstat(src_fd.get(), &st);
  len = st.st_size;

  do {
    ret = sendfile(dest_fd.get(), src_fd.get(), nullptr, len);
    if (ret == -1) {
      PLOG(ERROR) << "Fail to copy file " << src_path << " to " << dest_path
                  << errno;
      return false;
    }
    len -= ret;
  } while (len > 0 && ret > 0);

  return true;
}

bool IsErofsImage(const base::FilePath& image_path) {
  // Check the magic number of erofs placed at the 1024 byte.
  // https://elixir.bootlin.com/linux/latest/source/fs/erofs/erofs_fs.h#L53
  const off_t kErofsMagicOffset = 1024;
  const uint32_t kErofsMagicNumber = 0xe0f5e1e2;
  base::ScopedFD fd(open(image_path.value().c_str(), O_RDONLY));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << image_path.value();
    return false;
  }
  off_t cur_pos = lseek(fd.get(), kErofsMagicOffset, SEEK_SET);
  if (cur_pos != kErofsMagicOffset) {
    PLOG(ERROR) << "Failed to seek " << image_path.value() << " lseek returned "
                << cur_pos;
    return false;
  }
  uint32_t data;
  if (!base::ReadFromFD(fd.get(), reinterpret_cast<char*>(&data),
                        sizeof(data))) {
    PLOG(ERROR) << "Can't read the magic number of " << image_path.value();
    return false;
  }
  return data == kErofsMagicNumber;
}

bool GenerateFirstStageFstab(const base::FilePath& combined_property_file_name,
                             const base::FilePath& fstab_path,
                             const base::FilePath& vendor_image_path,
                             const std::string& cache_partition) {
  // TODO(b/269555375): Exit with error if an IO error occurs inside
  //                    IsErofsImage.
  const std::string vendor_fs_type =
      IsErofsImage(vendor_image_path) ? "erofs" : "squashfs";

  // The file is exposed to the guest by crosvm via /sys/firmware/devicetree,
  // which in turn allows the guest's init process to mount /vendor very early,
  // in its first stage (device) initialization step. crosvm also special-cases
  // #dt-vendor line and expose |combined_property_file_name| via the device
  // tree file system too. This also allow the init process to load the expanded
  // properties very early even before all file systems are mounted.
  //
  // The device name for /vendor has to match what arc_vm_client_adapter.cc
  // configures.
  std::string firstStageFstabTemplate = base::StringPrintf(
      "/dev/block/vdb /vendor %s ro,noatime,nodev "
      "wait,check,formattable,reservedsize=128M\n",
      vendor_fs_type.c_str());

  // A dedicated cache partition needs to be mounted in the first stage init
  // process. This is required for the adb remount / sync feature to work on
  // Android R+, optionally used in the dev process (b/182953041). The dedicated
  // partition is used as the mount point for upper layer of overlayfs backing.
  // Since the demo app partition is optionally mounted before the cache
  // partition, there is a need to determine the device number dynamically.
  // The device number is determined beforehand by checking the existence of the
  // demo partition, and are stored to |cache_partition|. Note that this check
  // would not be required once we switch to use virtiofs as the cache
  // partition.
  if (!cache_partition.empty()) {
    firstStageFstabTemplate += base::StringPrintf(
        "/dev/block/%s /cache ext4 rw,noatime,nodev "
        "wait,check,formattable,reservedsize=128M\n",
        cache_partition.c_str());
  }

  firstStageFstabTemplate +=
      base::StringPrintf("#dt-vendor build.prop %s default default\n",
                         combined_property_file_name.value().c_str());

  return WriteToFile(fstab_path, 0644, firstStageFstabTemplate);
}

std::optional<std::string> FilterMediaProfile(
    const base::FilePath& media_profile_xml,
    const base::FilePath& camera_test_config) {
  std::string content;
  if (!base::ReadFileToString(media_profile_xml, &content)) {
    LOG(ERROR) << "Failed to read media profile from "
               << media_profile_xml.value();
    return std::nullopt;
  }

  if (!base::PathExists(camera_test_config)) {
    // Don't filter if we cannot find the test config.
    return content;
  }
  std::string json_str;
  if (!base::ReadFileToString(camera_test_config, &json_str)) {
    LOG(ERROR) << "Failed to read camera test config from "
               << camera_test_config.value();
    return content;
  }
  auto config = base::JSONReader::ReadAndReturnValueWithError(json_str);
  if (!config.has_value() || !config->is_dict()) {
    LOG(ERROR) << "Failed to parse camera test config content: " << json_str;
    return content;
  }
  const auto& config_dict = config->GetDict();

  bool enable_front_camera =
      config_dict.FindBool(kEnableFrontCamera).value_or(true);
  bool enable_back_camera =
      config_dict.FindBool(kEnableBackCamera).value_or(true);
  if (enable_front_camera && enable_back_camera) {
    return content;
  }
  if (!enable_front_camera && !enable_back_camera) {
    // All built-in cameras are filtered out. No need of media profile xml.
    return "";
  }

  LIBXML_TEST_VERSION
  xmlDocPtr doc;

  auto result = [&doc, &content, enable_front_camera,
                 enable_back_camera]() -> std::optional<std::string> {
    doc = xmlReadMemory(content.c_str(), content.size(), nullptr, nullptr, 0);
    if (doc == nullptr) {
      LOG(ERROR) << "Failed to parse media profile content:\n" << content;
      return std::nullopt;
    }
    // For keeping indent.
    xmlKeepBlanksDefault(0);

    xmlNodePtr settings = xmlDocGetRootElement(doc);
    if (settings == nullptr) {
      LOG(ERROR) << "No root element node found in media profile content:\n"
                 << content;
      return std::nullopt;
    }
    if (std::string(reinterpret_cast<const char*>(settings->name)) !=
        "MediaSettings") {
      LOG(ERROR) << "Failed to find media settings in media profile content:\n"
                 << content;
      return std::nullopt;
    }

    std::vector<xmlNodePtr> camera_profiles;
    for (xmlNodePtr cur = xmlFirstElementChild(settings); cur != nullptr;
         cur = xmlNextElementSibling(cur)) {
      if (std::string("CamcorderProfiles") !=
          reinterpret_cast<const char*>(cur->name)) {
        continue;
      }
      camera_profiles.push_back(cur);
    }

    switch (camera_profiles.size()) {
      case 0:
        LOG(ERROR) << "No camera profile found in media profile content:\n"
                   << content;
        return std::nullopt;
      case 1:
        // The original content of media profile may already be filtered by test
        // code[1]. Here we ensure there's always have at least one camera to be
        // tested is available after applying all filtering.  TODO(b/187239915):
        // Remove filter in test code and unify filter logic here.
        // [1]
        // https://source.corp.google.com/chromeos_public/src/third_party/labpack/files/server/cros/camerabox_utils.py;rcl=d30bb56fe7ae9c39b122a28f1d5d2b64f928555c;l=106
        return content;
      case 2:
        break;
      default:
        NOTREACHED() << "Found more than 2 camera profiles";
        return std::nullopt;
    }

    xmlNodePtr front_camera_profile = nullptr;
    xmlNodePtr back_camera_profile = nullptr;
    for (xmlNodePtr profile : camera_profiles) {
      auto* xml_camera_prop =
          xmlGetProp(profile, reinterpret_cast<const xmlChar*>("cameraId"));
      if (!xml_camera_prop) {
        LOG(ERROR) << "Unable to get camera property.";
        return std::nullopt;
      }
      auto* cameraId = reinterpret_cast<const char*>(xml_camera_prop);
      if (std::string("0") == cameraId) {
        CHECK(back_camera_profile == nullptr)
            << "Duplicate back facing profile";
        back_camera_profile = profile;
      } else if (std::string("1") == cameraId) {
        CHECK(front_camera_profile == nullptr)
            << "Duplicate front facing profile";
        front_camera_profile = profile;
      } else {
        LOG(ERROR) << "Unknown cameraId \"" << cameraId
                   << "\" in media profile content:\n"
                   << content;
        xmlFree(xml_camera_prop);
        return std::nullopt;
      }
      xmlFree(xml_camera_prop);
    }

    if (enable_front_camera) {
      // After deleting the profile, the camera id of left profile should start
      // from 0.
      xmlSetProp(front_camera_profile,
                 reinterpret_cast<const xmlChar*>("cameraId"),
                 reinterpret_cast<const xmlChar*>("0"));
    } else {
      xmlUnlinkNode(front_camera_profile);
      xmlFreeNode(front_camera_profile);
    }

    if (enable_back_camera) {
      // After deleting the profile, the camera id of left profile should start
      // from 0.
      xmlSetProp(back_camera_profile,
                 reinterpret_cast<const xmlChar*>("cameraId"),
                 reinterpret_cast<const xmlChar*>("0"));
    } else {
      xmlUnlinkNode(back_camera_profile);
      xmlFreeNode(back_camera_profile);
    }

    // Dump results.
    xmlChar* buf = nullptr;
    int size = 0;
    xmlDocDumpFormatMemory(doc, &buf, &size, /* format */ 1);
    CHECK(buf != nullptr) << "Failed to dump filtered xml result";
    std::string xml_result(reinterpret_cast<const char*>(buf), size);
    xmlFree(buf);
    return xml_result;
  }();
  xmlFreeDoc(doc);
  xmlCleanupParser();

  return result;
}

std::optional<std::string> AppendFeatureManagement(
    const base::FilePath& hardware_profile_xml,
    segmentation::FeatureManagement& feature_management) {
  // Open the file
  std::string content;
  if (!base::ReadFileToString(hardware_profile_xml, &content)) {
    LOG(ERROR) << "Failed to read media profile from "
               << hardware_profile_xml.value();
    return std::nullopt;
  }

  // Get the list of features to enable.
  std::set<std::string> features =
      feature_management.ListFeatures(segmentation::USAGE_ANDROID);
  if (features.size() == 0) {
    // Nothing to add.
    return content;
  }

  // Interpret the XML file
  LIBXML_TEST_VERSION
  xmlDocPtr doc;

  auto result = [&doc, &content, &features]() -> std::optional<std::string> {
    doc = xmlReadMemory(content.c_str(), content.size(), nullptr, nullptr, 0);
    if (doc == nullptr) {
      LOG(ERROR) << "Failed to parse hardware profile content:\n" << content;
      return std::nullopt;
    }
    // For keeping indent.
    xmlKeepBlanksDefault(0);

    xmlNodePtr permissions = xmlDocGetRootElement(doc);
    if (permissions == nullptr) {
      LOG(ERROR) << "No root element node found in hardware profile content:\n"
                 << content;
      return std::nullopt;
    }
    if (std::string(reinterpret_cast<const char*>(permissions->name)) !=
        "permissions") {
      LOG(ERROR) << "Failed to find permissions settings in hardware profile "
                    "content:\n"
                 << content;
      return std::nullopt;
    }

    for (auto feature : features) {
      xmlNodePtr feature_node = xmlNewDocNode(
          doc, nullptr, reinterpret_cast<const xmlChar*>("feature"), nullptr);
      if (!feature_node) {
        LOG(ERROR) << "Unable to allocate a node to hardware profile content:\n"
                   << content;
        return std::nullopt;
      }
      if (xmlAddChild(permissions, feature_node) == nullptr) {
        LOG(ERROR) << "Unable to add a node to hardware profile content:\n"
                   << content;
        xmlFreeNode(feature_node);
        return std::nullopt;
      }
      if (xmlNewProp(feature_node, reinterpret_cast<const xmlChar*>("name"),
                     reinterpret_cast<const xmlChar*>(
                         base::StrCat(
                             {"org.chromium.arc.feature_management.", feature})
                             .c_str())) == nullptr) {
        LOG(ERROR) << "Unable to add feature " << feature
                   << "hardware profile content:\n"
                   << content;
        return std::nullopt;
      }
    }

    // Dump results.
    xmlChar* buf = nullptr;
    int size = 0;
    xmlDocDumpFormatMemory(doc, &buf, &size, /* format */ 1);
    CHECK(buf != nullptr) << "Failed to dump filtered xml result";
    std::string xml_result(reinterpret_cast<const char*>(buf), size);
    xmlFree(buf);
    return xml_result;
  }();
  xmlFreeDoc(doc);
  xmlCleanupParser();

  return result;
}
}  // namespace arc
