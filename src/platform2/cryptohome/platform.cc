// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Contains the implementation of class Platform

#include "cryptohome/platform.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/loop.h>
#include <mntent.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/quota.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <base/check_op.h>

#include <algorithm>
#include <limits>

#if USE_SELINUX
#include <selinux/restorecon.h>
#include <selinux/selinux.h>
#endif

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/numerics/safe_conversions.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <base/unguessable_token.h>
#include <brillo/blkdev_utils/device_mapper.h>
#include <brillo/blkdev_utils/get_backing_block_device.h>
#include <brillo/blkdev_utils/loop_device.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/blkdev_utils/storage_utils.h>
#include <brillo/file_utils.h>
#include <brillo/files/file_util.h>
#include <brillo/files/safe_fd.h>
#include <brillo/process/process.h>
#include <brillo/scoped_umask.h>
#include <brillo/secure_blob.h>
#include <libcrossystem/crossystem.h>
#include <rootdev/rootdev.h>
#include <secure_erase_file/secure_erase_file.h>

extern "C" {
#include <keyutils.h>
#include <linux/fs.h>
}

#include "cryptohome/crc.h"
#include "cryptohome/dircrypto_util.h"

using base::FilePath;
using base::SplitString;
using base::StringPrintf;

namespace {

// Log sync(), fsync(), etc. calls that take this many seconds or longer.
const base::TimeDelta kLongSync = base::Seconds(10);
// Hibernation stateful device: keep in sync with chromeos_startup.sh.
constexpr char kStatefulHibernationDevice[] = "/dev/mapper/stateful-rw";

constexpr ssize_t kLvmSignatureOffset = 512;
constexpr ssize_t kLvmSignatureSize = 8;
constexpr char kLvmSignature[] = "LABELONE";

constexpr char kProcDir[] = "/proc";
constexpr char kMountInfoFile[] = "mountinfo";
constexpr char kPathTune2fs[] = "/sbin/tune2fs";
constexpr char kEcryptFS[] = "ecryptfs";

bool IsDirectory(const base::stat_wrapper_t& file_info) {
  return !!S_ISDIR(file_info.st_mode);
}

/*
 * Split a /proc/<id>/mountinfo line in arguments and
 * populate information into |mount_info|.
 * Return true if the line seems valid.
 */
bool DecodeProcInfoLine(const std::string& line,
                        cryptohome::DecodedProcMountInfo* mount_info) {
  auto args =
      SplitString(line, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  size_t fs_idx = 6;
  if (args.size() <= fs_idx) {
    LOG(ERROR) << "Invalid procinfo: too few items: " << line;
    return false;
  }

  while (fs_idx < args.size() && args[fs_idx++] != "-") {
  }
  if (fs_idx + 1 >= args.size()) {
    LOG(ERROR) << "Invalid procinfo: separator or mount_source not found: "
               << line;
    return false;
  } else {
    mount_info->root = args[3];
    mount_info->mount_point = args[4];
    mount_info->filesystem_type = args[fs_idx];
    mount_info->mount_source = args[fs_idx + 1];
    return true;
  }
}

}  // namespace

namespace cryptohome {

const char kLoopPrefix[] = "/dev/loop";

void DcheckIsNonemptyAbsolutePath(const base::FilePath& path) {
  DCHECK(!path.empty());
  DCHECK(path.IsAbsolute()) << "path=" << path;
}

// TODO(b/232566569): Pass dependencies (lvm, loop device manager) into platform
// explicitly instead of creating in place.
Platform::Platform()
    : mount_info_path_(FilePath(kProcDir)
                           .Append(std::to_string(getpid()))
                           .Append(kMountInfoFile)),
      loop_device_manager_(std::make_unique<brillo::LoopDeviceManager>()),
      lvm_(std::make_unique<brillo::LogicalVolumeManager>()),
      crossystem_(std::make_unique<crossystem::Crossystem>()) {}

Platform::~Platform() {}

brillo::LoopDeviceManager* Platform::GetLoopDeviceManager() {
  return loop_device_manager_.get();
}

brillo::LogicalVolumeManager* Platform::GetLogicalVolumeManager() {
  return lvm_.get();
}

std::vector<DecodedProcMountInfo> Platform::ReadMountInfoFile() {
  std::string contents;
  if (!base::ReadFileToString(mount_info_path_, &contents))
    return std::vector<DecodedProcMountInfo>();

  std::vector<std::string> lines = SplitString(
      contents, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  std::vector<DecodedProcMountInfo> mount_info_content;
  for (const auto& line : lines) {
    DecodedProcMountInfo mount_info;
    if (!DecodeProcInfoLine(line, &mount_info))
      return std::vector<DecodedProcMountInfo>();
    mount_info_content.push_back(mount_info);
  }
  return mount_info_content;
}

bool Platform::GetLoopDeviceMounts(
    std::multimap<const FilePath, const FilePath>* mounts) {
  return GetMountsByDevicePrefix(kLoopPrefix, mounts);
}

bool Platform::GetMountsBySourcePrefix(
    const FilePath& from_prefix,
    std::multimap<const FilePath, const FilePath>* mounts) {
  std::vector<DecodedProcMountInfo> proc_mounts = ReadMountInfoFile();

  // If there is no mounts pointer, we can return false right away.
  if (!mounts) {
    return false;
  }

  // When using ecryptfs, we compare the mount device, otherwise,
  // we use the root directory .
  for (const auto& mount : proc_mounts) {
    FilePath root_dir;
    if (mount.filesystem_type == kEcryptFS)
      root_dir = FilePath(mount.mount_source);
    else
      root_dir = FilePath(mount.root);
    if (!from_prefix.IsParent(root_dir))
      continue;

    mounts->insert(std::pair<const FilePath, const FilePath>(
        root_dir, FilePath(mount.mount_point)));
  }
  return !mounts->empty();
}

bool Platform::GetMountsByDevicePrefix(
    const std::string& from_prefix,
    std::multimap<const FilePath, const FilePath>* mounts) {
  std::vector<DecodedProcMountInfo> proc_mounts = ReadMountInfoFile();

  // If there is no mounts pointer, we can return false right away.
  if (!mounts) {
    return false;
  }

  for (const auto& mount : proc_mounts) {
    if (!base::StartsWith(mount.mount_source, from_prefix,
                          base::CompareCase::SENSITIVE)) {
      continue;
    }
    mounts->insert({FilePath(mount.mount_source), FilePath(mount.mount_point)});
  }
  return !mounts->empty();
}

bool Platform::IsDirectoryMounted(const FilePath& directory) {
  DCHECK(directory.IsAbsolute()) << "directory=" << directory;

  // Trivial string match from /etc/mtab to see if the cryptohome mount point is
  // listed.  This works because Chrome OS is a controlled environment and the
  // only way /home/chronos/user should be mounted is if cryptohome mounted it.
  auto ret = AreDirectoriesMounted({directory});

  if (!ret)
    return false;

  return ret.value()[0];
}

std::optional<std::vector<bool>> Platform::AreDirectoriesMounted(
    const std::vector<base::FilePath>& directories) {
  std::string contents;
  if (!base::ReadFileToString(mount_info_path_, &contents)) {
    return std::nullopt;
  }

  std::vector<bool> ret;
  ret.reserve(directories.size());

  for (auto& directory : directories) {
    DCHECK(directory.IsAbsolute()) << "directory=" << directory;

    bool is_mounted =
        contents.find(StringPrintf(" %s ", directory.value().c_str())) !=
        std::string::npos;

    ret.push_back(is_mounted);
  }

  return ret;
}

bool Platform::Mount(const FilePath& from,
                     const FilePath& to,
                     const std::string& type,
                     uint32_t mount_flags,
                     const std::string& mount_options) {
  DCHECK(from.IsAbsolute()) << "from=" << from;
  DCHECK(to.IsAbsolute()) << "to=" << to;

  if (mount(from.value().c_str(), to.value().c_str(), type.c_str(), mount_flags,
            mount_options.c_str())) {
    return false;
  }
  return true;
}

bool Platform::Bind(const FilePath& from,
                    const FilePath& to,
                    RemountOption remount,
                    bool nosymfollow) {
  DCHECK(from.IsAbsolute()) << "from=" << from;
  DCHECK(to.IsAbsolute()) << "to=" << to;

  // To apply options specific to a bind mount, we have to call mount(2) twice.
  if (mount(from.value().c_str(), to.value().c_str(), nullptr, MS_BIND,
            nullptr))
    return false;

  uint32_t mount_flags = MS_REMOUNT | MS_BIND | kDefaultMountFlags;
  std::string options;
  if (nosymfollow) {
    mount_flags |= MS_NOSYMFOLLOW;
  }

  if (mount(nullptr, to.value().c_str(), nullptr, mount_flags, options.c_str()))
    return false;

  if (remount != RemountOption::kNoRemount) {
    uint32_t remount_mode;
    switch (remount) {
      case RemountOption::kPrivate:
        remount_mode = MS_PRIVATE;
        break;
      case RemountOption::kShared:
        remount_mode = MS_SHARED;
        break;
      case RemountOption::kMountsFlowIn:
        remount_mode = MS_SLAVE;
        break;
      case RemountOption::kUnbindable:
        remount_mode = MS_UNBINDABLE;
        break;
      default:
        return false;
    }
    if (mount(nullptr, to.value().c_str(), nullptr, remount_mode, nullptr))
      return false;
  }

  return true;
}

ExpireMountResult Platform::ExpireMount(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (umount2(path.value().c_str(), MNT_EXPIRE)) {
    if (errno == EAGAIN) {
      return ExpireMountResult::kMarked;
    } else {
      PLOG(ERROR) << "ExpireMount(" << path.value() << ") failed";
      if (errno == EBUSY) {
        return ExpireMountResult::kBusy;
      } else {
        return ExpireMountResult::kError;
      }
    }
  }
  return ExpireMountResult::kUnmounted;
}

bool Platform::Unmount(const FilePath& path, bool lazy, bool* was_busy) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (lazy) {
    if (umount2(path.value().c_str(), MNT_DETACH)) {
      if (was_busy) {
        *was_busy = (errno == EBUSY);
      }
      return false;
    }
  } else {
    if (umount(path.value().c_str())) {
      if (was_busy) {
        *was_busy = (errno == EBUSY);
      }
      return false;
    }
  }
  if (was_busy) {
    *was_busy = false;
  }
  return true;
}

void Platform::LazyUnmount(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (umount2(path.value().c_str(), MNT_DETACH | UMOUNT_NOFOLLOW)) {
    if (errno != EBUSY) {
      PLOG(ERROR) << "Lazy unmount failed";
    }
  }
}

std::unique_ptr<brillo::Process> Platform::CreateProcessInstance() {
  return std::make_unique<brillo::ProcessImpl>();
}

bool Platform::GetOwnership(const FilePath& path,
                            uid_t* user_id,
                            gid_t* group_id,
                            bool follow_links) const {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  struct stat path_status;
  int ret;
  if (follow_links)
    ret = stat(path.value().c_str(), &path_status);
  else
    ret = lstat(path.value().c_str(), &path_status);

  if (ret != 0) {
    PLOG(ERROR) << (follow_links ? "" : "l") << "stat() of \"" << path.value()
                << "\" failed.";
    return false;
  }
  if (user_id)
    *user_id = path_status.st_uid;
  if (group_id)
    *group_id = path_status.st_gid;
  return true;
}

bool Platform::SetOwnership(const FilePath& path,
                            uid_t user_id,
                            gid_t group_id,
                            bool follow_links) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  int ret;
  if (follow_links)
    ret = chown(path.value().c_str(), user_id, group_id);
  else
    ret = lchown(path.value().c_str(), user_id, group_id);
  if (ret) {
    PLOG(ERROR) << (follow_links ? "" : "l") << "chown() of \"" << path.value()
                << "\" to (" << user_id << "," << group_id << ") failed.";
    return false;
  }
  return true;
}

bool Platform::GetPermissions(const FilePath& path, mode_t* mode) const {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  struct stat path_status;
  if (stat(path.value().c_str(), &path_status) != 0) {
    PLOG(ERROR) << "stat() of \"" << path.value() << "\" failed.";
    return false;
  }
  *mode = path_status.st_mode;
  return true;
}

bool Platform::SetPermissions(const FilePath& path, mode_t mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (chmod(path.value().c_str(), mode)) {
    PLOG(ERROR) << "chmod() of \"" << path.value() << "\" to (" << std::oct
                << mode << ") failed.";
    return false;
  }
  return true;
}

int64_t Platform::AmountOfFreeDiskSpace(const FilePath& path) const {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return base::SysInfo::AmountOfFreeDiskSpace(path);
}

int64_t Platform::GetQuotaCurrentSpaceForUid(const base::FilePath& device,
                                             uid_t user_id) const {
  DCHECK(device.IsAbsolute()) << "device=" << device;

  struct dqblk dq = {};
  if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), device.value().c_str(), user_id,
               reinterpret_cast<char*>(&dq)) != 0) {
    PLOG(ERROR) << "quotactl failed for user " << user_id;
    return -1;
  }
  return dq.dqb_curspace;
}

int64_t Platform::GetQuotaCurrentSpaceForGid(const base::FilePath& device,
                                             gid_t group_id) const {
  DCHECK(device.IsAbsolute()) << "device=" << device;

  struct dqblk dq = {};
  if (quotactl(QCMD(Q_GETQUOTA, GRPQUOTA), device.value().c_str(), group_id,
               reinterpret_cast<char*>(&dq)) != 0) {
    return -1;
  }
  return dq.dqb_curspace;
}

int64_t Platform::GetQuotaCurrentSpaceForProjectId(const base::FilePath& device,
                                                   int project_id) const {
  DCHECK(device.IsAbsolute()) << "device=" << device;

  struct dqblk dq = {};
  if (quotactl(QCMD(Q_GETQUOTA, PRJQUOTA), device.value().c_str(), project_id,
               reinterpret_cast<char*>(&dq)) != 0) {
    return -1;
  }
  return dq.dqb_curspace;
}

bool Platform::GetQuotaProjectId(const base::FilePath& path,
                                 int* project_id) const {
  base::stat_wrapper_t stat = {};
  if (base::File::Lstat(path.value().c_str(), &stat) != 0) {
    PLOG(ERROR) << "Failed to stat " << path.value();
    return false;
  }
  brillo::SafeFD fd;
  brillo::SafeFD::Error err;
  if (S_ISDIR(stat.st_mode)) {
    std::tie(fd, err) = brillo::SafeFD::Root().first.OpenExistingDir(path);
  } else {
    std::tie(fd, err) = brillo::SafeFD::Root().first.OpenExistingFile(path);
  }
  if (brillo::SafeFD::IsError(err)) {
    PLOG(ERROR) << "Failed to open \"" << path.value() << "\" with error "
                << static_cast<int>(err);
    return false;
  }
  DCHECK(fd.is_valid());

  struct fsxattr fsx = {};
  if (ioctl(fd.get(), FS_IOC_FSGETXATTR, &fsx) < 0) {
    PLOG(ERROR) << "ioctl(FS_IOC_FSGETXATTR) failed";
    return false;
  }
  *project_id = fsx.fsx_projid;
  return true;
}

bool Platform::SetQuotaProjectId(const base::FilePath& path, int project_id) {
  base::stat_wrapper_t stat = {};
  if (base::File::Lstat(path.value().c_str(), &stat) != 0) {
    PLOG(ERROR) << "Failed to stat " << path.value();
    return false;
  }
  brillo::SafeFD fd;
  brillo::SafeFD::Error err;
  if (S_ISDIR(stat.st_mode)) {
    std::tie(fd, err) = brillo::SafeFD::Root().first.OpenExistingDir(path);
  } else {
    std::tie(fd, err) = brillo::SafeFD::Root().first.OpenExistingFile(path);
  }
  if (brillo::SafeFD::IsError(err)) {
    PLOG(ERROR) << "Failed to open \"" << path.value() << "\" with error "
                << static_cast<int>(err);
    return false;
  }
  DCHECK(fd.is_valid());

  int error = 0;
  return SetQuotaProjectIdWithFd(project_id, fd.get(), &error);
}

bool Platform::SetQuotaProjectIdWithFd(int project_id, int fd, int* out_error) {
  struct fsxattr fsx = {};
  if (ioctl(fd, FS_IOC_FSGETXATTR, &fsx) < 0) {
    *out_error = errno;
    PLOG(ERROR) << "ioctl(FS_IOC_FSGETXATTR) failed";
    return false;
  }
  fsx.fsx_projid = project_id;
  if (ioctl(fd, FS_IOC_FSSETXATTR, &fsx) < 0) {
    *out_error = errno;
    PLOG(ERROR) << "ioctl(FS_IOC_FSSETXATTR) failed: project_id=" << project_id;
    return false;
  }
  return true;
}

bool Platform::SetQuotaProjectInheritanceFlagWithFd(bool enable,
                                                    int fd,
                                                    int* out_error) {
  uint32_t flags;
  if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0) {
    *out_error = errno;
    PLOG(ERROR) << "ioctl(FS_IOC_GETFLAGS) failed";
    return false;
  }

  if (enable) {
    flags |= FS_PROJINHERIT_FL;
  } else {
    flags &= ~FS_PROJINHERIT_FL;
  }

  if (ioctl(fd, FS_IOC_SETFLAGS, reinterpret_cast<void*>(&flags)) < 0) {
    *out_error = errno;
    PLOG(ERROR) << "ioctl(FS_IOC_SETFLAGS) failed: flags=" << std::hex << flags;
    return false;
  }
  return true;
}

bool Platform::FileExists(const FilePath& path) const {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return base::PathExists(path);
}

int Platform::Access(const FilePath& path, uint32_t flag) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return HANDLE_EINTR(access(path.value().c_str(), flag));
}

bool Platform::DirectoryExists(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  base::stat_wrapper_t buf = {};
  return Stat(path, &buf) && S_ISDIR(buf.st_mode);
}

bool Platform::GetFileSize(const FilePath& path, int64_t* size) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return base::GetFileSize(path, size);
}

int64_t Platform::ComputeDirectoryDiskUsage(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::ComputeDirectoryDiskUsage(path);
}

FILE* Platform::OpenFile(const FilePath& path, const char* mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return base::OpenFile(path, mode);
}

bool Platform::CloseFile(FILE* fp) {
  return base::CloseFile(fp);
}

void Platform::InitializeFile(base::File* file,
                              const base::FilePath& path,
                              uint32_t flags) {
  return file->Initialize(path, flags);
}

bool Platform::LockFile(int fd) {
  return HANDLE_EINTR(flock(fd, LOCK_EX)) == 0;
}

bool Platform::WriteFile(const FilePath& path, const brillo::Blob& blob) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::WriteBlobToFile<brillo::Blob>(path, blob);
}

bool Platform::WriteSecureBlobToFile(const FilePath& path,
                                     const brillo::SecureBlob& blob) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::WriteBlobToFile<brillo::SecureBlob>(path, blob);
}

bool Platform::WriteStringToFile(const FilePath& path,
                                 const std::string& data) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::WriteStringToFile(path, data);
}

bool Platform::WriteArrayToFile(const FilePath& path,
                                const char* data,
                                size_t size) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::WriteToFile(path, data, size);
}

bool Platform::WriteFileAtomic(const FilePath& path,
                               const brillo::Blob& blob,
                               mode_t mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::WriteBlobToFileAtomic<brillo::Blob>(path, blob, mode);
}

bool Platform::WriteSecureBlobToFileAtomic(const FilePath& path,
                                           const brillo::SecureBlob& blob,
                                           mode_t mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::WriteBlobToFileAtomic<brillo::SecureBlob>(path, blob, mode);
}

bool Platform::WriteStringToFileAtomic(const FilePath& path,
                                       const std::string& data,
                                       mode_t mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::WriteToFileAtomic(path, data.data(), data.size(), mode);
}

bool Platform::WriteFileAtomicDurable(const FilePath& path,
                                      const brillo::Blob& blob,
                                      mode_t mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  const std::string data(reinterpret_cast<const char*>(blob.data()),
                         blob.size());
  return WriteStringToFileAtomicDurable(path, data, mode);
}

bool Platform::WriteSecureBlobToFileAtomicDurable(
    const FilePath& path, const brillo::SecureBlob& blob, mode_t mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (!WriteSecureBlobToFileAtomic(path, blob, mode))
    return false;

  WriteChecksum(path, blob.data(), blob.size(), mode);
  return SyncDirectory(FilePath(path).DirName());
}

bool Platform::WriteStringToFileAtomicDurable(const FilePath& path,
                                              const std::string& data,
                                              mode_t mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (!WriteStringToFileAtomic(path, data, mode))
    return false;
  WriteChecksum(path, data.data(), data.size(), mode);
  return SyncDirectory(FilePath(path).DirName());
}

bool Platform::TouchFileDurable(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  brillo::Blob empty_blob(0);
  if (!WriteFile(path, empty_blob))
    return false;
  return SyncDirectory(FilePath(path).DirName());
}

bool Platform::ReadFile(const FilePath& path, brillo::Blob* blob) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return ReadFileToBlob<brillo::Blob>(path, blob);
}

bool Platform::ReadFileToString(const FilePath& path, std::string* string) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (!base::ReadFileToString(path, string)) {
    return false;
  }
  VerifyChecksum(path, string->data(), string->size());
  return true;
}

bool Platform::ReadFileToSecureBlob(const FilePath& path,
                                    brillo::SecureBlob* sblob) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return ReadFileToBlob<brillo::SecureBlob>(path, sblob);
}

bool Platform::CreateDirectoryAndGetError(const FilePath& path,
                                          base::File::Error* error) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return base::CreateDirectoryAndGetError(path, error);
}

bool Platform::CreateDirectory(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return base::CreateDirectory(path);
}

bool Platform::SafeDirChmod(const base::FilePath& path, mode_t mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  // Reset mask since we are setting the mode explicitly.
  brillo::ScopedUmask scoped_umask(0);

  auto root_fd_result = brillo::SafeFD::Root();
  if (root_fd_result.second != brillo::SafeFD::Error::kNoError) {
    return false;
  }

  auto path_result = root_fd_result.first.OpenExistingDir(path);
  if (path_result.second != brillo::SafeFD::Error::kNoError) {
    return false;
  }

  if (HANDLE_EINTR(fchmod(path_result.first.get(), mode)) != 0) {
    PLOG(ERROR) << "Failed to set permissions in SafeDirChmod() for \""
                << path.value() << '"';
    return false;
  }

  return true;
}

bool Platform::SafeDirChown(const base::FilePath& path,
                            uid_t user_id,
                            gid_t group_id) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  auto root_fd_result = brillo::SafeFD::Root();
  if (root_fd_result.second != brillo::SafeFD::Error::kNoError) {
    return false;
  }

  auto path_result = root_fd_result.first.OpenExistingDir(path);
  if (path_result.second != brillo::SafeFD::Error::kNoError) {
    return false;
  }

  if (HANDLE_EINTR(fchown(path_result.first.get(), user_id, group_id)) != 0) {
    PLOG(ERROR) << "Failed to set ownership in SafeDirChown() for \""
                << path.value() << '"';
    return false;
  }

  return true;
}

bool Platform::SafeCreateDirAndSetOwnershipAndPermissions(
    const base::FilePath& path, mode_t mode, uid_t user_id, gid_t group_id) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  // Reset mask since we are setting the mode explicitly.
  brillo::ScopedUmask scoped_umask(0);

  auto root_fd_result = brillo::SafeFD::Root();
  if (root_fd_result.second != brillo::SafeFD::Error::kNoError) {
    return false;
  }

  auto path_result =
      root_fd_result.first.MakeDir(path, mode, user_id, group_id);
  if (path_result.second != brillo::SafeFD::Error::kNoError) {
    return false;
  }

  // mkdirat, which is used within MakeDir, only sets permissions under 01777
  // mask. There should be a separate chmod to allow SetGid and SetUid modes.
  // It is done here in a safe manner by doing fchmod on the returned
  // descriptor.
  constexpr mode_t mkdirat_mask = 01777;
  if ((mode & ~mkdirat_mask) == 0) {
    return true;
  }
  if (HANDLE_EINTR(fchmod(path_result.first.get(), mode)) != 0) {
    PLOG(ERROR) << "Failed to set permissions in MakeDir() for \""
                << path.value() << '"';
    return false;
  }

  return true;
}

bool Platform::UdevAdmSettle(const base::FilePath& device_path,
                             bool wait_for_device) {
  DCHECK(device_path.IsAbsolute()) << "device_path=" << device_path;

  brillo::ProcessImpl udevadm_process;
  udevadm_process.AddArg("/bin/udevadm");
  udevadm_process.AddArg("settle");

  if (wait_for_device) {
    udevadm_process.AddArg("-t");
    udevadm_process.AddArg("10");
    udevadm_process.AddArg("-E");
    udevadm_process.AddArg(device_path.value());
  }
  // Close unused file descriptors in child process.
  udevadm_process.SetCloseUnusedFileDescriptors(true);

  // Start the process and return.
  int rc = udevadm_process.Run();
  if (rc != 0)
    return false;

  return true;
}

bool Platform::IsStatefulLogicalVolumeSupported() {
  base::FilePath stateful_device = GetStatefulDevice();

  base::ScopedFD fd(HANDLE_EINTR(
      open(stateful_device.value().c_str(), O_RDONLY | O_CLOEXEC)));

  if (!fd.is_valid())
    return false;

  char lvm_signature[kLvmSignatureSize + 1];

  if (HANDLE_EINTR(pread(fd.get(), &lvm_signature, kLvmSignatureSize,
                         kLvmSignatureOffset)) != kLvmSignatureSize)
    return false;
  lvm_signature[kLvmSignatureSize] = '\0';

  return std::string(lvm_signature) == std::string(kLvmSignature);
}

base::FilePath Platform::GetStatefulDevice() {
  // Check if the stateful hibernation dm-snapshot device is active and use it.
  base::FilePath stateful_hibernation_device(kStatefulHibernationDevice);
  if (FileExists(stateful_hibernation_device))
    return stateful_hibernation_device;

  char root_device[PATH_MAX];
  int ret = rootdev(root_device, sizeof(root_device),
                    true,   // Do full resolution.
                    true);  // Remove partition number.
  if (ret != 0) {
    LOG(WARNING) << "rootdev failed with error code " << ret;
    return base::FilePath();
  }

  return brillo::AppendPartition(base::FilePath(root_device), 1);
}

bool Platform::DeleteFile(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::DeleteFile(path);
}

bool Platform::DeletePathRecursively(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::DeletePathRecursively(path);
}

bool Platform::DeleteFileDurable(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (!brillo::DeletePathRecursively(path))
    return false;
  return SyncDirectory(path.DirName());
}

bool Platform::DeleteFileSecurely(const FilePath& path) {
  bool ok = false;

  if (secure_erase_file::IsSupported(path)) {
    ok = secure_erase_file::SecureErase(path);
  }

  if (!ok) {
    ok = secure_erase_file::ZeroFile(path);
  }

  return ok && secure_erase_file::DropCaches();
}

bool Platform::EnumerateDirectoryEntries(const FilePath& path,
                                         bool recursive,
                                         std::vector<FilePath>* ent_list) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  auto ft = static_cast<base::FileEnumerator::FileType>(
      base::FileEnumerator::FILES | base::FileEnumerator::DIRECTORIES |
      base::FileEnumerator::SHOW_SYM_LINKS);
  base::FileEnumerator ent_enum(path, recursive, ft);
  for (FilePath path = ent_enum.Next(); !path.empty(); path = ent_enum.Next())
    ent_list->push_back(path);
  return true;
}

bool Platform::IsDirectoryEmpty(const base::FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return base::IsDirectoryEmpty(path);
}

base::Time Platform::GetCurrentTime() const {
  return base::Time::Now();
}

bool Platform::Stat(const FilePath& path, base::stat_wrapper_t* buf) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return base::File::Lstat(path.value().c_str(), buf) == 0;
}

bool Platform::HasExtendedFileAttribute(const FilePath& path,
                                        const std::string& name) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  ssize_t sz = lgetxattr(path.value().c_str(), name.c_str(), nullptr, 0);
  if (sz < 0) {
    if (errno != ENODATA) {
      PLOG(ERROR) << "lgetxattr for " << name << ": " << path.value();
    }
    return false;
  }
  return true;
}

bool Platform::ListExtendedFileAttributes(const FilePath& path,
                                          std::vector<std::string>* attr_list) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  ssize_t sz = llistxattr(path.value().c_str(), nullptr, 0);
  if (sz < 0) {
    PLOG(ERROR) << "llistxattr: " << path.value();
    return false;
  }
  std::vector<char> names(sz);
  if (llistxattr(path.value().c_str(), names.data(), sz) < 0) {
    PLOG(ERROR) << "llistxattr: " << path.value();
    return false;
  }
  int pos = 0;
  while (pos < sz) {
    attr_list->emplace_back(names.data() + pos);
    pos += attr_list->back().length() + 1;
  }
  return true;
}

bool Platform::GetExtendedFileAttributeAsString(const base::FilePath& path,
                                                const std::string& name,
                                                std::string* value) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  ssize_t sz = lgetxattr(path.value().c_str(), name.c_str(), nullptr, 0);
  if (sz < 0) {
    PLOG(ERROR) << "lgetxattr for " << name << ": " << path.value();
    return false;
  }
  std::vector<char> value_vector(sz);
  if (!GetExtendedFileAttribute(path, name, value_vector.data(), sz)) {
    return false;
  }
  value->assign(value_vector.data(), sz);
  return true;
}

bool Platform::GetExtendedFileAttribute(const base::FilePath& path,
                                        const std::string& name,
                                        char* value,
                                        ssize_t size) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (lgetxattr(path.value().c_str(), name.c_str(), value, size) != size) {
    PLOG(ERROR) << "lgetxattr for " << name << ": " << path.value();
    return false;
  }
  return true;
}

bool Platform::SetExtendedFileAttribute(const base::FilePath& path,
                                        const std::string& name,
                                        const char* value,
                                        size_t size) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (lsetxattr(path.value().c_str(), name.c_str(), value, size, 0) != 0) {
    PLOG(ERROR) << "lsetxattr for " << name << ", " << value << ": "
                << path.value();
    return false;
  }
  return true;
}

bool Platform::RemoveExtendedFileAttribute(const base::FilePath& path,
                                           const std::string& name) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (lremovexattr(path.value().c_str(), name.c_str()) != 0) {
    PLOG(ERROR) << "lremovexattr for " << name << ": " << path.value();
    return false;
  }
  return true;
}

bool Platform::GetExtFileAttributes(const FilePath& path, int* flags) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  int fd = HANDLE_EINTR(open(path.value().c_str(), O_RDONLY));
  if (fd < 0) {
    PLOG(ERROR) << "open: " << path.value();
    return false;
  }
  // FS_IOC_GETFLAGS actually takes int*
  // though the signature suggests long*.
  // https://lwn.net/Articles/575846/
  if (ioctl(fd, FS_IOC_GETFLAGS, flags) < 0) {
    PLOG(ERROR) << "ioctl: " << path.value();
    IGNORE_EINTR(close(fd));
    return false;
  }
  IGNORE_EINTR(close(fd));
  return true;
}

bool Platform::SetExtFileAttributes(const FilePath& path, int added_flags) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  int fd = HANDLE_EINTR(open(path.value().c_str(), O_RDONLY));
  if (fd < 0) {
    PLOG(ERROR) << "open: " << path.value();
    return false;
  }
  // FS_IOC_SETFLAGS actually takes int*
  // though the signature suggests long*.
  // https://lwn.net/Articles/575846/
  int current_flags;
  if (ioctl(fd, FS_IOC_GETFLAGS, &current_flags) < 0) {
    PLOG(ERROR) << "ioctl GETFLAGS: " << path.value();
    IGNORE_EINTR(close(fd));
    return false;
  }
  int flags = current_flags | added_flags;
  if (ioctl(fd, FS_IOC_SETFLAGS, &flags) < 0) {
    PLOG(ERROR) << "ioctl SETFLAGS for flags=" << std::hex << current_flags
                << "+" << std::hex << added_flags << ": " << path.value();
    IGNORE_EINTR(close(fd));
    return false;
  }
  IGNORE_EINTR(close(fd));
  return true;
}

bool Platform::HasNoDumpFileAttribute(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  int flags;
  return GetExtFileAttributes(path, &flags) &&
         (flags & FS_NODUMP_FL) == FS_NODUMP_FL;
}

bool Platform::Rename(const FilePath& from, const FilePath& to) {
  DCHECK(from.IsAbsolute()) << "from=" << from;
  DCHECK(to.IsAbsolute()) << "to=" << to;

  return base::ReplaceFile(from, to, /*error=*/nullptr);
}

bool Platform::Copy(const FilePath& from, const FilePath& to) {
  DCHECK(from.IsAbsolute()) << "from=" << from;
  DCHECK(to.IsAbsolute()) << "to=" << to;

  return base::CopyDirectory(from, to, true);
}

bool Platform::StatVFS(const FilePath& path, struct statvfs* vfs) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return statvfs(path.value().c_str(), vfs) == 0;
}

bool Platform::SameVFS(const base::FilePath& mnt_a,
                       const base::FilePath& mnt_b) {
  DCHECK(mnt_a.IsAbsolute()) << "mnt_a=" << mnt_a;
  DCHECK(mnt_b.IsAbsolute()) << "mnt_b=" << mnt_b;

  struct stat stat_a, stat_b;

  if (lstat(mnt_a.value().c_str(), &stat_a)) {
    PLOG(ERROR) << "lstat: " << mnt_a.value().c_str();
    return false;
  }
  if (lstat(mnt_b.value().c_str(), &stat_b)) {
    PLOG(ERROR) << "lstat: " << mnt_b.value().c_str();
    return false;
  }
  return (stat_a.st_dev == stat_b.st_dev);
}

bool Platform::FindFilesystemDevice(const FilePath& filesystem_in,
                                    std::string* device) {
  DCHECK(filesystem_in.IsAbsolute()) << "filesystem_in=" << filesystem_in;

  /* Clear device to indicate failure case. */
  device->clear();

  base::FilePath result = brillo::GetBackingLogicalDeviceForFile(filesystem_in);

  if (result.empty()) {
    return false;
  }

  *device = result.value();

  return true;
}

bool Platform::ReportFilesystemDetails(const FilePath& filesystem,
                                       const FilePath& logfile) {
  DCHECK(filesystem.IsAbsolute()) << "filesystem=" << filesystem;
  DCHECK(logfile.IsAbsolute()) << "logfile=" << logfile;

  brillo::ProcessImpl process;
  int rc;
  std::string device;
  if (!FindFilesystemDevice(filesystem, &device)) {
    LOG(ERROR) << "Failed to find device for " << filesystem.value();
    return false;
  }

  process.RedirectOutput(logfile.value());
  process.AddArg(kPathTune2fs);
  process.AddArg("-l");
  process.AddArg(device);

  rc = process.Run();
  if (rc == 0)
    return true;
  LOG(ERROR) << "Failed to run tune2fs on " << device << " ("
             << filesystem.value() << ", exit " << rc << ")";
  return false;
}

bool Platform::FirmwareWriteProtected() {
  return crossystem_->VbGetSystemPropertyInt("wpsw_cur").value_or(-1) != 0;
}

base::UnguessableToken Platform::CreateUnguessableToken() {
  return base::UnguessableToken::Create();
}

bool Platform::SyncFileOrDirectory(const FilePath& path,
                                   bool is_directory,
                                   bool data_sync) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return brillo::SyncFileOrDirectory(path, is_directory, data_sync);
}

bool Platform::SyncFile(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return SyncFileOrDirectory(path, false /* directory */,
                             false /* data_sync */);
}

bool Platform::SyncDirectory(const FilePath& path) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  return SyncFileOrDirectory(path, true /* directory */, false /* data_sync */);
}

void Platform::Sync() {
  const base::TimeTicks start = base::TimeTicks::Now();
  sync();
  const base::TimeDelta delta = base::TimeTicks::Now() - start;
  if (delta > kLongSync) {
    LOG(WARNING) << "Long sync(): " << delta.InSeconds() << " seconds";
  }
}

bool Platform::CreateSymbolicLink(const base::FilePath& path,
                                  const base::FilePath& target) {
  // Note that the `target` can be relative.
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (!base::CreateSymbolicLink(target, path)) {
    PLOG(ERROR) << "Failed to create link " << path.value();
    return false;
  }
  return true;
}

bool Platform::ReadLink(const base::FilePath& path, base::FilePath* target) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  if (!base::ReadSymbolicLink(path, target)) {
    PLOG(ERROR) << "Failed to read link " << path.value();
    return false;
  }
  return true;
}

bool Platform::SetFileTimes(const base::FilePath& path,
                            const struct timespec& atime,
                            const struct timespec& mtime,
                            bool follow_links) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  const struct timespec times[2] = {atime, mtime};
  if (utimensat(AT_FDCWD, path.value().c_str(), times,
                follow_links ? 0 : AT_SYMLINK_NOFOLLOW)) {
    PLOG(ERROR) << "Failed to update times for file " << path.value();
    return false;
  }
  return true;
}

bool Platform::SendFile(int fd_to, int fd_from, off_t offset, size_t count) {
  while (count > 0) {
    ssize_t written = sendfile(fd_to, fd_from, &offset, count);
    if (written < 0) {
      PLOG(ERROR) << "sendfile failed to copy data";
      return false;
    }
    if (written == 0) {
      LOG(ERROR) << "Attempting to read past the end of the file";
      return false;
    }
    count -= written;
  }
  return true;
}

bool Platform::CreateSparseFile(const base::FilePath& path, int64_t size) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  base::File file;
  InitializeFile(&file, path,
                 base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!file.IsValid()) {
    PLOG(ERROR) << "open sparse file " << path.value();
    return false;
  }
  return file.SetLength(size);
}

bool Platform::GetBlkSize(const base::FilePath& device, uint64_t* size) {
  DCHECK(device.IsAbsolute()) << "device=" << device;

  base::ScopedFD fd(
      HANDLE_EINTR(open(device.value().c_str(), O_RDONLY | O_CLOEXEC)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "open " << device.value();
    return false;
  }
  if (ioctl(fd.get(), BLKGETSIZE64, size)) {
    PLOG(ERROR) << "ioctl(BLKGETSIZE): " << device.value();
    return false;
  }
  return true;
}

bool Platform::DetachLoop(const base::FilePath& device_path) {
  DCHECK(device_path.IsAbsolute()) << "device_path=" << device_path;

  // TODO(dlunev): This is a horrible way to do it, but LoopDeviceManager
  // doesn't support searching by the path, only by the number, so then we have
  // a choice to either parse out the number from |device_path| or iterate over.
  // Since this function is not used a lot, iterating over all loop devices
  // doesn't cost a lot, but we should go and fix the interface of the
  // LoopDeviceManager to be sane. This function is also temporary until we
  // can rewrite the stale mount cleanup path - replacing the usage now is
  // complicated, because of the way the tests for stale cleanup are written.
  // The idea is to actually replace that path with a more generic session
  // recovery driver once the work on mount refactoring is finished.
  for (const auto& device : GetLoopDeviceManager()->GetAttachedDevices()) {
    if (device->GetDevicePath() == device_path) {
      std::ignore = device->SetName("");
      return device->Detach();
    }
  }
  // Not found the device
  return false;
}

bool Platform::DiscardDevice(const base::FilePath& device) {
  DCHECK(device.IsAbsolute()) << "device=" << device;

  uint64_t size;
  if (!GetBlkSize(device, &size)) {
    LOG(ERROR) << "Failed to get device size";
    return false;
  }

  uint64_t range[2] = {0, size};

  base::ScopedFD fd(
      HANDLE_EINTR(open(device.value().c_str(), O_RDWR | O_CLOEXEC)));

  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to open device " << device;
    return false;
  }

  if (ioctl(fd.get(), BLKDISCARD, &range)) {
    LOG(ERROR) << "Failed to discard device " << device;
    return false;
  }

  return true;
}

std::vector<Platform::LoopDevice> Platform::GetAttachedLoopDevices() {
  std::vector<LoopDevice> devices;
  for (const auto& device : GetLoopDeviceManager()->GetAttachedDevices()) {
    devices.push_back({device->GetBackingFilePath(), device->GetDevicePath()});
  }
  return devices;
}

bool Platform::FormatExt4(const base::FilePath& file,
                          const std::vector<std::string>& opts,
                          uint64_t blocks) {
  DCHECK(file.IsAbsolute()) << "file=" << file;

  brillo::ProcessImpl format_process;
  format_process.AddArg("/sbin/mkfs.ext4");

  for (const auto& arg : opts)
    format_process.AddArg(arg);

  format_process.AddArg(file.value());
  if (blocks != 0)
    format_process.AddArg(std::to_string(blocks));

  // No need to emit output.
  format_process.AddArg("-q");

  // Close unused file descriptors in child process.
  format_process.SetCloseUnusedFileDescriptors(true);

  // Avoid polluting the parent process' stdout.
  format_process.RedirectOutput("/dev/null");

  int rc = format_process.Run();
  if (rc != 0) {
    LOG(ERROR) << "Can't format '" << file.value()
               << "' as ext4, exit status: " << rc;
    return false;
  }

  // Tune the formatted filesystem:
  // -c 0: Disable max mount count checking.
  // -i 0: Disable filesystem checking.
  return Tune2Fs(file, {"-c", "0", "-i", "0"});
}

bool Platform::Tune2Fs(const base::FilePath& file,
                       const std::vector<std::string>& opts) {
  DCHECK(file.IsAbsolute()) << "file=" << file;

  brillo::ProcessImpl tune_process;
  tune_process.AddArg("/sbin/tune2fs");
  for (const auto& arg : opts)
    tune_process.AddArg(arg);

  tune_process.AddArg(file.value());

  // Close unused file descriptors in child process.
  tune_process.SetCloseUnusedFileDescriptors(true);

  // Avoid polluting the parent process' stdout.
  tune_process.RedirectOutput("/dev/null");

  int rc = tune_process.Run();
  if (rc != 0) {
    LOG(ERROR) << "Can't tune ext4: " << file.value() << ", error: " << rc;
    return false;
  }
  return true;
}

bool Platform::ResizeFilesystem(const base::FilePath& file, uint64_t blocks) {
  DCHECK(file.IsAbsolute()) << "file=" << file;

  brillo::ProcessImpl resize_process;
  resize_process.AddArg("/sbin/resize2fs");
  resize_process.AddArg("-f");
  resize_process.AddArg(file.value().c_str());
  resize_process.AddArg(std::to_string(blocks));

  // Close unused file descriptors in child process.
  resize_process.SetCloseUnusedFileDescriptors(true);

  // Start the process and return.
  LOG(INFO) << "Resizing filesystem on " << file.value() << " to " << blocks;
  int rc = resize_process.Run();
  if (rc != 0)
    return false;

  LOG(INFO) << "Resizing process started.";
  return true;
}

bool Platform::RestoreSELinuxContexts(const base::FilePath& path,
                                      bool recursive) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

#if USE_SELINUX
  LOG(INFO) << "Restoring SELinux contexts for: " << path.value()
            << ", recursive=" << std::boolalpha << recursive;
  int restorecon_flag = 0;
  if (recursive)
    restorecon_flag |= SELINUX_RESTORECON_RECURSE;
  if (selinux_restorecon(path.value().c_str(), restorecon_flag) != 0) {
    PLOG(ERROR) << "restorecon(" << path.value() << ") failed";
    return false;
  }
#endif
  return true;
}

void Platform::AddGlobalSELinuxRestoreconExclusion(
    const std::vector<base::FilePath>& exclude) {
#if USE_SELINUX
  if (!exclude.empty()) {
    // Initialize the array to size of exclude and one more for NULL delimiter
    // at the end.
    std::vector<const char*> exclude_cstring(exclude.size() + 1);
    std::transform(exclude.begin(), exclude.end(), exclude_cstring.begin(),
                   [](const base::FilePath& path) -> const char* {
                     return path.value().c_str();
                   });
    selinux_restorecon_set_exclude_list(exclude_cstring.data());
  }
#endif
}

std::optional<std::string> Platform::GetSELinuxContextOfFD(int fd) {
#if USE_SELINUX
  char* con = nullptr;
  if (fgetfilecon(fd, &con) < 0) {
    PLOG(ERROR) << "fgetfilecon failed";
    return std::nullopt;
  }
  std::string result = con;
  freecon(con);
  return result;
#else
  return std::string();
#endif
}

bool Platform::SetSELinuxContext(const base::FilePath& path,
                                 const std::string& context) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

#if USE_SELINUX
  int result = setfilecon(path.value().c_str(), context.c_str());
  if (result != 0) {
    LOG(ERROR) << "Failed to set SELinux context for " << path
               << ", errno = " << errno;
    return false;
  }
#else
  LOG(WARNING)
      << "Try to set SELinux context when SELinux is disabled at compile time.";
#endif
  return true;
}

bool Platform::SetupProcessKeyring() {
  // We have patched upstart to set up a session keyring in init.
  // This results in the user keyring not present under the session keyring and
  // it breaks eCryptfs. Set up a process keyring and link the user keyring to
  // it to fix this.
  if (keyctl_link(KEY_SPEC_USER_KEYRING, KEY_SPEC_PROCESS_KEYRING)) {
    PLOG(ERROR) << "Failed to link the user keyring to the process keyring.";
    return false;
  }
  // When we have a process keyring, it hides the session keyring and it breaks
  // ext4 encryption.
  // Link the session keyring to the process keyring so that request_key() can
  // find keys under the session keyring too.
  if (keyctl_link(KEY_SPEC_SESSION_KEYRING, KEY_SPEC_PROCESS_KEYRING)) {
    PLOG(ERROR) << "Failed to link the session keyring to the process keyring.";
    return false;
  }
  return true;
}

dircrypto::KeyState Platform::GetDirCryptoKeyState(const FilePath& dir) {
  DCHECK(dir.IsAbsolute()) << "dir=" << dir;

  return dircrypto::GetDirectoryKeyState(dir);
}

bool Platform::SetDirCryptoKey(const FilePath& dir,
                               const dircrypto::KeyReference& key_reference) {
  DCHECK(dir.IsAbsolute()) << "dir=" << dir;

  return dircrypto::SetDirectoryKey(dir, key_reference);
}

int Platform::GetDirectoryPolicyVersion(const base::FilePath& dir) const {
  DCHECK(dir.IsAbsolute()) << "dir=" << dir;

  return dircrypto::GetDirectoryPolicyVersion(dir);
}

bool Platform::InvalidateDirCryptoKey(
    const dircrypto::KeyReference& key_reference, const FilePath& shadow_root) {
  DCHECK(shadow_root.IsAbsolute()) << "shadow_root=" << shadow_root;

  return dircrypto::RemoveDirectoryKey(key_reference, shadow_root);
}

bool Platform::CheckFscryptKeyIoctlSupport() const {
  return dircrypto::CheckFscryptKeyIoctlSupport();
}

bool Platform::ClearUserKeyring() {
  /* Flush cache to prevent corruption */
  return (keyctl(KEYCTL_CLEAR, KEY_SPEC_USER_KEYRING) == 0);
}

FileEnumerator* Platform::GetFileEnumerator(const FilePath& root_path,
                                            bool recursive,
                                            int file_type) {
  DCHECK(root_path.IsAbsolute()) << "root_path=" << root_path;

  return new FileEnumerator(root_path, recursive, file_type);
}

template <class T>
bool Platform::ReadFileToBlob(const FilePath& path, T* blob) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  int64_t file_size;
  if (!base::PathExists(path)) {
    return false;
  }
  if (!base::GetFileSize(path, &file_size)) {
    LOG(ERROR) << "Could not get size of " << path.value();
    return false;
  }
  // Compare to the max of a signed integer.
  if (file_size > static_cast<int64_t>(std::numeric_limits<int>::max())) {
    LOG(ERROR) << "File " << path.value() << " is too large: " << file_size
               << " bytes.";
    return false;
  }
  blob->resize(file_size);
  int data_read =
      base::ReadFile(path, reinterpret_cast<char*>(blob->data()), blob->size());
  // Cast is okay because of comparison to INT_MAX above.
  if (data_read != static_cast<int>(file_size)) {
    LOG(ERROR) << "Only read " << data_read << " of " << file_size << " bytes"
               << " from " << path.value() << ".";
    return false;
  }
  VerifyChecksum(path, blob->data(), blob->size());
  return true;
}

std::string Platform::GetChecksum(const void* input, size_t input_size) {
  uint32_t sum = Crc32(input, input_size);
  return base::HexEncode(&sum, 4);
}

void Platform::WriteChecksum(const FilePath& path,
                             const void* content,
                             const size_t content_size,
                             mode_t mode) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  FilePath name = path.AddExtension(kChecksumExtension);
  WriteStringToFileAtomic(name, GetChecksum(content, content_size), mode);
}

void Platform::VerifyChecksum(const FilePath& path,
                              const void* content,
                              const size_t content_size) {
  DCHECK(path.IsAbsolute()) << "path=" << path;

  // Exclude some system paths.
  std::string path_value = path.value();
  if (base::StartsWith(path_value, "/etc", base::CompareCase::SENSITIVE) ||
      base::StartsWith(path_value, "/dev", base::CompareCase::SENSITIVE) ||
      base::StartsWith(path_value, "/sys", base::CompareCase::SENSITIVE) ||
      base::StartsWith(path_value, "/proc", base::CompareCase::SENSITIVE)) {
    return;
  }
  FilePath name = path.AddExtension(kChecksumExtension);
  if (!FileExists(name)) {
    return;
  }
  std::string saved_sum;
  if (!base::ReadFileToString(name, &saved_sum)) {
    LOG(ERROR) << "CHECKSUM: Failed to read checksum for " << path.value();
    return;
  }
  if (saved_sum != GetChecksum(content, content_size)) {
    // Check if the last modified time is out-of-sync for the two files. If they
    // weren't written together they can't be expected to match.
    base::File::Info content_file_info;
    base::File::Info checksum_file_info;
    if (!base::GetFileInfo(path, &content_file_info) ||
        !base::GetFileInfo(name, &checksum_file_info)) {
      LOG(ERROR) << "CHECKSUM: Failed to read file info for " << path.value();
      return;
    }
    base::TimeDelta checksum_timestamp_diff =
        checksum_file_info.last_modified - content_file_info.last_modified;
    if (checksum_timestamp_diff.magnitude().InSeconds() > 1) {
      LOG(ERROR) << "CHECKSUM: Checksum out-of-sync for " << path.value();
    } else {
      LOG(ERROR) << "CHECKSUM: Failed to verify checksum for " << path.value();
    }
    // Attempt to update the checksum to match the current content.
    mode_t current_mode;
    if (GetPermissions(name, &current_mode)) {
      WriteChecksum(path, content, content_size, current_mode);
    }
    return;
  }
}

FileEnumerator::FileInfo::FileInfo(
    const base::FileEnumerator::FileInfo& file_info) {
  Assign(file_info);
}

FileEnumerator::FileInfo::FileInfo(const FilePath& name,
                                   const base::stat_wrapper_t& stat)
    : name_(name), stat_(stat) {}

FileEnumerator::FileInfo::FileInfo(const FileEnumerator::FileInfo& other) {
  if (other.info_.get()) {
    Assign(*other.info_);
  } else {
    info_.reset();
    name_ = other.name_;
    stat_ = other.stat_;
  }
}

FileEnumerator::FileInfo::FileInfo() {
  Assign(base::FileEnumerator::FileInfo());
}

FileEnumerator::FileInfo::~FileInfo() {}

FileEnumerator::FileInfo& FileEnumerator::FileInfo::operator=(
    const FileEnumerator::FileInfo& other) {
  if (other.info_.get()) {
    Assign(*other.info_);
  } else {
    info_.reset();
    name_ = other.name_;
    stat_ = other.stat_;
  }
  return *this;
}

bool FileEnumerator::FileInfo::IsDirectory() const {
  if (info_.get())
    return info_->IsDirectory();
  return ::IsDirectory(stat_);
}

FilePath FileEnumerator::FileInfo::GetName() const {
  if (info_.get())
    return info_->GetName();
  return name_;
}

int64_t FileEnumerator::FileInfo::GetSize() const {
  if (info_.get())
    return info_->GetSize();
  return stat_.st_size;
}

base::Time FileEnumerator::FileInfo::GetLastModifiedTime() const {
  if (info_.get())
    return info_->GetLastModifiedTime();
  return base::Time::FromTimeT(stat_.st_mtime);
}

const base::stat_wrapper_t& FileEnumerator::FileInfo::stat() const {
  if (info_.get())
    return info_->stat();
  return stat_;
}

void FileEnumerator::FileInfo::Assign(
    const base::FileEnumerator::FileInfo& file_info) {
  info_ = std::make_unique<base::FileEnumerator::FileInfo>(file_info);
  memset(&stat_, 0, sizeof(stat_));
}

FileEnumerator::FileEnumerator(const FilePath& root_path,
                               bool recursive,
                               int file_type) {
  DCHECK(root_path.IsAbsolute()) << "root_path=" << root_path;

  enumerator_ =
      std::make_unique<base::FileEnumerator>(root_path, recursive, file_type);
}

FileEnumerator::FileEnumerator(const FilePath& root_path,
                               bool recursive,
                               int file_type,
                               const std::string& pattern) {
  DCHECK(root_path.IsAbsolute()) << "root_path=" << root_path;

  enumerator_ = std::make_unique<base::FileEnumerator>(root_path, recursive,
                                                       file_type, pattern);
}

FileEnumerator::FileEnumerator() = default;
FileEnumerator::~FileEnumerator() = default;

FilePath FileEnumerator::Next() {
  if (!enumerator_.get())
    return FilePath();
  return enumerator_->Next();
}

FileEnumerator::FileInfo FileEnumerator::GetInfo() {
  return FileInfo(enumerator_->GetInfo());
}

}  // namespace cryptohome
