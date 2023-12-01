// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include <base/containers/contains.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/blkdev_utils/storage_utils.h>
#include <brillo/files/file_util.h>
#include <brillo/key_value_store.h>
#include <brillo/process/process.h>

#include "init/clobber_state.h"
#include "init/crossystem.h"
#include "init/crossystem_impl.h"
#include "init/startup/platform_impl.h"
#include "init/utils.h"

namespace {

constexpr char kProcCmdLine[] = "proc/cmdline";
constexpr char kFactoryDir[] = "mnt/stateful_partition/dev_image/factory";
constexpr char kProcFilesystems[] = "proc/filesystems";

const size_t kMaxReadSize = 4 * 1024;

}  // namespace

namespace startup {

bool Platform::Stat(const base::FilePath& path, struct stat* st) {
  return stat(path.value().c_str(), st) == 0;
}

bool Platform::Statvfs(const base::FilePath& path, struct statvfs* st) {
  return statvfs(path.value().c_str(), st) == 0;
}

bool Platform::Mount(const base::FilePath& src,
                     const base::FilePath& dst,
                     const std::string& type,
                     const unsigned long flags,  // NOLINT(runtime/int)
                     const std::string& data) {
  return mount(src.value().c_str(), dst.value().c_str(), type.c_str(), flags,
               data.c_str()) == 0;
}

bool Platform::Mount(const std::string& src,
                     const base::FilePath& dst,
                     const std::string& type,
                     const unsigned long flags,  // NOLINT(runtime/int)
                     const std::string& data) {
  return mount(src.c_str(), dst.value().c_str(), type.c_str(), flags,
               data.c_str()) == 0;
}

bool Platform::Umount(const base::FilePath& path) {
  return !umount(path.value().c_str());
}

base::ScopedFD Platform::Open(const base::FilePath& pathname, int flags) {
  return base::ScopedFD(HANDLE_EINTR(open(pathname.value().c_str(), flags)));
}

// NOLINTNEXTLINE(runtime/int)
int Platform::Ioctl(int fd, unsigned long request, int* arg1) {
  return ioctl(fd, request, arg1);
}

bool Platform::Fchown(int fd, uid_t owner, gid_t group) {
  return fchown(fd, owner, group) == 0;
}

int Platform::MountEncrypted(const std::vector<std::string>& args,
                             std::string* output) {
  brillo::ProcessImpl mount_enc;
  mount_enc.AddArg("/usr/sbin/mount-encrypted");
  for (auto arg : args) {
    mount_enc.AddArg(arg);
  }
  if (output) {
    mount_enc.RedirectUsingMemory(STDOUT_FILENO);
  }

  int status = mount_enc.Run();
  if (output) {
    *output = mount_enc.GetOutputString(STDOUT_FILENO);
  }
  return status;
}

void Platform::BootAlert(const std::string& arg) {
  brillo::ProcessImpl boot_alert;
  boot_alert.AddArg("/sbin/chromeos-boot-alert");
  boot_alert.AddArg(arg);
  int ret = boot_alert.Run();
  if (ret != 0) {
    PLOG(WARNING) << "chromeos-boot-alert failed with code " << ret;
  }
}

[[noreturn]] void Platform::Clobber(const std::vector<std::string> args) {
  brillo::ProcessImpl clobber;
  clobber.AddArg("/sbin/clobber-state");

  // Clobber should not be called with empty args, but to ensure that is
  // the case, use "keepimg" if nothing is specified.
  if (args.empty()) {
    clobber.AddArg("keepimg");
  } else {
    for (const std::string& arg : args) {
      clobber.AddArg(arg);
    }
  }

  int ret = clobber.Run();
  CHECK_NE(ret, 0);
  PLOG(ERROR) << "unable to run clobber-state; ret=" << ret;
  exit(1);
}

bool Platform::VpdSlow(const std::vector<std::string>& args,
                       std::string* output) {
  brillo::ProcessImpl vpd;
  vpd.AddArg("/usr/sbin/vpd");
  for (const std::string& arg : args) {
    vpd.AddArg(arg);
  }
  vpd.RedirectUsingMemory(STDOUT_FILENO);

  if (vpd.Run() == 0) {
    *output = vpd.GetOutputString(STDOUT_FILENO);
    return true;
  }
  return false;
}

void Platform::ClobberLog(const std::string& msg) {
  brillo::ProcessImpl log;
  log.AddArg("/sbin/clobber-log");
  log.AddArg("--");
  log.AddArg(msg);
  if (log.Run() != 0) {
    LOG(WARNING) << "clobber-log failed for message: " << msg;
  }
}

void Platform::Clobber(const std::string& boot_alert_msg,
                       const std::vector<std::string>& args,
                       const std::string& clobber_log_msg) {
  BootAlert(boot_alert_msg);
  ClobberLog(clobber_log_msg);
  Clobber(args);
}

void Platform::RemoveInBackground(const std::vector<base::FilePath>& paths) {
  pid_t pid = fork();
  if (pid == 0) {
    for (auto path : paths) {
      brillo::DeletePathRecursively(path);
    }
    exit(0);
  }
}

// Run command, cmd_path.
void Platform::RunProcess(const base::FilePath& cmd_path) {
  brillo::ProcessImpl proc;
  proc.AddArg(cmd_path.value());
  if (proc.Run() != 0) {
    PLOG(WARNING) << "Failed to run " << cmd_path.value();
  }
}

bool Platform::RunHiberman(const base::FilePath& output_file) {
  brillo::ProcessImpl hiberman;
  hiberman.AddArg("/usr/sbin/hiberman");
  hiberman.AddArg("resume-init");
  hiberman.AddArg("-v");
  hiberman.RedirectOutput(output_file.value());
  int ret = hiberman.Run();
  if (ret != 0) {
    PLOG(WARNING) << "hiberman failed with code " << ret;
    return false;
  }
  return true;
}

void Platform::AddClobberCrashReport(const std::vector<std::string> args) {
  brillo::ProcessImpl crash;
  crash.AddArg("/sbin/crash_reporter");
  crash.AddArg("--early");
  crash.AddArg("--log_to_stderr");
  for (auto arg : args) {
    crash.AddArg(arg);
  }
  int ret = crash.Run();
  if (ret != 0) {
    PLOG(WARNING) << "crash_reporter failed with code " << ret;
    return;
  }

  // TODO(sarthakkukreti): Delete this since clobbering handles things.
  sync();
}

std::optional<base::FilePath> Platform::GetRootDevicePartitionPath(
    const std::string& partition_label) {
  base::FilePath root_dev;
  if (!utils::GetRootDevice(&root_dev, /*strip_partition=*/true)) {
    LOG(WARNING) << "Unable to get root device";
    return std::nullopt;
  }

  const int esp_partition_num =
      utils::GetPartitionNumber(root_dev, partition_label);
  if (esp_partition_num == -1) {
    LOG(WARNING) << "Unable to get partition number for label "
                 << partition_label;
    return std::nullopt;
  }

  return brillo::AppendPartition(root_dev, esp_partition_num);
}

void Platform::ReplayExt4Journal(const base::FilePath& dev) {
  brillo::ProcessImpl e2fsck;
  e2fsck.AddArg("/sbin/e2fsck");
  e2fsck.AddArg("-p");
  e2fsck.AddArg("-E");
  e2fsck.AddArg("journal_only");
  e2fsck.AddArg(dev.value());
  int ret = e2fsck.Run();
  if (ret != 0) {
    PLOG(WARNING) << "e2fsck failed with code " << ret;
  }
}

void Platform::ClobberLogRepair(const base::FilePath& dev,
                                const std::string& msg) {
  brillo::ProcessImpl log_repair;
  log_repair.AddArg("/sbin/clobber-log");
  log_repair.AddArg("--repair");
  log_repair.AddArg(dev.value());
  log_repair.AddArg(msg);
  int status = log_repair.Run();
  if (status != 0) {
    PLOG(WARNING) << "Repairing clobber.log failed with code " << status;
  }
}

// Returns if we are running on a debug build.
bool Platform::IsDebugBuild(CrosSystem* const cros_system) {
  int debug;
  if (cros_system->GetInt("debug_build", &debug) && debug == 1) {
    return true;
  } else {
    return false;
  }
}

// Determine if the device is in dev mode.
bool Platform::InDevMode(CrosSystem* cros_system) {
  // cros_debug equals one if we've booted in developer mode or we've booted
  // a developer image.
  int debug;
  return (cros_system->GetInt("cros_debug", &debug) && debug == 1);
}

// Determine if the device is using a test image.
bool IsTestImage(const base::FilePath& lsb_file) {
  brillo::KeyValueStore store;
  if (!store.Load(lsb_file)) {
    PLOG(ERROR) << "Problem parsing " << lsb_file.value();
    return false;
  }
  std::string value;
  if (!store.GetString("CHROMEOS_RELEASE_TRACK", &value)) {
    PLOG(ERROR) << "CHROMEOS_RELEASE_TRACK not found in " << lsb_file.value();
    return false;
  }
  return base::StartsWith(value, "test", base::CompareCase::SENSITIVE);
}

// Return if the device is in factory test mode.
bool IsFactoryTestMode(CrosSystem* cros_system,
                       const base::FilePath& base_dir) {
  // The path to factory enabled tag. If this path exists in a debug build,
  // we assume factory test mode.
  base::FilePath factory_dir = base_dir.Append(kFactoryDir);
  base::FilePath factory_tag = factory_dir.Append("enabled");
  struct stat statbuf;
  int res;
  if (cros_system->GetInt("debug_build", &res) && res == 1 &&
      stat(factory_tag.value().c_str(), &statbuf) == 0 &&
      S_ISREG(statbuf.st_mode)) {
    return true;
  }
  return false;
}

// Return if the device is in factory installer mode.
bool IsFactoryInstallerMode(const base::FilePath& base_dir) {
  std::string cmdline;

  if (!base::ReadFileToStringWithMaxSize(base_dir.Append(kProcCmdLine),
                                         &cmdline, kMaxReadSize)) {
    PLOG(ERROR) << "Failed to read proc command line";
    return false;
  }

  if (cmdline.find("cros_factory_install") != std::string::npos) {
    return true;
  }

  struct stat statbuf;
  base::FilePath installer = base_dir.Append("root/.factory_installer");
  if (stat(installer.value().c_str(), &statbuf) == 0 &&
      S_ISREG(statbuf.st_mode)) {
    return true;
  }
  return false;
}

// Return if the device is in either in factory test mode or in factory
// installer mode.
bool IsFactoryMode(CrosSystem* cros_system, const base::FilePath& base_dir) {
  return (IsFactoryTestMode(cros_system, base_dir) ||
          IsFactoryInstallerMode(base_dir));
}

// Determines if a filesystem is supported.
// False if there's an error checking or if the filesystem isn't supported,
// true if the filesystem is supported.
bool IsSupportedFilesystem(const std::string& filesystem,
                           const base::FilePath& base_dir) {
  // List of supported filesystems, along with indicators like "nodev".
  // See /proc/filesystems under `man 5 proc`.
  const base::FilePath filesystems = base_dir.Append(kProcFilesystems);

  std::string filesystems_content;
  if (!base::ReadFileToString(filesystems, &filesystems_content)) {
    PLOG(ERROR) << "Failed to read " << kProcFilesystems;
    return false;
  }
  const auto supported_filesystems =
      base::SplitStringPiece(filesystems_content, base::kWhitespaceASCII,
                             base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  return base::Contains(supported_filesystems, filesystem);
}

}  // namespace startup
