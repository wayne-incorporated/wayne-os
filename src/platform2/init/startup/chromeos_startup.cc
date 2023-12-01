// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <filesystem>
#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/files/file_util.h>
#include <brillo/process/process.h>
#include <brillo/strings/string_utils.h>
#include <brillo/userdb_utils.h>

#include "init/crossystem.h"
#include "init/crossystem_impl.h"
#include "init/file_attrs_cleaner.h"
#include "init/startup/chromeos_startup.h"
#include "init/startup/constants.h"
#include "init/startup/factory_mode_mount_helper.h"
#include "init/startup/flags.h"
#include "init/startup/mount_helper.h"
#include "init/startup/mount_helper_factory.h"
#include "init/startup/platform_impl.h"
#include "init/startup/security_manager.h"
#include "init/startup/standard_mount_helper.h"
#include "init/startup/stateful_mount.h"
#include "init/startup/test_mode_mount_helper.h"
#include "init/startup/uefi_startup.h"
#include "init/utils.h"

namespace {

constexpr char kHome[] = "home";
constexpr char kUnencrypted[] = "unencrypted";
constexpr char kVar[] = "var";
constexpr char kVarLog[] = "var/log";
constexpr char kChronos[] = "chronos";
constexpr char kUser[] = "user";
constexpr char kRoot[] = "root";

// The "/." ensures we trigger the automount, instead of just examining the
// mount point.
// TODO(b/244186883): remove this.
constexpr char kKernelDebugTracingDir[] = "kernel/debug/tracing/.";

constexpr char kRunNamespaces[] = "run/namespaces";
constexpr char kRun[] = "run";
constexpr char kLock[] = "lock";
constexpr char kEmpty[] = "empty";
constexpr char kMedia[] = "media";
constexpr char kSysfs[] = "sys";

constexpr char kKernelConfig[] = "kernel/config";
constexpr char kKernelDebug[] = "kernel/debug";
constexpr char kKernelSecurity[] = "kernel/security";
constexpr char kKernelTracing[] = "kernel/tracing";

constexpr char kTpmSimulator[] = "etc/init/tpm2-simulator.conf";

constexpr char kSELinuxEnforce[] = "fs/selinux/enforce";

// This file is created by clobber-state after the transition to dev mode.
constexpr char kDevModeFile[] = ".developer_mode";
// Flag file indicating that encrypted stateful should be preserved across
// TPM clear. If the file is present, it's expected that TPM is not owned.
constexpr char kPreservationRequestFile[] = "preservation_request";
// This file is created after the TPM is initialized and the device is owned.
constexpr char kInstallAttributesFile[] = "home/.shadow/install_attributes.pb";
// File used to trigger a stateful reset. Contains arguments for the
// clobber-state" call. This file may exist at boot time, as some use cases
// operate by creating this file with the necessary arguments and then
// rebooting.
constexpr char kResetFile[] = "factory_install_reset";
// Flag file indicating that mount encrypted stateful failed last time.
// If the file is present and mount_encrypted failed again, machine would
// enter self-repair mode.
constexpr char kMountEncryptedFailedFile[] = "mount_encrypted_failed";
// kEncryptedStatefulMnt stores the path to the initial mount point for
// the encrypted stateful partition
constexpr char kEncryptedStatefulMnt[] = "encrypted";
// This file is written to when /var is too full and the logs are deleted.
constexpr char kReclaimFullVar[] = ".reclaim_full_var";
// This value is threshold for determining that /var is full.
const int kVarFullThreshold = 10485760;

constexpr char kDaemonStore[] = "daemon-store";
constexpr char kEtc[] = "etc";

constexpr char kDisableStatefulSecurityHard[] =
    "usr/share/cros/startup/disable_stateful_security_hardening";
constexpr char kDebugfsAccessGrp[] = "debugfs-access";

constexpr char kTpmFirmwareUpdateCleanup[] =
    "usr/sbin/tpm-firmware-update-cleanup";
constexpr char kTpmFirmwareUpdateRequestFlagFile[] =
    "unencrypted/preserve/tpm_firmware_update_request";

constexpr char kLibWhitelist[] = "lib/whitelist";
constexpr char kLibDevicesettings[] = "lib/devicesettings";

constexpr char kPreserve[] = "preserve";
const std::array<const char*, 4> kPreserveDirs = {
    "var/lib/servod",
    "usr/local/servod",
    "var/lib/device_health_profile",
    "usr/local/etc/wifi_creds",
};

}  // namespace

namespace startup {

// Process the arguments from included USE flags.
void ChromeosStartup::ParseFlags(Flags* flags) {
  flags->direncryption = USE_DIRENCRYPTION;
  flags->fsverity = USE_FSVERITY;
  flags->prjquota = USE_PRJQUOTA;
  flags->encstateful = USE_ENCRYPTED_STATEFUL;
  if (flags->encstateful) {
    flags->sys_key_util = USE_TPM2;
  }
  // Note: encrypted_reboot_vault is disabled only for Gale
  // to be able to use openssl 1.1.1.
  flags->encrypted_reboot_vault = USE_ENCRYPTED_REBOOT_VAULT;
  flags->lvm_stateful = USE_LVM_STATEFUL_PARTITION;
}

// We manage this base timestamp by hand. It isolates us from bad clocks on
// the system where this image was built/modified, and on the runtime image
// (in case a dev modified random paths while the clock was out of sync).
// TODO(b/234157809): Our namespaces module doesn't support time namespaces
// currently. Add unittests for CheckClock once we add support.
void ChromeosStartup::CheckClock() {
  time_t cur_time;
  time(&cur_time);

  if (cur_time < kBaseSecs) {
    struct timespec stime;
    stime.tv_sec = kBaseSecs;
    stime.tv_nsec = 0;
    if (clock_settime(CLOCK_REALTIME, &stime) != 0) {
      // TODO(b/232901639): Improve failure reporting.
      PLOG(WARNING) << "Unable to set time.";
    }
  }
}

void ChromeosStartup::Sysctl() {
  // Initialize kernel sysctl settings early so that they take effect for boot
  // processes.
  brillo::ProcessImpl proc;
  proc.AddArg("/usr/sbin/sysctl");
  proc.AddArg("-q");
  proc.AddArg("--system");
  int status = proc.Run();
  if (status != 0) {
    LOG(WARNING) << "Failed to initialize kernel sysctl settings.";
  }
}

// Returns if the TPM is owned or couldn't determine.
bool ChromeosStartup::IsTPMOwned() {
  int output = 0;
  base::FilePath owned = root_.Append(kTPMOwnedPath);
  // Check file contents
  if (!utils::ReadFileToInt(owned, &output)) {
    PLOG(WARNING) << "Could not determine TPM owned, failed to read "
                  << owned.value();
    return true;
  }
  if (output == 0) {
    return false;
  }
  return true;
}

// Returns if device needs to clobber even though there's no devmode file
// present and boot is in verified mode.
bool ChromeosStartup::NeedsClobberWithoutDevModeFile() {
  base::FilePath preservation_request =
      stateful_.Append(kPreservationRequestFile);
  base::FilePath install_attrs = stateful_.Append(kInstallAttributesFile);
  struct stat statbuf;
  if (!IsTPMOwned() &&
      (!platform_->Stat(preservation_request, &statbuf) ||
       statbuf.st_uid != getuid()) &&
      (platform_->Stat(install_attrs, &statbuf) &&
       statbuf.st_uid == getuid())) {
    return true;
  }
  return false;
}

// Returns if the device is in transitioning between verified boot and dev mode.
// devsw_boot is the expected value of devsw_boot.
bool ChromeosStartup::IsDevToVerifiedModeTransition(int devsw_boot) {
  int boot;
  std::string dstr;
  return (cros_system_->GetInt("devsw_boot", &boot) && boot == devsw_boot) &&
         (cros_system_->GetString("mainfw_type", &dstr) && dstr != "recovery");
}

// Walk the specified path and reset any file attributes (like immutable bit).
void ChromeosStartup::ForceCleanFileAttrs(const base::FilePath& path) {
  // No physical stateful partition available, usually due to initramfs
  // (recovery image, factory install shim or netboot. Do not check.
  if (state_dev_.empty()) {
    return;
  }

  std::vector<std::string> skip;
  bool status = file_attrs_cleaner::ScanDir(path.value(), skip);

  if (!status) {
    std::vector<std::string> args = {"keepimg"};
    platform_->Clobber(
        "self-repair", args,
        std::string("Bad file attrs under ").append(path.value()));
  }
}

// Checks if /var is close to being full.
// Returns true if there is less than 10MB of free space left in /var or if
// there are less than 100 inodes available on the underlying filesystem.
bool ChromeosStartup::IsVarFull() {
  struct statvfs st;
  base::FilePath var = root_.Append(kVar);
  if (!platform_->Statvfs(var, &st)) {
    PLOG(WARNING) << "Failed statvfs " << var.value();
    return false;
  }

  return (st.f_bavail < kVarFullThreshold / st.f_bsize || st.f_favail < 100);
}

ChromeosStartup::ChromeosStartup(std::unique_ptr<CrosSystem> cros_system,
                                 const Flags& flags,
                                 const base::FilePath& root,
                                 const base::FilePath& stateful,
                                 const base::FilePath& lsb_file,
                                 const base::FilePath& proc_file,
                                 std::unique_ptr<Platform> platform,
                                 std::unique_ptr<MountHelper> mount_helper)
    : cros_system_(std::move(cros_system)),
      flags_(flags),
      lsb_file_(lsb_file),
      proc_(proc_file),
      root_(root),
      stateful_(stateful),
      platform_(std::move(platform)),
      mount_helper_(std::move(mount_helper)) {}

void ChromeosStartup::EarlySetup() {
  const base::FilePath sysfs = root_.Append(kSysfs);
  gid_t debugfs_grp;
  if (!brillo::userdb::GetGroupInfo(kDebugfsAccessGrp, &debugfs_grp)) {
    PLOG(WARNING) << "Can't get gid for " << kDebugfsAccessGrp;
  } else {
    char data[25];
    snprintf(data, sizeof(data), "mode=0750,uid=0,gid=%d", debugfs_grp);
    const base::FilePath debug = sysfs.Append(kKernelDebug);
    if (!platform_->Mount("debugfs", debug, "debugfs", kCommonMountFlags,
                          data)) {
      // TODO(b/232901639): Improve failure reporting.
      PLOG(WARNING) << "Unable to mount " << debug.value();
    }
  }

  // HACK(b/244186883): ensure we trigger the /sys/kernel/debug/tracing
  // automount now (before we set 0755 below), because otherwise the kernel may
  // change its permissions whenever it eventually does get automounted.
  // TODO(b/244186883): remove this.
  struct stat st;
  const base::FilePath debug_tracing = sysfs.Append(kKernelDebugTracingDir);
  // Ignore errors.
  platform_->Stat(debug_tracing, &st);

  // Mount tracefs at /sys/kernel/tracing. On older kernels, tracing was part
  // of debugfs and was present at /sys/kernel/debug/tracing. Newer kernels
  // continue to automount it there when accessed via
  // /sys/kernel/debug/tracing/, but we avoid that where possible, to limit our
  // dependence on debugfs.
  const base::FilePath tracefs = sysfs.Append(kKernelTracing);
  // All users may need to access the tracing directory.
  if (!platform_->Mount("tracefs", tracefs, "tracefs", kCommonMountFlags,
                        "mode=0755")) {
    // TODO(b/232901639): Improve failure reporting.
    PLOG(WARNING) << "Unable to mount " << tracefs.value();
  }

  // Mount configfs, if present.
  const base::FilePath configfs = sysfs.Append(kKernelConfig);
  if (base::DirectoryExists(configfs)) {
    if (!platform_->Mount("configfs", configfs, "configfs", kCommonMountFlags,
                          "")) {
      // TODO(b/232901639): Improve failure reporting.
      PLOG(WARNING) << "Unable to mount " << configfs.value();
    }
  }

  // Mount securityfs as it is used to configure inode security policies below.
  const base::FilePath securityfs = sysfs.Append(kKernelSecurity);
  if (!platform_->Mount("securityfs", securityfs, "securityfs",
                        kCommonMountFlags, "")) {
    // TODO(b/232901639): Improve failure reporting.
    PLOG(WARNING) << "Unable to mount " << securityfs.value();
  }

  if (!SetupLoadPinVerityDigests(root_, platform_.get())) {
    LOG(WARNING) << "Failed to setup LoadPin verity digests.";
  }

  // Initialize kernel sysctl settings early so that they take effect for boot
  // processes.
  Sysctl();

  // Protect a bind mount to the Chrome mount namespace.
  const base::FilePath namespaces = root_.Append(kRunNamespaces);
  if (!platform_->Mount(namespaces, namespaces, "", MS_BIND, "") ||
      !platform_->Mount(base::FilePath(), namespaces, "", MS_PRIVATE, "")) {
    PLOG(WARNING) << "Unable to mount " << namespaces.value();
  }

  const base::FilePath disable_sec_hard =
      root_.Append(kDisableStatefulSecurityHard);
  enable_stateful_security_hardening_ = !base::PathExists(disable_sec_hard);
  if (!enable_stateful_security_hardening_ &&
      !ConfigureProcessMgmtSecurity(root_)) {
    PLOG(WARNING) << "Failed to configure process management security.";
  }
}

// Apply /mnt/stateful_partition specific tmpfiles.d configurations
void ChromeosStartup::TmpfilesConfiguration(
    const std::vector<std::string>& dirs) {
  brillo::ProcessImpl tmpfiles;
  tmpfiles.AddArg("/usr/bin/systemd-tmpfiles");
  tmpfiles.AddArg("--create");
  tmpfiles.AddArg("--remove");
  tmpfiles.AddArg("--boot");
  for (std::string path : dirs) {
    tmpfiles.AddArg("--prefix");
    tmpfiles.AddArg(path);
  }
  if (tmpfiles.Run() != 0) {
    std::string msg =
        "tmpfiles.d failed for " + brillo::string_utils::Join(",", dirs);
    mount_helper_->CleanupMounts(msg);
  }
}

// Check for whether we need a stateful wipe, and alert the user as
// necessary.
void ChromeosStartup::CheckForStatefulWipe() {
  // We can wipe for several different reasons:
  //  + User requested "power wash" which will create kResetFile.
  //  + Switch from verified mode to dev mode. We do this if we're in
  //    dev mode, and kDevModeFile doesn't exist. clobber-state
  //    in this case will create the file, to prevent re-wipe.
  //  + Switch from dev mode to verified mode. We do this if we're in
  //    verified mode, and kDevModeFile still exists. (This check
  //    isn't necessarily reliable.)
  //
  // Stateful wipe for dev mode switching is skipped if the build is a debug
  // build or if we've booted a non-recovery image in recovery mode (for
  // example, doing Esc-F3-Power on a Chromebook with DEV-signed firmware);
  // this protects various development use cases, most especially prototype
  // units or booting Chromium OS on non-Chrome hardware. And because crossystem
  // is slow on some platforms, we want to do the additional checks only after
  // verified kDevModeFile existence.
  std::vector<std::string> clobber_args;
  struct stat stbuf;
  std::string boot_alert_msg;
  std::string clobber_log_msg;
  base::FilePath reset_file = stateful_.Append(kResetFile);
  if ((lstat(reset_file.value().c_str(), &stbuf) == 0 &&
       S_ISLNK(stbuf.st_mode)) ||
      base::PathExists(reset_file)) {
    boot_alert_msg = "power_wash";
    // If it's not a plain file owned by us, force a powerwash.
    if (stbuf.st_uid != getuid() || !S_ISREG(stbuf.st_mode)) {
      clobber_args.push_back("keepimg");
    } else {
      std::string str;
      if (!base::ReadFileToString(reset_file, &str)) {
        PLOG(WARNING) << "Failed to read reset file";
      } else {
        std::vector<std::string> split_args = base::SplitString(
            str, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
        for (const std::string& arg : split_args) {
          clobber_args.push_back(arg);
        }
      }
    }
    if (clobber_args.empty()) {
      clobber_args.push_back("keepimg");
    }
  } else if (state_dev_.empty()) {
    // No physical stateful partition available, usually due to initramfs
    // (recovery image, factory install shim or netboot). Do not wipe.
  } else if (IsDevToVerifiedModeTransition(0)) {
    bool res = platform_->Stat(dev_mode_allowed_file_, &stbuf);
    if ((res && stbuf.st_uid == getuid()) || NeedsClobberWithoutDevModeFile()) {
      if (!DevIsDebugBuild()) {
        // We're transitioning from dev mode to verified boot.
        // When coming back from developer mode, we don't need to
        // clobber as aggressively. Fast will do the trick.
        boot_alert_msg = "leave_dev";
        clobber_args.push_back("fast");
        clobber_args.push_back("keepimg");
        std::string msg;
        if (res && stbuf.st_uid == getuid()) {
          msg = "'Leave developer mode, dev_mode file present'";
        } else {
          msg = "'Leave developer mode, no dev_mode file'";
        }
        clobber_log_msg = msg;
      } else {
        // Only fast clobber the non-protected paths in debug build to preserve
        // the testing tools.
        DevUpdateStatefulPartition("clobber");
      }
    }
  } else if (IsDevToVerifiedModeTransition(1)) {
    if (!platform_->Stat(dev_mode_allowed_file_, &stbuf) ||
        stbuf.st_uid != getuid()) {
      if (!DevIsDebugBuild()) {
        // We're transitioning from verified boot to dev mode.
        boot_alert_msg = "enter_dev";
        clobber_args.push_back("keepimg");
        clobber_log_msg = "Enter developer mode";
      } else {
        // Only fast clobber the non-protected paths in debug build to preserve
        // the testing tools.
        DevUpdateStatefulPartition("clobber");
        if (!PathExists(dev_mode_allowed_file_)) {
          if (!base::WriteFile(dev_mode_allowed_file_, "")) {
            PLOG(WARNING) << "Failed to create file: "
                          << dev_mode_allowed_file_.value();
          }
        }
      }
    }
  }

  if (!clobber_args.empty()) {
    platform_->Clobber(boot_alert_msg, clobber_args, clobber_log_msg);
  }
}

// Mount /home.
void ChromeosStartup::MountHome() {
  const base::FilePath home = stateful_.Append(kHome);
  const base::FilePath home_root = root_.Append(kHome);
  mount_helper_->MountOrFail(home, home_root, "", MS_BIND, "");
  // Remount /home with nosymfollow: bind mounts do not accept the option
  // within the same command.
  if (!platform_->Mount(base::FilePath(), home_root, "",
                        MS_REMOUNT | kCommonMountFlags | MS_NOSYMFOLLOW, "")) {
    PLOG(WARNING) << "Unable to remount " << home_root.value();
  }
}

// Start tpm2-simulator if it exists.
// TODO(b:261148112): Replace initctl call with logic to directly communicate
// with upstart.
void ChromeosStartup::StartTpm2Simulator() {
  base::FilePath tpm_simulator = root_.Append(kTpmSimulator);
  if (base::PathExists(tpm_simulator)) {
    brillo::ProcessImpl ictl;
    ictl.AddArg("/sbin/initctl");
    ictl.AddArg("start");
    ictl.AddArg("tpm2-simulator");
    // Failure is fine, we just continue.
    ictl.Run();
  }
}

// Clean up after a TPM firmware update. This must happen before mounting
// stateful, which will initialize the TPM again.
void ChromeosStartup::CleanupTpm() {
  base::FilePath tpm_update_req =
      stateful_.Append(kTpmFirmwareUpdateRequestFlagFile);
  if (base::PathExists(tpm_update_req)) {
    base::FilePath tpm_cleanup = root_.Append(kTpmFirmwareUpdateCleanup);
    if (base::PathExists(tpm_cleanup)) {
      platform_->RunProcess(tpm_cleanup);
    }
  }
}

// Move from /var/lib/whitelist to /var/lib/devicesettings if it is empty or
// non-existing. If /var/lib/devicesettings already exists, just remove
// /var/lib/whitelist.
// TODO(b/219506748): Remove the following lines by 2030 the latest. If there
// was a stepping stone to R99+ for all boards in between, or the number of
// devices using a version that did not have this code is less than the number
// of devices suffering from disk corruption, code can be removed earlier.
void ChromeosStartup::MoveToLibDeviceSettings() {
  base::FilePath whitelist = root_.Append(kVar).Append(kLibWhitelist);
  base::FilePath devicesettings = root_.Append(kVar).Append(kLibDevicesettings);
  // If the old whitelist dir still exists, try to migrate it.
  if (base::DirectoryExists(whitelist)) {
    if (base::IsDirectoryEmpty(whitelist)) {
      // If it is empty, delete it.
      if (!brillo::DeleteFile(whitelist)) {
        PLOG(WARNING) << "Failed to delete path " << whitelist.value();
      }
    } else if (brillo::DeleteFile(devicesettings)) {
      // If devicesettings didn't exist, or was empty, DeleteFile passed.
      // Rename the old path.
      if (!base::Move(whitelist, devicesettings)) {
        PLOG(WARNING) << "Failed to move " << whitelist.value() << " to "
                      << devicesettings.value();
      }
    } else {
      // Both directories exist and are not empty. Do nothing.
      LOG(WARNING) << "Unable to move " << whitelist.value() << " to "
                   << devicesettings.value()
                   << ", both directories are not empty";
    }
  }
}

// Create daemon store folders.
// See
// https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md#securely-mounting-daemon-store-folders.
void ChromeosStartup::CreateDaemonStore() {
  base::FilePath run_ds = root_.Append(kRun).Append(kDaemonStore);
  base::FilePath etc_ds = root_.Append(kEtc).Append(kDaemonStore);
  base::FileEnumerator iter(etc_ds, false,
                            base::FileEnumerator::FileType::DIRECTORIES);
  for (base::FilePath store = iter.Next(); !store.empty();
       store = iter.Next()) {
    base::FilePath rds = run_ds.Append(store.BaseName());
    if (!base::CreateDirectory(rds)) {
      PLOG(WARNING) << "mkdir failed for " << rds.value();
      continue;
    }
    if (!base::SetPosixFilePermissions(rds, 0755)) {
      PLOG(WARNING) << "chmod failed for " << rds.value();
      continue;
    }
    platform_->Mount(rds, rds, "", MS_BIND, "");
    platform_->Mount(base::FilePath("none"), rds, "", MS_SHARED, "");
  }
}

// Remove /var/empty if it exists. Use /mnt/empty instead.
void ChromeosStartup::RemoveVarEmpty() {
  base::FilePath var_empty = root_.Append(kVar).Append(kEmpty);
  base::ScopedFD dfd(open(var_empty.value().c_str(), O_DIRECTORY | O_CLOEXEC));
  if (!dfd.is_valid()) {
    if (errno != ENOENT) {
      PLOG(WARNING) << "Unable to open directory " << var_empty.value();
    }
    return;
  }
  file_attrs_cleaner::AttributeCheckStatus status =
      file_attrs_cleaner::CheckFileAttributes(var_empty, true, dfd.get());
  if (status != file_attrs_cleaner::AttributeCheckStatus::CLEARED) {
    PLOG(WARNING) << "Unexpected CheckFileAttributes status for "
                  << var_empty.value();
  }
  if (!base::DeletePathRecursively(var_empty)) {
    PLOG(WARNING) << "Failed to delete path " << var_empty.value();
  }
}

// Make sure that what gets written to /var/log stays in /var/log.
void ChromeosStartup::CheckVarLog() {
  base::FilePath varLog = root_.Append(kVarLog);
  base::FileEnumerator var_iter(
      root_.Append(kVarLog), true,
      base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::DIRECTORIES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS);
  for (base::FilePath path = var_iter.Next(); !path.empty();
       path = var_iter.Next()) {
    if (base::IsLink(path)) {
      base::FilePath realpath;
      if (!base::NormalizeFilePath(path, &realpath) ||
          !varLog.IsParent(realpath)) {
        if (!brillo::DeleteFile(path)) {
          // Bail out and wipe on failure to remove a symlink.
          mount_helper_->CleanupMounts(
              "Failed to remove symlinks under /var/log");
        }
      }
    }
  }
}

// Restore file contexts for /var.
void ChromeosStartup::RestoreContextsForVar(
    void (*restorecon_func)(const base::FilePath& path,
                            const std::vector<base::FilePath>& exclude,
                            bool is_recursive,
                            bool set_digests)) {
  // Restore file contexts for /var.
  base::FilePath sysfs = root_.Append(kSysfs);
  base::FilePath selinux = sysfs.Append(kSELinuxEnforce);
  if (!base::PathExists(selinux)) {
    LOG(INFO) << selinux.value()
              << " does not exist, can not restore file contexts";
    return;
  }
  base::FilePath var = root_.Append(kVar);
  std::vector<base::FilePath> exc_empty;
  restorecon_func(var, exc_empty, true, true);

  // Restoring file contexts for sysfs. tracefs is excluded from this
  // invocation and delayed in a separate job to improve boot time.
  std::vector<base::FilePath> exclude = {sysfs.Append(kKernelDebug),
                                         sysfs.Append(kKernelTracing)};
  restorecon_func(sysfs, exclude, true, false);

  // We cannot do recursive for .shadow since userdata is encrypted (including
  // file names) before user logs-in. Restoring context for it may mislabel
  // files if encrypted filename happens to match something.
  base::FilePath home = root_.Append(kHome);
  base::FilePath shadow = home.Append(".shadow");
  std::vector<base::FilePath> shadow_paths = {home, shadow};
  base::FileEnumerator shadow_files(shadow, false,
                                    base::FileEnumerator::FileType::FILES, "*");
  for (base::FilePath path = shadow_files.Next(); !path.empty();
       path = shadow_files.Next()) {
    shadow_paths.push_back(path);
  }
  base::FileEnumerator shadow_dot(shadow, false,
                                  base::FileEnumerator::FileType::FILES, ".*");
  for (base::FilePath path = shadow_dot.Next(); !path.empty();
       path = shadow_dot.Next()) {
    shadow_paths.push_back(path);
  }
  base::FileEnumerator shadow_subdir(
      shadow, false, base::FileEnumerator::FileType::FILES, "*/*");
  for (base::FilePath path = shadow_subdir.Next(); !path.empty();
       path = shadow_subdir.Next()) {
    shadow_paths.push_back(path);
  }
  for (auto path : shadow_paths) {
    restorecon_func(path, exc_empty, false, false);
  }

  // It's safe to recursively restorecon /home/{user,root,chronos} since
  // userdir is not bind-mounted here before logging in.
  std::array<base::FilePath, 3> h_paths = {
      home.Append(kUser), home.Append(kRoot), home.Append(kChronos)};
  for (auto h_path : h_paths) {
    restorecon_func(h_path, exc_empty, true, true);
  }
}

// Main function to run chromeos_startup.
int ChromeosStartup::Run() {
  dev_mode_ = platform_->InDevMode(cros_system_.get());

  // Make sure our clock is somewhat up-to-date. We don't need any resources
  // mounted below, so do this early on.
  CheckClock();

  // bootstat writes timings to tmpfs.
  bootstat_.LogEvent("pre-startup");

  EarlySetup();

  stateful_mount_ = std::make_unique<StatefulMount>(
      flags_, root_, stateful_, platform_.get(),
      std::make_unique<brillo::LogicalVolumeManager>(), mount_helper_.get());
  stateful_mount_->MountStateful();
  state_dev_ = stateful_mount_->GetStateDev();
  dev_image_ = stateful_mount_->GetDevImage();

  if (enable_stateful_security_hardening_) {
    // Block symlink traversal and opening of FIFOs on stateful. Note that we
    // set up exceptions for developer mode later on.
    BlockSymlinkAndFifo(root_, stateful_.value());
  }

  // Checks if developer mode is blocked.
  dev_mode_allowed_file_ = stateful_.Append(kDevModeFile);
  DevCheckBlockDevMode(dev_mode_allowed_file_);

  CheckForStatefulWipe();

  // Cleanup the file attributes in the unencrypted stateful directory.
  base::FilePath unencrypted = stateful_.Append(kUnencrypted);
  ForceCleanFileAttrs(unencrypted);

  std::vector<std::string> tmpfiles = {stateful_.value()};
  TmpfilesConfiguration(tmpfiles);

  MountHome();

  StartTpm2Simulator();

  CleanupTpm();

  base::FilePath encrypted_failed = stateful_.Append(kMountEncryptedFailedFile);
  struct stat stbuf;
  if (!mount_helper_->DoMountVarAndHomeChronos()) {
    if (!platform_->Stat(encrypted_failed, &stbuf) ||
        stbuf.st_uid != getuid()) {
      base::WriteFile(encrypted_failed, "");
    } else {
      cros_system_->SetInt("recovery_request", 1);
    }

    utils::Reboot();
    return 0;
  }

  brillo::DeleteFile(encrypted_failed);
  base::FilePath encrypted_state_mnt = stateful_.Append(kEncryptedStatefulMnt);
  mount_helper_->RememberMount(encrypted_state_mnt);

  // Setup the encrypted reboot vault once the encrypted stateful partition
  // is available. If unlocking the encrypted reboot vault failed (due to
  // power loss/reboot/invalid vault), attempt to recreate the encrypted reboot
  // vault.
  if (flags_.encrypted_reboot_vault) {
    if (!utils::UnlockEncryptedRebootVault()) {
      utils::CreateEncryptedRebootVault();
    }
  }

  ForceCleanFileAttrs(root_.Append(kVar));
  ForceCleanFileAttrs(root_.Append(kHome).Append(kChronos));

  // If /var is too full, delete the logs so the device can boot successfully.
  // It is possible that the fullness of /var was not due to logs, but that
  // is very unlikely. If such a thing happens, we have a serious problem
  // which should not be covered up here.
  if (IsVarFull()) {
    brillo::DeletePathRecursively(root_.Append(kVarLog));
    base::FilePath reclaim_full_var = stateful_.Append(kReclaimFullVar);
    base::WriteFile(reclaim_full_var, "Startup.ReclaimFullVar");
  }

  // Gather logs if needed. This might clear /var, so all init has to be after
  // this.
  DevGatherLogs();

  // Collect crash reports from early boot/mount failures.
  brillo::ProcessImpl crash_reporter;
  crash_reporter.AddArg("/sbin/crash_reporter");
  crash_reporter.AddArg("--ephemeral_collect");
  if (crash_reporter.Run() != 0) {
    PLOG(WARNING) << "Unable to collect early logs and crashes.";
  }

  if (enable_stateful_security_hardening_) {
    ConfigureFilesystemExceptions(root_);
  }

  std::vector<std::string> tmpfile_args = {root_.Append(kHome).value(),
                                           root_.Append(kVar).value()};
  TmpfilesConfiguration(tmpfile_args);

  MoveToLibDeviceSettings();

  MaybeRunUefiStartup(*UefiDelegate::Create(*platform_, root_));

  // /run is tmpfs used for runtime data. Make sure /var/run and /var/lock
  // are bind-mounted to /run and /run/lock respectively for backwards
  // compatibility.
  // Bind mount /run to /var/run.
  const base::FilePath var = root_.Append(kVar);
  const base::FilePath root_run = root_.Append(kRun);
  platform_->Mount(root_run, var.Append(kRun), "", MS_BIND, "");
  mount_helper_->RememberMount(root_run);

  // Bind mount /run/lock to /var/lock.
  const base::FilePath root_run_lock = root_run.Append(kLock);
  platform_->Mount(root_run_lock, var.Append(kLock), "", MS_BIND, "");
  mount_helper_->RememberMount(root_run_lock);

  CreateDaemonStore();

  RemoveVarEmpty();

  CheckVarLog();

  // MS_SHARED to give other namespaces access to mount points under /media.
  platform_->Mount(base::FilePath(kMedia), root_.Append(kMedia), "tmpfs",
                   MS_NOSUID | MS_NODEV | MS_NOEXEC, "");
  platform_->Mount(base::FilePath(), root_.Append(kMedia), "", MS_SHARED, "");

  std::vector<std::string> t_args = {root_.Append(kMedia).value()};
  TmpfilesConfiguration(t_args);

  RestoreContextsForVar(&utils::Restorecon);

  // Mount dev packages.
  DevMountPackages(dev_image_);
  RestorePreservedPaths();

  // Unmount securityfs so that further modifications to inode security
  // policies are not possible
  const base::FilePath kernel_sec =
      root_.Append(kSysfs).Append(kKernelSecurity);
  if (!platform_->Umount(kernel_sec)) {
    PLOG(WARNING) << "Failed to umount: " << kernel_sec;
  }

  bootstat_.LogEvent("post-startup");

  return 0;
}

// Temporary function during the migration of the code. Run the bash
// version of chromeos_startup, which has been copied to chromeos_startup.sh
// to allow editing without effecting existing script. As more functionality
// moves to c++, it will be removed from chromeos_startup.sh.
int ChromeosStartup::RunChromeosStartupScript() {
  brillo::ProcessImpl proc;
  proc.AddArg("/sbin/chromeos_startup.sh");
  return proc.Run();
}

// Check whether the device is allowed to boot in dev mode.
// 1. If a debug build is already installed on the system, ignore block_devmode.
//    It is pointless in this case, as the device is already in a state where
//    the local user has full control.
// 2. According to recovery mode only boot with signed images, the block_devmode
//    could be ignored here -- otherwise factory shim will be blocked especially
//    that RMA center can't reset this device.
void ChromeosStartup::DevCheckBlockDevMode(
    const base::FilePath& dev_mode_file) const {
  if (!dev_mode_) {
    return;
  }
  int devsw;
  int debug;
  int rec_reason;
  if (!cros_system_->GetInt("devsw_boot", &devsw) ||
      !cros_system_->GetInt("debug_build", &debug) ||
      !cros_system_->GetInt("recovery_reason", &rec_reason)) {
    LOG(WARNING) << "Failed to get boot information from crossystem";
    return;
  }
  if (!(devsw == 1 && debug == 0 && rec_reason == 0)) {
    DLOG(INFO) << "Debug build is already installed, ignore block_devmode";
    return;
  }

  // The file indicates the system has booted in developer mode and must
  // initiate a wiping process in the next (normal mode) boot.
  base::FilePath vpd_block_dir = root_.Append("sys/firmware/vpd/rw");
  base::FilePath vpd_block_file = vpd_block_dir.Append("block_devmode");
  bool block_devmode = false;

  // Checks ordered by run time.
  // 1. Try reading VPD through /sys.
  // 2. Try crossystem.
  // 3. Re-read VPD directly from SPI flash (slow!) but only for systems
  //    that don't have VPD in sysplatform and only when NVRAM indicates that it
  //    has been cleared.
  int crossys_block;
  int nvram;
  int val;
  if (utils::ReadFileToInt(vpd_block_file, &val) && val == 1) {
    block_devmode = true;
  } else if (cros_system_->GetInt("block_devmode", &crossys_block) &&
             crossys_block == 1) {
    block_devmode = true;
  } else if (!base::DirectoryExists(vpd_block_dir) &&
             cros_system_->GetInt("nvram_cleared", &nvram) && nvram == 1) {
    std::string output;
    std::vector<std::string> args = {"-i", "RW_VPD", "-g", "block_devmode"};
    if (platform_->VpdSlow(args, &output) && output == "1") {
      block_devmode = true;
    }
  }

  if (block_devmode) {
    // Put a flag file into place that will trigger a stateful partition wipe
    // after reboot in verified mode.
    if (!PathExists(dev_mode_file)) {
      base::WriteFile(dev_mode_file, "");
    }

    platform_->BootAlert("block_devmode");
  }
}

// Set dev_mode_ for tests.
void ChromeosStartup::SetDevMode(bool dev_mode) {
  dev_mode_ = dev_mode;
}

bool ChromeosStartup::DevIsDebugBuild() const {
  if (!dev_mode_) {
    return false;
  }
  return platform_->IsDebugBuild(cros_system_.get());
}

bool ChromeosStartup::DevUpdateStatefulPartition(const std::string& args) {
  if (!dev_mode_) {
    return true;
  }
  return stateful_mount_->DevUpdateStatefulPartition(args);
}

void ChromeosStartup::DevGatherLogs() {
  if (dev_mode_) {
    stateful_mount_->DevGatherLogs(root_);
  }
}

void ChromeosStartup::DevMountPackages(const base::FilePath& device) {
  if (!dev_mode_) {
    return;
  }
  stateful_mount_->DevMountPackages(device);
}

void ChromeosStartup::RestorePreservedPaths() {
  if (!dev_mode_) {
    return;
  }
  base::FilePath preserve_dir =
      stateful_.Append(kUnencrypted).Append(kPreserve);
  for (const auto& path : kPreserveDirs) {
    base::FilePath fpath(path);
    base::FilePath src = preserve_dir.Append(fpath);
    if (base::DirectoryExists(src)) {
      const base::FilePath dst = root_.Append(fpath);
      base::CreateDirectory(dst);
      if (!base::Move(src, dst)) {
        PLOG(WARNING) << "Failed to move " << src.value();
      }
    }
  }
}

}  // namespace startup
