// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <base/environment.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_util.h>

#include "installer/cgpt_manager.h"
#include "installer/chromeos_install_config.h"
#include "installer/chromeos_legacy.h"
#include "installer/chromeos_postinst.h"
#include "installer/chromeos_setimage.h"
#include "installer/inst_util.h"
#include "installer/metrics.h"
#include "installer/reven_partition_migration.h"
#include "installer/slow_boot_notify.h"

using std::string;

namespace {
const char kStatefulMount[] = "/mnt/stateful_partition";

const char kUMABiosType[] = "Installer.Postinstall.BiosType";
const char kUMANonChromebookBiosSuccessEFI[] =
    "Installer.Postinstall.NonChromebookBiosSuccess.EFI";
const char kUMANonChromebookBiosSuccessLegacy[] =
    "Installer.Postinstall.NonChromebookBiosSuccess.Legacy";
const char kUMANonChromebookBiosSuccessSecure[] =
    "Installer.Postinstall.NonChromebookBiosSuccess.Secure";
const char kUMANonChromebookBiosSuccessUBoot[] =
    "Installer.Postinstall.NonChromebookBiosSuccess.UBoot";
const char kUMANonChromebookBiosSuccessUnknown[] =
    "Installer.Postinstall.NonChromebookBiosSuccess.Unknown";
const char kUMAESPMountRetries[] = "Installer.Postinstall.ESPMountRetries";

bool GetKernelCommandLine(string* kernel_cmd_line) {
  if (!base::ReadFileToString(base::FilePath("/proc/cmdline"),
                              kernel_cmd_line)) {
    LOG(ERROR) << "Can't read kernel commandline options";
    return false;
  }
  return true;
}
}  // namespace

bool ConfigureInstall(const base::FilePath& install_dev,
                      const base::FilePath& install_dir,
                      BiosType bios_type,
                      DeferUpdateAction defer_update_action,
                      bool force_update_firmware,
                      InstallConfig* install_config) {
  Partition root = Partition(install_dev, install_dir);

  string slot;
  if (root.number() == PartitionNum::ROOT_A) {
    slot = "A";
  } else if (root.number() == PartitionNum::ROOT_B) {
    slot = "B";
  } else {
    LOG(ERROR) << "Not a valid target partition number: " << root.number();
    return false;
  }

  base::FilePath kernel_dev = MakePartitionDev(
      root.base_device(), PartitionNum(root.number().Value() - 1));

  base::FilePath boot_dev =
      MakePartitionDev(root.base_device(), PartitionNum::EFI_SYSTEM);

  // if we don't know the bios type, detect it. Errors are logged
  // by the detect method.
  if (bios_type == BiosType::kUnknown && !DetectBiosType(&bios_type)) {
    return false;
  }

  // Put the actual values on the result structure
  install_config->slot = slot;
  install_config->root = root;
  install_config->kernel = Partition(kernel_dev);
  install_config->boot = Partition(boot_dev, base::FilePath("/tmp/boot_mnt"));
  install_config->bios_type = bios_type;
  install_config->defer_update_action = defer_update_action;
  install_config->force_update_firmware = force_update_firmware;

  return true;
}

bool IsRunningMiniOS() {
  string kernel_cmd_line;
  return GetKernelCommandLine(&kernel_cmd_line) &&
         kernel_cmd_line.find("cros_minios") != string::npos;
}

bool DetectBiosType(BiosType* bios_type) {
  string kernel_cmd_line;
  return GetKernelCommandLine(&kernel_cmd_line) &&
         KernelConfigToBiosType(kernel_cmd_line, bios_type);
}

bool KernelConfigToBiosType(const string& kernel_config, BiosType* type) {
  if (kernel_config.find("cros_secure") != string::npos) {
    *type = BiosType::kSecure;
    return true;
  }

  if (kernel_config.find("cros_legacy") != string::npos) {
#ifdef __arm__
    // The Arm platform only uses U-Boot, but may set cros_legacy to mean
    // U-Boot without our secure boot modifications.
    *type = BiosType::kUBoot;
#else
    *type = BiosType::kLegacy;
#endif
    return true;
  }

  if (kernel_config.find("cros_efi") != string::npos) {
    *type = BiosType::kEFI;
    return true;
  }

  // No recognized bios type was found
  LOG(ERROR) << "No recognized cros_XXX bios option on kernel command line.";
  return false;
}

namespace {

void SendBiosTypeUMA(BiosType bios_type) {
  std::unique_ptr<MetricsInterface> metrics =
      MetricsInterface::GetMetricsInstance();

  // Send UMA for bios type.
  // The reven board expands the variety of bios_types we expect to be in use.
  // Watching usage distribution helps make educated decisions.
  metrics->SendEnumMetric(kUMABiosType, static_cast<int>(bios_type),
                          static_cast<int>(BiosType::kMaxValue));
}

// Send UMA for non-Chromebook postinst success.
// The reven board expands the variety of bios_types we expect to be in use.
// This helps us monitor failures for non-Chromebook bios types.
// NB: If a user reboots shortly after a failure here and the failure results in
// an inability to boot back into the OS, the metric may never be sent. We
// expect this to underreport failures.
void SendNonChromebookBiosSuccess(MetricsInterface& metrics,
                                  BiosType bios_type,
                                  bool success) {
  // This matches a set of metrics in histograms.xml, and should not be altered.
  std::string uma_name;
  switch (bios_type) {
    case BiosType::kUnknown:
      uma_name = kUMANonChromebookBiosSuccessUnknown;
      break;
    case BiosType::kSecure:
      uma_name = kUMANonChromebookBiosSuccessSecure;
      break;
    case BiosType::kUBoot:
      uma_name = kUMANonChromebookBiosSuccessUBoot;
      break;
    case BiosType::kLegacy:
      uma_name = kUMANonChromebookBiosSuccessLegacy;
      break;
    case BiosType::kEFI:
      uma_name = kUMANonChromebookBiosSuccessEFI;
      break;
  }

  metrics.SendBooleanMetric(uma_name, success);
}

// Run the cr50 script with the given args. Returns zero on success, exit code
// on failure.
//
// script_name the script in /usr/share/cros to run
// script_arg the args to run the script with
//
int RunCr50Script(const base::FilePath& install_dir,
                  const string& script_name,
                  const string& script_arg) {
  base::FilePath script =
      install_dir.Append("usr/share/cros").Append(script_name);
  if (!base::PathExists(script)) {
    // The script is not there, means no cr50 present either, nothing to do.
    return 0;
  }
  return RunCommand({script.value(), script_arg});
}

// Updates firmware. We must activate new firmware only after new kernel is
// actived (installed and made bootable), otherwise new firmware with all old
// kernels may lead to recovery screen (due to new key).
// TODO(hungte) Replace the shell execution by native code (crosbug.com/25407).
// Note that this returns an exit code, not bool success/failure.
int FirmwareUpdate(const InstallConfig& install_config, bool is_update) {
  base::FilePath install_dir = install_config.root.mount();
  base::FilePath command =
      install_dir.Append("usr/sbin/chromeos-firmwareupdate");
  if (!base::PathExists(command)) {
    LOG(INFO) << "No firmware updates available.";
    // Return success.
    return 0;
  }

  string mode;
  if (is_update) {
    switch (install_config.defer_update_action) {
      case DeferUpdateAction::kAuto:
        // Background auto update by Update Engine.
        mode = "autoupdate";
        break;
      case DeferUpdateAction::kHold:
        mode = "deferupdate_hold";
        break;
      case DeferUpdateAction::kApply:
        mode = "deferupdate_apply";
        break;
    }
  } else {
    // Recovery image, or from command "chromeos-install".
    mode = "recovery";
  }

  LOG(INFO) << "Firmware update with mode=" << mode;
  int result = RunCommand({command.value(), "--mode=" + mode});

  // Next step after postinst may take a lot of time (eg, disk wiping)
  // and people may confuse that as 'firmware update takes a long wait',
  // we explicitly prompt here.
  if (result == 0) {
    LOG(INFO) << "Firmware update completed.";
  } else if (result == 3) {
    LOG(INFO) << "Firmware can't be updated. Booted from RW Firmware B"
                 " with error code: "
              << result;
  } else if (result == 4) {
    LOG(INFO) << "RO Firmware needs update, but is really marked RO."
                 " with error code: "
              << result;
  } else {
    LOG(INFO) << "Firmware update failed with error code: " << result;
  }

  return result;
}

// Fix the unencrypted permission. The permission on this file have been
// deployed with wrong values (0766 for the permission) and/or the wrong
// uid:gid.
void FixUnencryptedPermission() {
  string unencrypted_dir = string(kStatefulMount) + "/unencrypted";
  LOG(INFO) << "Checking permission of " << unencrypted_dir;
  struct stat unencrypted_stat;
  const mode_t target_mode =
      S_IFDIR | S_IRWXU | (S_IRGRP | S_IXGRP) | (S_IROTH | S_IXOTH);  // 040755
  if (stat(unencrypted_dir.c_str(), &unencrypted_stat) != 0) {
    PLOG(ERROR) << "Couldn't check the current permission, ignored";
  } else if (unencrypted_stat.st_uid == 0 && unencrypted_stat.st_gid == 0 &&
             unencrypted_stat.st_mode == target_mode) {
    LOG(INFO) << "Permission is ok.";
  } else {
    bool ok = true;
    // chmod(2) only takes the last four octal digits, so we flip the IFDIR bit.
    if (chmod(unencrypted_dir.c_str(), target_mode ^ S_IFDIR) != 0) {
      PLOG(ERROR) << "chmod failed";
      ok = false;
    }
    if (chown(unencrypted_dir.c_str(), 0, 0) != 0) {
      PLOG(ERROR) << "chown failed";
      ok = false;
    }
    if (ok)
      LOG(INFO) << "Permission changed successfully.";
  }
}

// Do board specific post install stuff, if available.
bool RunBoardPostInstall(const base::FilePath& install_dir) {
  base::FilePath script = install_dir.Append("usr/sbin/board-postinst");

  if (!base::PathExists(script)) {
    return true;
  }

  int result = RunCommand({script.value(), install_dir.value()});

  if (result)
    LOG(ERROR) << "Board post install failed, result: " << result;
  else
    LOG(INFO) << "Board post install succeeded.";

  return result == 0;
}

bool UpdatePartitionTable(CgptManager& cgpt_manager,
                          const InstallConfig& install_config,
                          bool is_update) {
  LOG(INFO) << "Updating Partition Table Attributes using CgptManager...";

  CgptErrorCode result =
      cgpt_manager.SetHighestPriority(install_config.kernel.number());
  if (result != CgptErrorCode::kSuccess) {
    LOG(ERROR) << "Unable to set highest priority for kernel: "
               << install_config.kernel.number();
    return false;
  }

  // If it's not an update, pre-mark the first boot as successful
  // since we can't fall back on the old install.
  bool new_kern_successful = !is_update;
  result = cgpt_manager.SetSuccessful(install_config.kernel.number(),
                                      new_kern_successful);
  if (result != CgptErrorCode::kSuccess) {
    LOG(ERROR) << "Unable to set successful to " << new_kern_successful
               << " for kernel: " << install_config.kernel.number();
    return false;
  }

  int numTries = 6;
  result =
      cgpt_manager.SetNumTriesLeft(install_config.kernel.number(), numTries);
  if (result != CgptErrorCode::kSuccess) {
    LOG(ERROR) << "Unable to set NumTriesLeft to " << numTries
               << " for kernel: " << install_config.kernel.number();
    return false;
  }

  LOG(INFO) << "Updated kernel " << install_config.kernel.number()
            << " with Successful: " << new_kern_successful
            << " and NumTriesLeft: " << numTries;
  return true;
}

bool RollbackPartitionTable(CgptManager& cgpt_manager,
                            const InstallConfig& install_config) {
  // In all these checks below, we continue even if there's a failure
  // so as to cleanup as much as possible.
  bool new_kern_successful = false;
  bool rollback_successful = true;
  CgptErrorCode result =
      cgpt_manager.SetSuccessful(install_config.kernel.number(), false);
  if (result != CgptErrorCode::kSuccess) {
    rollback_successful = false;
    LOG(ERROR) << "Unable to set successful to " << new_kern_successful
               << " for kernel: " << install_config.kernel.number();
  }

  int numTries = 0;
  result =
      cgpt_manager.SetNumTriesLeft(install_config.kernel.number(), numTries);
  if (result != CgptErrorCode::kSuccess) {
    rollback_successful = false;
    LOG(ERROR) << "Unable to set NumTriesLeft to " << numTries
               << " for kernel: " << install_config.kernel.number();
  }

  int priority = 0;
  result = cgpt_manager.SetPriority(install_config.kernel.number(), priority);
  if (result != CgptErrorCode::kSuccess) {
    rollback_successful = false;
    LOG(ERROR) << "Unable to set Priority to " << priority
               << " for kernel: " << install_config.kernel.number();
  }

  if (rollback_successful)
    LOG(INFO) << "Successfully updated GPT with all settings to rollback.";

  return rollback_successful;
}

// Try to repair the partition table, but don't worry if we can't.
void RepairPartitionTable(CgptManager& cgpt_manager) {
  CgptErrorCode result = cgpt_manager.RepairPartitionTable();
  if (result != CgptErrorCode::kSuccess) {
    LOG(WARNING) << "Error while trying to repair partition table."
                 << " Probably everything is fine.";
  }
}

// Non-Chromebook/box bootloaders and their config files are stored on the
// EFI System Partition (ESP). Mount the partition and "Do post install stuff"
// for these bootloaders.
//
// Returns early for irrelevant bootloaders.
// Returns false for some errors, true otherwise.
// TODO(tbrandston): perhaps we should only return false for errors that would
// interfere with completing install/update?
bool ESPPostInstall(const InstallConfig& install_config) {
  std::unique_ptr<MetricsInterface> metrics =
      MetricsInterface::GetMetricsInstance();
  // Early-return for bootloaders we don't handle here.
  switch (install_config.bios_type) {
    case BiosType::kSecure:
      LOG(INFO) << "Not running ESPPostInstall for BiosType: kSecure";
      return true;
    case BiosType::kUnknown:
      // Returning false here to maintain approximate historical behavior
      // where kUnknown results in postinst failure.
      LOG(ERROR) << "Exiting early for BiosType: kUnknown";
      return false;
    case BiosType::kUBoot:
    case BiosType::kLegacy:
    case BiosType::kEFI:
      break;
  }

  if (!base::CreateDirectory(install_config.boot.mount())) {
    LOG(ERROR) << "Failed to create mount dir for EFI System Partition.";
    return false;
  }

  // Mount the EFI system partition.
  LOG(INFO) << "mount " << install_config.boot.device() << " to "
            << install_config.boot.mount();

  bool mount_success = false;
  int mount_attempts = 0;
  int max_mount_attempts = 5;

  // As of switching to Linux v5.15, the `udev_settle` call may be ran
  // before all disk operations. Given there isn't a fully synchronous
  // mechanism we can rely on, we're retrying with another settle attempt.

  for (; mount_attempts < max_mount_attempts; ++mount_attempts) {
    LOG(INFO) << "Mount attempt " << mount_attempts + 1 << " of "
              << max_mount_attempts;

    // Wait for partitions to be re-read, else the mount will race.
    int settle_result = RunCommand({"udevadm", "settle", "--timeout=10"});
    if (settle_result < 0) {
      LOG(INFO) << "Failed to run udevadm settle --timeout=10. "
                << "Returned value is " << settle_result << ".";
    }

    int mount_result = mount(install_config.boot.device().value().c_str(),
                             install_config.boot.mount().value().c_str(),
                             "vfat", MS_NODEV | MS_NOEXEC | MS_NOSUID, nullptr);

    if (mount_result == 0) {
      mount_success = true;
      break;
    } else {
      LOG(WARNING) << "Mount operation failed with err code " << mount_result
                   << ". Retrying in 1sec";
      sleep(1);
    }
  }

  metrics->SendLinearMetric(kUMAESPMountRetries, mount_attempts,
                            max_mount_attempts);

  if (!mount_success) {
    PLOG(ERROR) << "Failed to mount " << install_config.boot.device() << " to "
                << install_config.boot.mount() << ". See above for err code";
    return false;
  }

  bool success = true;

  switch (install_config.bios_type) {
    case BiosType::kUnknown:
    case BiosType::kSecure:
      success = false;
      break;

    case BiosType::kUBoot:
      // The Arm platform only uses U-Boot, but may set cros_legacy to mean
      // U-Boot without secure boot modifications. This may need handling.
      if (!RunLegacyUBootPostInstall(install_config)) {
        LOG(ERROR) << "Legacy PostInstall failed.";
        success = false;
      }
      break;

    case BiosType::kLegacy:
      if (!RunLegacyPostInstall(install_config)) {
        LOG(ERROR) << "Legacy PostInstall failed.";
        success = false;
        break;
      }

      // Configure EFI entries in addition to the legacy.
      // Allows devices that can boot installers in legacy
      // but will boot the installed target in EFI mode.
      // Errors here are not necessarily fatal as the common
      // case is the machine will boot successfully from legacy.
      if (USE_POSTINSTALL_CONFIG_EFI_AND_LEGACY) {
        if (!RunEfiPostInstall(install_config)) {
          LOG(WARNING) << "Ignored secondary EFI PostInstall failure.";
        }
      }

      break;

    case BiosType::kEFI:
      if (!RunEfiPostInstall(install_config)) {
        LOG(ERROR) << "EFI PostInstall failed.";
        success = false;
        break;
      }

      // Optionally update the legacy boot entries to support
      // devices that can boot from the USB in EFI mode with the
      // installed disk booting in legacy mode.
      if (USE_POSTINSTALL_CONFIG_EFI_AND_LEGACY) {
        if (!RunLegacyPostInstall(install_config)) {
          LOG(WARNING) << "Ignored secondary Legacy PostInstall failure.";
        }
      }

      break;
  }

  SendNonChromebookBiosSuccess(*metrics, install_config.bios_type, success);

  // Unmount the EFI system partition.
  LOG(INFO) << "umount " << install_config.boot.mount();
  if (umount(install_config.boot.mount().value().c_str()) != 0) {
    PLOG(ERROR) << "Failed to unmount " << install_config.boot.mount();
    success = false;
  }

  return success;
}

// Do post install stuff.
//
// Install kernel, set up the proper bootable partition in
// GPT table, update firmware if necessary and possible.
//
// install_config defines the root, kernel and boot partitions.
//
bool ChromeosChrootPostinst(const InstallConfig& install_config,
                            int* exit_code) {
  auto env = base::Environment::Create();

  // Extract External ENVs
  bool is_factory_install = env->HasVar(kEnvIsFactoryInstall);
  bool is_recovery_install = env->HasVar(kEnvIsRecoveryInstall);
  bool is_install = env->HasVar(kEnvIsInstall);
  bool is_update = !is_factory_install && !is_recovery_install && !is_install &&
                   !IsRunningMiniOS();

  switch (install_config.defer_update_action) {
    case DeferUpdateAction::kAuto:
    case DeferUpdateAction::kHold: {
      // TODO(dgarrett): Remove when chromium:216338 is fixed.
      // If this FS was mounted read-write, we can't do deltas from it. Mark the
      // FS as such
      Touch(install_config.root.mount().Append(
          ".nodelta"));  // Ignore Error on purpose

      LOG(INFO) << "Setting boot target to " << install_config.root.device()
                << ": Partition " << install_config.root.number() << ", Slot "
                << install_config.slot;

      if (!SetImage(install_config)) {
        LOG(ERROR) << "SetImage failed.";
        return false;
      }

      // This cache file might be invalidated, and will be recreated on next
      // boot. Error ignored, since we don't care if it didn't exist to start
      // with.
      string network_driver_cache = "/var/lib/preload-network-drivers";
      LOG(INFO) << "Clearing network driver boot cache: "
                << network_driver_cache;
      unlink(network_driver_cache.c_str());

      break;
    }
    case DeferUpdateAction::kApply:
      break;
  }

  LOG(INFO) << "Syncing filesystems before changing boot order...";
  LoggingTimerStart();
  sync();
  LoggingTimerFinish();

  CgptManager cgpt_manager;

  CgptErrorCode result =
      cgpt_manager.Initialize(install_config.root.base_device());
  if (result != CgptErrorCode::kSuccess) {
    LOG(ERROR) << "Unable to initialize CgptManager().";
    return false;
  }

  switch (install_config.defer_update_action) {
    case DeferUpdateAction::kApply:
      LOG(INFO) << "Updating partition table for deferred update APPLY.";
      [[fallthrough]];
    case DeferUpdateAction::kAuto: {
      // Keep this before the |UpdatePartitionTable| and subsequent
      // |udevadm settle|. This prevents the updates to the GPT from failing,
      // and can also cause the partitions to be re-read.
      if (USE_POSTINSTALL_CGPT_REPAIR) {
        RepairPartitionTable(cgpt_manager);
      }

      if (!UpdatePartitionTable(cgpt_manager, install_config, is_update)) {
        LOG(ERROR) << "UpdatePartitionTable failed.";
        return false;
      }

      // For Chromebook firmware (`BiosType::kSecure`) the new partition has now
      // been marked bootable (for most devices, see Note below) and a reboot
      // will boot into it. Thus, it's important that any future errors in this
      // script do not cause this script to return failure unless in factory
      // mode.
      //
      // For other BiosTypes, while we might boot to the new partition the files
      // on the EFI System Partition aren't yet set up to boot successfully.
      //
      // Note: for devices using MTD storage the partition won't be marked
      // bootable until `cgpt_manager.Finalize` is called or cgpt_manager is
      // destructed. b/260606556

      if (!ESPPostInstall(install_config)) {
        LOG(ERROR) << "ESPPostInstall failed.";
        // ESPPostInstall has failed. We don't know which changes have been made
        // or which slot they'll allow booting into. My best guess is that a
        // rollback will generally be better than leaving things as-is.
        if (!RollbackPartitionTable(cgpt_manager, install_config)) {
          LOG(ERROR) << "RollbackPartitionTable failed.";
        }
        return false;
      }

      // Run a partition migration to increase the size of kernel
      // partitions on the reven board. This is a no-op if the
      // `reven_partition_migration` USE flag is not enabled.
      if (!RunRevenPartitionMigration(
              cgpt_manager, *MetricsInterface::GetMetricsInstance(), *env)) {
        LOG(ERROR) << "Fatal partition migration error.";
        return false;
      }

      FixUnencryptedPermission();

      // We have a new image, making the ureadahead pack files
      // out-of-date.  Delete the files so that ureadahead will
      // regenerate them on the next reboot.
      // WARNING: This doesn't work with upgrade from USB, rather than full
      // install/recovery. We don't have support for it as it'll increase the
      // complexity here, and only developers do upgrade from USB.
      if (!RemovePackFiles(base::FilePath("/var/lib/ureadahead"))) {
        LOG(ERROR) << "RemovePackFiles Failed.";
      }

      // Create a file indicating that the install is completed. The file
      // will be used in /sbin/chromeos_startup to run tasks on the next boot.
      // See comments above about removing ureadahead files.
      base::FilePath install_completed =
          base::FilePath(kStatefulMount).Append(".install_completed");
      if (!Touch(install_completed)) {
        PLOG(ERROR) << "Touch(" << install_completed << ") failed.";
      }

      // If present, remove firmware checking completion file to force a disk
      // firmware check at reboot.
      string disk_fw_check_complete =
          string(kStatefulMount) +
          "/unencrypted/cache/.disk_firmware_upgrade_completed";
      unlink(disk_fw_check_complete.c_str());

      if (!is_factory_install &&
          !RunBoardPostInstall(install_config.root.mount())) {
        LOG(ERROR) << "Failed to perform board specific post install script.";
        // The comment starting "For Chromebook firmware..." says not to return
        // failure here. Looks like we're doing it anyway?
        return false;
      }

      break;
    }
    case DeferUpdateAction::kHold:
      LOG(INFO) << "Skipping partition table update for deferred update HOLD.";
      break;
  }

  // Use `--force_update_firmware` to bypass this tag check.
  base::FilePath firmware_tag_file =
      install_config.root.mount().Append("root/.force_update_firmware");

  bool attempt_firmware_update =
      (!is_factory_install && base::PathExists(firmware_tag_file));

  if (install_config.force_update_firmware) {
    if (attempt_firmware_update) {
      LOG(INFO) << "Firmware update is already set to be attempted.";
    } else {
      LOG(INFO) << "Forcing the firmware update.";
    }
    attempt_firmware_update = true;
  }

  // In factory process, firmware is either pre-flashed or assigned by
  // mini-omaha server, and we don't want to try updates inside postinst.
  if (attempt_firmware_update) {
    base::FilePath fspm_main;
    if (CreateTemporaryFile(&fspm_main))
      SlowBootNotifyPreFwUpdate(fspm_main);

    *exit_code = FirmwareUpdate(install_config, is_update);
    if (*exit_code == 0) {
      base::FilePath fspm_next;
      if (CreateTemporaryFile(&fspm_next))
        SlowBootNotifyPostFwUpdate(fspm_next);

      if (SlowBootNotifyRequired(fspm_main, fspm_next)) {
        base::FilePath slow_boot_req_file(string(kStatefulMount) +
                                          "/etc/slow_boot_required");
        if (WriteFile(slow_boot_req_file, "1", 1) != 1)
          PLOG(ERROR) << "Unable to write to file:"
                      << slow_boot_req_file.value();
      }
      base::DeleteFile(fspm_main);
      base::DeleteFile(fspm_next);
    } else {
      base::DeleteFile(fspm_main);

      LOG(INFO)
          << "Rolling back update due to failure calling firmware updater";
      // Note: This will only rollback the ChromeOS verified boot target.
      // The assumption is that systems running firmware autoupdate
      // are not running legacy (non-ChromeOS) firmware. If the firmware
      // updater crashes or writes corrupt data rather than gracefully
      // failing, we'll probably need to recover with a recovery image.
      if (!RollbackPartitionTable(cgpt_manager, install_config)) {
        LOG(ERROR) << "RollbackPartitionTable failed.";
      }

      return false;
    }
  }

  // Don't modify Cr50 in factory.
  if (!is_factory_install) {
    int result = 0;

    // Check the device state to determine if the board id should be set.
    if (RunCr50Script(install_config.root.mount(), "cr50-set-board-id.sh",
                      "check_device")) {
      LOG(INFO) << "Skip setting board id";
    } else {
      // Set the board id with unknown phase.
      result = RunCr50Script(install_config.root.mount(),
                             "cr50-set-board-id.sh", "unknown");
      // cr50 set board id failure is not a reason to interrupt installation.
      if (result)
        LOG(ERROR) << "ignored: cr50-set-board-id failure: " << result;
    }

    result = RunCr50Script(install_config.root.mount(), "cr50-update.sh",
                           install_config.root.mount().value());
    // cr50 update failure is not a reason for interrupting installation.
    if (result)
      LOG(WARNING) << "ignored: cr50-update failure: " << result;
    LOG(INFO) << "cr50 setup complete.";
  }

  if (cgpt_manager.Finalize() != CgptErrorCode::kSuccess) {
    LOG(ERROR) << "Failed to write GPT changes back.";
    return false;
  }

  printf("ChromeosChrootPostinst complete\n");
  return true;
}

}  // namespace

bool RunPostInstall(const base::FilePath& install_dev,
                    const base::FilePath& install_dir,
                    BiosType bios_type,
                    DeferUpdateAction defer_update_action,
                    bool force_update_firmware,
                    int* exit_code) {
  InstallConfig install_config;

  if (!ConfigureInstall(install_dev, install_dir, bios_type,
                        defer_update_action, force_update_firmware,
                        &install_config)) {
    LOG(ERROR) << "Configure failed.";
    // In the failure case don't try to use `install_config.bios_type`, we don't
    // want to rely on the implementation of `ConfigureInstall`.
    SendBiosTypeUMA(bios_type);
    return false;
  }

  // Bios type may only be detected in `ConfigureInstall`, so make sure to send
  // the detected value.
  SendBiosTypeUMA(install_config.bios_type);

  // Log how we are configured.
  LOG(INFO) << "PostInstall Configured: " << install_config.slot.c_str() << ", "
            << install_config.root.device() << ", "
            << install_config.kernel.device() << ", "
            << install_config.boot.device();

  string uname;
  if (GetKernelInfo(&uname)) {
    LOG(INFO) << "Current Kernel Info: " << uname.c_str();
  }

  string lsb_contents;
  // If we can read the lsb-release we are updating TO, log it
  if (base::ReadFileToString(
          install_config.root.mount().Append("etc/lsb-release"),
          &lsb_contents)) {
    LOG(INFO) << "lsb-release inside the new rootfs:\n" << lsb_contents.c_str();
  }

  if (!ChromeosChrootPostinst(install_config, exit_code)) {
    LOG(ERROR) << "PostInstall Failed.";
    return false;
  }

  LOG(INFO) << "Syncing filesystem at end of postinst...";
  sync();

  // Need to reduce the amount of time as much as possible for defer update
  // APPLY action as it will be noticeable to users. Only sleep for `kAuto`.
  switch (install_config.defer_update_action) {
    case DeferUpdateAction::kAuto:
      // Sync doesn't appear to sync out cgpt changes, so
      // let them flush themselves. (chromium-os:35992)
      sleep(10);
      break;
    case DeferUpdateAction::kApply:
      break;
    case DeferUpdateAction::kHold:
      break;
  }

  return true;
}
