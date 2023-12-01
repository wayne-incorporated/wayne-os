// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/updater/cros_fp_updater.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/process/launch.h>
#include <base/strings/string_split.h>
#include <base/time/time.h>
#include <chromeos/ec/ec_commands.h>
#include <cros_config/cros_config_interface.h>
#include <libec/ec_command.h>

#include "biod/biod_config.h"
#include "biod/biod_system.h"
#include "biod/cros_fp_device.h"
#include "biod/cros_fp_firmware.h"
#include "biod/updater/update_reason.h"
#include "biod/updater/update_status.h"
#include "biod/updater/update_utils.h"
#include "biod/utils.h"

namespace {

constexpr base::TimeDelta kBootSplashScreenLaunchTimeout = base::Seconds(10);

constexpr char kFlashromPath[] = "/usr/sbin/flashrom";
constexpr char kRebootFile[] = "/tmp/force_reboot_after_fw_update";

bool UpdateImage(const biod::CrosFpDeviceUpdate& ec_dev,
                 const biod::CrosFpBootUpdateCtrl& boot_ctrl,
                 const biod::CrosFpFirmware& fw,
                 enum ec_image image) {
  if (boot_ctrl.TriggerBootUpdateSplash()) {
    DLOG(INFO) << "Successfully launched update splash screen.";
  } else {
    DLOG(ERROR) << "Failed to launch boot update splash screen, continuing.";
  }
  if (!ec_dev.Flash(fw, image)) {
    LOG(ERROR) << "Failed to flash "
               << biod::CrosFpDeviceUpdate::EcCurrentImageToString(image)
               << ", aborting.";
    return false;
  }

  // If we updated the FW, we need to reboot (b/119222361).
  // We only reboot if we succeed, since we do not want to
  // create a reboot loop.
  if (boot_ctrl.ScheduleReboot()) {
    DLOG(INFO) << "Successfully scheduled reboot after update.";
  } else {
    DLOG(ERROR) << "Failed to schedule reboot after update, continuing.";
  }
  return true;
}

}  // namespace

namespace biod {

bool GetAppOutputAndErrorWithTimeout(const base::CommandLine& cmd_input,
                                     const base::TimeDelta& delta,
                                     std::string* output) {
  std::string delta_str = std::to_string(delta.InSecondsF());
  base::CommandLine cmd_timeout{base::FilePath("timeout")};
  cmd_timeout.AppendSwitchASCII("kill-after", "1s");
  cmd_timeout.AppendSwitchASCII("signal", "QUIT");
  cmd_timeout.AppendSwitch("verbose");
  cmd_timeout.AppendSwitch("preserve-status");
  cmd_timeout.AppendArg(delta_str);
  base::CommandLine cmd_input_copy = cmd_input;
  cmd_input_copy.PrependWrapper(cmd_timeout.GetCommandLineString());
  return base::GetAppOutputAndError(cmd_input_copy, output);
}

std::vector<std::string> kNeedResetBoards{kFpBoardDartmonkey, kFpBoardNami,
                                          kFpBoardNocturne};

std::string CrosFpDeviceUpdate::EcCurrentImageToString(enum ec_image image) {
  switch (image) {
    case EC_IMAGE_UNKNOWN:
      return "UNKNOWN";
    case EC_IMAGE_RO:
      return "RO";
    case EC_IMAGE_RW:
      return "RW";
    default:
      return "INVALID";
  }
  NOTREACHED();
}

std::optional<ec::CrosFpDeviceInterface::EcVersion>
CrosFpDeviceUpdate::GetVersion() const {
  auto fd = base::ScopedFD(open(CrosFpDevice::kCrosFpPath, O_RDWR | O_CLOEXEC));
  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to open fingerprint device, while fetching version.";
    return std::nullopt;
  }

  auto version = biod::CrosFpDevice::GetVersion(fd);
  if (!version) {
    LOG(ERROR) << "Failed to read fingerprint version.";
    return std::nullopt;
  }
  return version;
}

bool CrosFpDeviceUpdate::IsFlashProtectEnabled(bool* status) const {
  DCHECK(status != nullptr);

  auto fd = base::ScopedFD(open(CrosFpDevice::kCrosFpPath, O_RDWR | O_CLOEXEC));
  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to open fingerprint device, while fetching "
                  "flashprotect status.";
    return false;
  }

  ec::EcCommand<struct ec_params_flash_protect,
                struct ec_response_flash_protect>
      fp_cmd(EC_CMD_FLASH_PROTECT, EC_VER_FLASH_PROTECT);
  fp_cmd.Req()->mask = 0;
  fp_cmd.Req()->flags = 0;
  if (!fp_cmd.Run(fd.get())) {
    LOG(ERROR) << "Failed to fetch fingerprint flashprotect flags.";
    return false;
  }
  *status = fp_cmd.Resp()->flags & EC_FLASH_PROTECT_RO_NOW;
  return true;
}

bool CrosFpDeviceUpdate::Flash(const CrosFpFirmware& fw,
                               enum ec_image image) const {
  DCHECK(image == EC_IMAGE_RO || image == EC_IMAGE_RW);

  std::string image_str = EcCurrentImageToString(image);

  LOG(INFO) << "Flashing " << image_str << " of FPMCU.";

  base::CommandLine cmd{base::FilePath(kFlashromPath)};
  cmd.AppendSwitch("noverify-all");
  cmd.AppendSwitchASCII("programmer", "ec:type=fp");
  cmd.AppendSwitchASCII("image", "EC_" + image_str);

  // The write switch does not work with --write=<PATH> syntax.
  // It must appear as --write <PATH>.
  cmd.AppendSwitch("write");
  cmd.AppendArgPath(fw.GetPath());

  LOG(INFO) << "Launching '" << cmd.GetCommandLineString() << "'.";

  std::string cmd_output;
  base::TimeDelta timeout_time = base::Minutes(2);
  bool status = GetAppOutputAndErrorWithTimeout(cmd, timeout_time, &cmd_output);
  const auto lines = base::SplitStringPiece(
      cmd_output, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto line : lines) {
    LOG(INFO) << cmd.GetProgram().BaseName().value() << ": " << line;
  }
  if (!status) {
    LOG(ERROR) << "FPMCU flash utility failed.";
    return false;
  }
  return true;
}

// Show splashscreen about critical update to the user so they don't
// reboot in the middle, potentially during RO update.
bool CrosFpBootUpdateCtrl::TriggerBootUpdateSplash() const {
  LOG(INFO) << "Launching update splash screen.";

  base::CommandLine cmd{base::FilePath("chromeos-boot-alert")};
  cmd.AppendArg("update_firmware");

  DLOG(INFO) << "Launching '" << cmd.GetCommandLineString() << "'.";

  std::string cmd_output;
  bool status = GetAppOutputAndErrorWithTimeout(
      cmd, kBootSplashScreenLaunchTimeout, &cmd_output);
  const auto lines = base::SplitStringPiece(
      cmd_output, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto line : lines) {
    LOG(INFO) << cmd.GetProgram().BaseName().value() << ": " << line;
  }
  if (!status) {
    LOG(ERROR) << "Update splash screen launcher failed.";
    return false;
  }
  return true;
}

bool CrosFpBootUpdateCtrl::ScheduleReboot() const {
  LOG(INFO) << "Scheduling post update reboot.";

  // Trigger a file create.
  base::File file(base::FilePath(kRebootFile),
                  base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!file.IsValid()) {
    LOG(ERROR) << "Failed to schedule post update reboot: "
               << base::File::ErrorToString(file.error_details());
    return false;
  }
  return true;
}

namespace updater {

UpdateResult DoUpdate(const CrosFpDeviceUpdate& ec_dev,
                      const CrosFpBootUpdateCtrl& boot_ctrl,
                      const CrosFpFirmware& fw,
                      const BiodSystem& system,
                      brillo::CrosConfigInterface* cros_config) {
  bool attempted = false;
  UpdateResult result = {UpdateStatus::kUpdateNotNecessary,
                         UpdateReason::kNone};

  // Grab the new firmware file's versions.
  CrosFpFirmware::ImageVersion fw_version = fw.GetVersion();

  // Grab the FPMCU's current firmware version and current active image.
  auto ecver = ec_dev.GetVersion();
  if (!ecver) {
    result.status = UpdateStatus::kUpdateFailedGetVersion;
    return result;
  }

  LOG(INFO) << "Hardware write protect: "
            << (system.HardwareWriteProtectIsEnabled() ? "enabled"
                                                       : "disabled");

  // If write protection is not enabled, the RO firmware should
  // be updated first, as this allows for re-keying (dev->premp->mp)
  // and non-forward compatible changes.
  bool flashprotect_enabled;
  if (!ec_dev.IsFlashProtectEnabled(&flashprotect_enabled)) {
    result.status = UpdateStatus::kUpdateFailedFlashProtect;
    return result;
  }
  if (!flashprotect_enabled) {
    LOG(INFO) << "Flashprotect is disabled.";
    if (ecver->ro_version != fw_version.ro_version) {
      result.reason |= UpdateReason::kMismatchROVersion;
      attempted = true;
      LOG(INFO) << "FPMCU RO firmware mismatch, updating.";
      if (!UpdateImage(ec_dev, boot_ctrl, fw, EC_IMAGE_RO)) {
        result.status = UpdateStatus::kUpdateFailedRO;
        return result;
      }
    } else {
      LOG(INFO) << "FPMCU RO firmware is up to date.";
    }
  } else {
    LOG(INFO) << "FPMCU RO firmware is protected: no update.";
  }

  // The firmware should be updated if RO is active (i.e. RW is corrupted) or if
  // the firmware version available on the rootfs is different from the RW.
  bool active_image_ro = ecver->current_image != EC_IMAGE_RW;
  bool rw_mismatch = ecver->rw_version != fw_version.rw_version;
  if (active_image_ro) {
    result.reason |= UpdateReason::kActiveImageRO;
  }
  if (rw_mismatch) {
    result.reason |= UpdateReason::kMismatchRWVersion;
  }
  if (active_image_ro || rw_mismatch) {
    attempted = true;
    LOG(INFO)
        << "FPMCU RW firmware mismatch or failed RW boot detected, updating.";
    if (!UpdateImage(ec_dev, boot_ctrl, fw, EC_IMAGE_RW)) {
      result.status = UpdateStatus::kUpdateFailedRW;
      return result;
    }

    // Dartmonkey FPMCU board won't boot after update when HW WP is off but
    // SW WP is on until power reset. See http://go/flashrom-fpmcu-wp-bug
    // for details.
    std::string board_name = biod::FingerprintBoard(cros_config).value_or("");
    bool board_need_reset =
        std::find(kNeedResetBoards.begin(), kNeedResetBoards.end(),
                  board_name) != kNeedResetBoards.end();
    if (board_need_reset && flashprotect_enabled &&
        !system.HardwareWriteProtectIsEnabled()) {
      result.status = UpdateStatus::kUpdateSucceededNeedPowerReset;
      return result;
    }
  } else {
    LOG(INFO) << "FPMCU RW firmware is up to date.";
  }

  result.status = attempted ? UpdateStatus::kUpdateSucceeded
                            : UpdateStatus::kUpdateNotNecessary;
  return result;
}

}  // namespace updater
}  // namespace biod
