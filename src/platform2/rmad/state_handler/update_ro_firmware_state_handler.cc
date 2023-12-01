// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/update_ro_firmware_state_handler.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/sequence_checker.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/task_traits.h>
#include <base/task/thread_pool.h>
#include <brillo/file_utils.h>
#include <re2/re2.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_constants.h"
#include "rmad/logs/logs_utils.h"
#include "rmad/system/power_manager_client_impl.h"
#include "rmad/udev/udev_device.h"
#include "rmad/udev/udev_utils.h"
#include "rmad/utils/cmd_utils_impl.h"
#include "rmad/utils/dbus_utils.h"
#include "rmad/utils/futility_utils_impl.h"
#include "rmad/utils/write_protect_utils_impl.h"

namespace {

constexpr char kFirmwareUpdaterPath[] = "/var/lib/rmad/chromeos-firmwareupdate";

bool GetDeviceIdFromRootfsDeviceFile(const std::string& device_file,
                                     char* device_id) {
  re2::StringPiece string_piece(device_file);
  re2::RE2 regexp("/dev/sd([[:lower:]])3");
  std::string device_id_string;
  if (RE2::FullMatch(string_piece, regexp, &device_id_string)) {
    *device_id = device_id_string[0];
    return true;
  }
  return false;
}

}  // namespace

namespace rmad {

UpdateRoFirmwareStateHandler::UpdateRoFirmwareStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback), is_mocked_(false) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
  udev_utils_ = std::make_unique<UdevUtilsImpl>();
  cmd_utils_ = std::make_unique<CmdUtilsImpl>();
  write_protect_utils_ = std::make_unique<WriteProtectUtilsImpl>();
  power_manager_client_ =
      std::make_unique<PowerManagerClientImpl>(GetSystemBus());
}

UpdateRoFirmwareStateHandler::UpdateRoFirmwareStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback,
    std::unique_ptr<UdevUtils> udev_utils,
    std::unique_ptr<CmdUtils> cmd_utils,
    std::unique_ptr<WriteProtectUtils> write_protect_utils,
    std::unique_ptr<PowerManagerClient> power_manager_client)
    : BaseStateHandler(json_store, daemon_callback),
      is_mocked_(true),
      udev_utils_(std::move(udev_utils)),
      cmd_utils_(std::move(cmd_utils)),
      write_protect_utils_(std::move(write_protect_utils)),
      power_manager_client_(std::move(power_manager_client)) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

RmadErrorCode UpdateRoFirmwareStateHandler::InitializeState() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Make sure HWWP is off before initializing the state.
  if (bool hwwp_enabled;
      !write_protect_utils_->GetHardwareWriteProtectionStatus(&hwwp_enabled) ||
      hwwp_enabled) {
    return RMAD_ERROR_WP_ENABLED;
  }

  if (!state_.has_update_ro_firmware()) {
    auto update_ro_firmware = std::make_unique<UpdateRoFirmwareState>();
    update_ro_firmware->set_optional(CanSkipUpdate());
    state_.set_allocated_update_ro_firmware(update_ro_firmware.release());

    sequenced_task_runner_ = base::SequencedTaskRunner::GetCurrentDefault();
    updater_task_runner_ = base::ThreadPool::CreateTaskRunner(
        {base::TaskPriority::BEST_EFFORT, base::MayBlock()});
  }

  if (bool firmware_updated;
      json_store_->GetValue(kFirmwareUpdated, &firmware_updated) &&
      firmware_updated) {
    status_ = RMAD_UPDATE_RO_FIRMWARE_COMPLETE;
    RecordFirmwareUpdateStatusToLogs(json_store_,
                                     FirmwareUpdateStatus::kFirmwareComplete);
  } else {
    status_ = RMAD_UPDATE_RO_FIRMWARE_WAIT_USB;
  }
  usb_detected_ = !GetRemovableBlockDevices().empty();
  return RMAD_ERROR_OK;
}

void UpdateRoFirmwareStateHandler::RunState() {
  StartSignalTimer();
  StartPollingTimer();
}

void UpdateRoFirmwareStateHandler::CleanUpState() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  StopSignalTimer();
  StopPollingTimer();
}

void UpdateRoFirmwareStateHandler::StartSignalTimer() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  status_signal_timer_.Start(
      FROM_HERE, kSignalInterval, this,
      &UpdateRoFirmwareStateHandler::SendFirmwareUpdateSignal);
}

void UpdateRoFirmwareStateHandler::StopSignalTimer() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (status_signal_timer_.IsRunning()) {
    status_signal_timer_.Stop();
  }
}

void UpdateRoFirmwareStateHandler::StartPollingTimer() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  check_usb_timer_.Start(FROM_HERE, kPollInterval, this,
                         &UpdateRoFirmwareStateHandler::WaitUsb);
}

void UpdateRoFirmwareStateHandler::StopPollingTimer() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (check_usb_timer_.IsRunning()) {
    check_usb_timer_.Stop();
  }
}

BaseStateHandler::GetNextStateCaseReply
UpdateRoFirmwareStateHandler::GetNextStateCase(const RmadState& state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!state.has_update_ro_firmware()) {
    LOG(ERROR) << "RmadState missing |update RO firmware| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }
  const UpdateRoFirmwareState& update_ro_firmware = state.update_ro_firmware();
  if (update_ro_firmware.choice() ==
      UpdateRoFirmwareState::RMAD_UPDATE_CHOICE_UNKNOWN) {
    LOG(ERROR) << "RmadState missing |udpate| argument.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_ARGS_MISSING);
  }
  if (!state_.update_ro_firmware().optional() &&
      update_ro_firmware.choice() ==
          UpdateRoFirmwareState::RMAD_UPDATE_CHOICE_SKIP) {
    LOG(ERROR) << "RO firmware update is mandatory.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_ARGS_VIOLATION);
  }

  switch (state.update_ro_firmware().choice()) {
    case UpdateRoFirmwareState::RMAD_UPDATE_CHOICE_CONTINUE:
      if (status_ != RMAD_UPDATE_RO_FIRMWARE_COMPLETE) {
        return NextStateCaseWrapper(RMAD_ERROR_WAIT);
      }
      // Firmware update completed. Same behavior as SKIP.
      [[fallthrough]];
    case UpdateRoFirmwareState::RMAD_UPDATE_CHOICE_SKIP:
      if (bool mlb_repair;
          json_store_->GetValue(kMlbRepair, &mlb_repair) && mlb_repair) {
        return NextStateCaseWrapper(RmadState::StateCase::kRestock);
      }
      return NextStateCaseWrapper(RmadState::StateCase::kUpdateDeviceInfo);
    default:
      break;
  }
  NOTREACHED();
  return NextStateCaseWrapper(RmadState::StateCase::STATE_NOT_SET,
                              RMAD_ERROR_NOT_SET,
                              RMAD_ADDITIONAL_ACTIVITY_NOTHING);
}

bool UpdateRoFirmwareStateHandler::CanSkipUpdate() {
  if (bool firmware_updated;
      json_store_->GetValue(kFirmwareUpdated, &firmware_updated) &&
      firmware_updated) {
    return true;
  }
  if (bool ro_verified;
      json_store_->GetValue(kRoFirmwareVerified, &ro_verified) && ro_verified) {
    return true;
  }
  return false;
}

void UpdateRoFirmwareStateHandler::SendFirmwareUpdateSignal() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  daemon_callback_->GetUpdateRoFirmwareSignalCallback().Run(status_);
  // |usb_detected_| is not up-to-date when firmware update is in progress.
  daemon_callback_->GetExternalDiskSignalCallback().Run(usb_detected_);
}

std::vector<std::unique_ptr<UdevDevice>>
UpdateRoFirmwareStateHandler::GetRemovableBlockDevices() const {
  std::vector<std::unique_ptr<UdevDevice>> devices =
      udev_utils_->EnumerateBlockDevices();
  devices.erase(std::remove_if(devices.begin(), devices.end(),
                               [](const std::unique_ptr<UdevDevice>& device) {
                                 return !device->IsRemovable();
                               }),
                devices.end());
  return devices;
}

void UpdateRoFirmwareStateHandler::WaitUsb() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Update |usb_detected_|.
  std::vector<std::unique_ptr<UdevDevice>> removable_devices =
      GetRemovableBlockDevices();
  usb_detected_ = !removable_devices.empty();
  // Do nothing if firmware update is completed.
  if (status_ == RMAD_UPDATE_RO_FIRMWARE_COMPLETE) {
    return;
  }
  // Update |status_| if firmware update is not completed.
  if (removable_devices.empty()) {
    // External disk is not detected. Keep waiting.
    status_ = RMAD_UPDATE_RO_FIRMWARE_WAIT_USB;
  } else if (status_ == RMAD_UPDATE_RO_FIRMWARE_WAIT_USB) {
    // External disk is just detected. Look for rootfs partition.
    for (const auto& device : removable_devices) {
      const std::string& device_node = device->GetDeviceNode();
      if (char device_id;
          GetDeviceIdFromRootfsDeviceFile(device_node, &device_id)) {
        // Only try to mount the first root partition found. Stop the polling
        // to prevent mounting twice.
        StopPollingTimer();
        daemon_callback_->GetExecuteMountAndCopyFirmwareUpdaterCallback().Run(
            static_cast<uint8_t>(device_id),
            base::BindOnce(&UpdateRoFirmwareStateHandler::OnCopyCompleted,
                           base::Unretained(this)));
        return;
      }
    }
    // External disk is detected but no rootfs partition found. Treat this
    // case as file not found.
    status_ = RMAD_UPDATE_RO_FIRMWARE_FILE_NOT_FOUND;
    RecordFirmwareUpdateStatusToLogs(
        json_store_, FirmwareUpdateStatus::kUsbPluggedInFileNotFound);
  }
}

void UpdateRoFirmwareStateHandler::OnCopyCompleted(bool copy_success) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  FirmwareUpdateStatus firmware_update_status;
  if (copy_success) {
    DLOG(INFO) << "Found firmware updater";
    status_ = RMAD_UPDATE_RO_FIRMWARE_UPDATING;
    updater_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&UpdateRoFirmwareStateHandler::OnCopySuccess,
                                  base::Unretained(this)));
    firmware_update_status = FirmwareUpdateStatus::kUsbPluggedIn;
  } else {
    LOG(WARNING) << "Cannot find firmware updater";
    status_ = RMAD_UPDATE_RO_FIRMWARE_FILE_NOT_FOUND;
    DCHECK(!check_usb_timer_.IsRunning());
    StartPollingTimer();
    firmware_update_status = FirmwareUpdateStatus::kUsbPluggedInFileNotFound;
  }
  RecordFirmwareUpdateStatusToLogs(json_store_, firmware_update_status);
}

void UpdateRoFirmwareStateHandler::OnCopySuccess() {
  // This is run in |updater_task_runner_|.
  const base::FilePath updater_path(kFirmwareUpdaterPath);
  // Check again that the copied firmware updater exists.
  CHECK(base::PathExists(updater_path));
  bool update_success = RunFirmwareUpdater();
  // Remove the copied firmware updater.
  CHECK(base::DeleteFile(updater_path));

  sequenced_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&UpdateRoFirmwareStateHandler::OnUpdateCompleted,
                     base::Unretained(this), update_success));
}

void UpdateRoFirmwareStateHandler::OnUpdateCompleted(bool update_success) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  FirmwareUpdateStatus firmware_update_status;
  if (update_success) {
    json_store_->SetValue(kFirmwareUpdated, true);
    status_ = RMAD_UPDATE_RO_FIRMWARE_REBOOTING;
    PostRebootTask();
    firmware_update_status = FirmwareUpdateStatus::kFirmwareUpdated;
  } else {
    // Treat update failure as "no valid updater file".
    // TODO(chenghan): Add an enum for update failure.
    status_ = RMAD_UPDATE_RO_FIRMWARE_FILE_NOT_FOUND;
    DCHECK(!check_usb_timer_.IsRunning());
    StartPollingTimer();
    firmware_update_status = FirmwareUpdateStatus::kUsbPluggedInFileNotFound;
  }
  RecordFirmwareUpdateStatusToLogs(json_store_, firmware_update_status);
}

bool UpdateRoFirmwareStateHandler::RunFirmwareUpdater() {
  // This is run in |updater_task_runner_|.
  // For security reasons, we should only run the firmware update when HWWP and
  // SWWP are off.

  // First make sure the state handler is not mocked so the following
  // HWWP/SWWP checks are real.
  if (is_mocked_) {
    LOG(ERROR) << "State handler is mocked. Aborting firmware update.";
    return false;
  }

  // Make sure HWWP is off.
  if (bool hwwp_enabled;
      !write_protect_utils_->GetHardwareWriteProtectionStatus(&hwwp_enabled) ||
      hwwp_enabled) {
    LOG(ERROR) << "HWWP is enabled. Aborting firmware update.";
    return false;
  }

  // Make sure AP/EC WP are off.
  if (bool enabled;
      !write_protect_utils_->GetApWriteProtectionStatus(&enabled) || enabled) {
    LOG(ERROR) << "AP SWWP is enabled. Aborting firmware update.";
    return false;
  }
  if (bool enabled;
      !write_protect_utils_->GetEcWriteProtectionStatus(&enabled) || enabled) {
    LOG(ERROR) << "EC SWWP is enabled. Aborting firmware update.";
    return false;
  }

  // All checks pass. Run the firmware updater.
  bool update_success = false;
  if (std::string output; cmd_utils_->GetOutputAndError(
          {"futility", "update", "-a", kFirmwareUpdaterPath, "--mode=recovery",
           "--force"},
          &output)) {
    DLOG(INFO) << "Firmware updater success";
    update_success = true;
  } else {
    LOG(ERROR) << "Firmware updater failed";
    LOG(ERROR) << output;
  }
  return update_success;
}

void UpdateRoFirmwareStateHandler::PostRebootTask() {
  sequenced_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&UpdateRoFirmwareStateHandler::Reboot,
                     base::Unretained(this)),
      kRebootDelay);
}

void UpdateRoFirmwareStateHandler::Reboot() {
  if (!power_manager_client_->Restart()) {
    LOG(ERROR) << "Failed to reboot";
  }
}

}  // namespace rmad
