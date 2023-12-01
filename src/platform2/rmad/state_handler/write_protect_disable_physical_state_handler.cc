// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/write_protect_disable_physical_state_handler.h"

#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>

#include "rmad/constants.h"
#include "rmad/metrics/metrics_utils.h"
#include "rmad/system/power_manager_client_impl.h"
#include "rmad/utils/cr50_utils_impl.h"
#include "rmad/utils/crossystem_utils_impl.h"
#include "rmad/utils/dbus_utils.h"
#include "rmad/utils/write_protect_utils_impl.h"

namespace rmad {

WriteProtectDisablePhysicalStateHandler::
    WriteProtectDisablePhysicalStateHandler(
        scoped_refptr<JsonStore> json_store,
        scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback),
      working_dir_path_(kDefaultWorkingDirPath) {
  cr50_utils_ = std::make_unique<Cr50UtilsImpl>();
  crossystem_utils_ = std::make_unique<CrosSystemUtilsImpl>();
  write_protect_utils_ = std::make_unique<WriteProtectUtilsImpl>();
}

WriteProtectDisablePhysicalStateHandler::
    WriteProtectDisablePhysicalStateHandler(
        scoped_refptr<JsonStore> json_store,
        scoped_refptr<DaemonCallback> daemon_callback,
        const base::FilePath& working_dir_path,
        std::unique_ptr<Cr50Utils> cr50_utils,
        std::unique_ptr<CrosSystemUtils> crossystem_utils,
        std::unique_ptr<WriteProtectUtils> write_protect_utils)
    : BaseStateHandler(json_store, daemon_callback),
      working_dir_path_(working_dir_path),
      cr50_utils_(std::move(cr50_utils)),
      crossystem_utils_(std::move(crossystem_utils)),
      write_protect_utils_(std::move(write_protect_utils)) {}

RmadErrorCode WriteProtectDisablePhysicalStateHandler::InitializeState() {
  if (!state_.has_wp_disable_physical()) {
    auto wp_disable_physical =
        std::make_unique<WriteProtectDisablePhysicalState>();
    // Keep device open if we don't want to wipe the device.
    bool wipe_device;
    if (!json_store_->GetValue(kWipeDevice, &wipe_device)) {
      LOG(ERROR) << "Variable " << kWipeDevice << " not found";
      return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
    }
    wp_disable_physical->set_keep_device_open(!wipe_device);
    state_.set_allocated_wp_disable_physical(wp_disable_physical.release());
  }

  return RMAD_ERROR_OK;
}

void WriteProtectDisablePhysicalStateHandler::RunState() {
  VLOG(1) << "Start polling write protection";
  if (signal_timer_.IsRunning()) {
    signal_timer_.Stop();
  }
  signal_timer_.Start(
      FROM_HERE, kPollInterval, this,
      &WriteProtectDisablePhysicalStateHandler::CheckWriteProtectOffTask);
}

void WriteProtectDisablePhysicalStateHandler::CleanUpState() {
  // Stop the polling loop.
  if (signal_timer_.IsRunning()) {
    signal_timer_.Stop();
  }
}

BaseStateHandler::GetNextStateCaseReply
WriteProtectDisablePhysicalStateHandler::GetNextStateCase(
    const RmadState& state) {
  if (!state.has_wp_disable_physical()) {
    LOG(ERROR) << "RmadState missing |physical write protection| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }

  // The state will reboot automatically when write protect is disabled. Before
  // that, always return RMAD_ERROR_WAIT.
  return NextStateCaseWrapper(RMAD_ERROR_WAIT);
}

BaseStateHandler::GetNextStateCaseReply
WriteProtectDisablePhysicalStateHandler::TryGetNextStateCaseAtBoot() {
  // If conditions are met, we can transition to the next state.
  if (IsReadyForTransition()) {
    if (cr50_utils_->IsFactoryModeEnabled()) {
      json_store_->SetValue(
          kWpDisableMethod,
          WpDisableMethod_Name(
              RMAD_WP_DISABLE_METHOD_PHYSICAL_ASSEMBLE_DEVICE));
      MetricsUtils::SetMetricsValue(
          json_store_, kMetricsWpDisableMethod,
          WpDisableMethod_Name(
              RMAD_WP_DISABLE_METHOD_PHYSICAL_ASSEMBLE_DEVICE));
    } else {
      json_store_->SetValue(
          kWpDisableMethod,
          WpDisableMethod_Name(
              RMAD_WP_DISABLE_METHOD_PHYSICAL_KEEP_DEVICE_OPEN));
      MetricsUtils::SetMetricsValue(
          json_store_, kMetricsWpDisableMethod,
          WpDisableMethod_Name(
              RMAD_WP_DISABLE_METHOD_PHYSICAL_KEEP_DEVICE_OPEN));
    }
    return NextStateCaseWrapper(RmadState::StateCase::kWpDisableComplete);
  }

  // Otherwise, stay on the same state.
  return NextStateCaseWrapper(GetStateCase());
}

bool WriteProtectDisablePhysicalStateHandler::IsReadyForTransition() const {
  // To transition to next state, all the conditions should meet
  // - HWWP should be disabled.
  // - We can skip enabling factory mode, either factory mode is already enabled
  //   or we want to keep the device open.
  // - We have triggered an EC reboot.
  return IsEcRebooted() && CanSkipEnablingFactoryMode() && IsHwwpDisabled();
}

bool WriteProtectDisablePhysicalStateHandler::IsEcRebooted() const {
  // TODO(chenghan): Use ectool to probe ro_at_boot for more precise check.
  bool ec_rebooted = false;
  return json_store_->GetValue(kEcRebooted, &ec_rebooted) && ec_rebooted;
}

bool WriteProtectDisablePhysicalStateHandler::IsHwwpDisabled() const {
  bool hwwp_enabled;
  return (
      write_protect_utils_->GetHardwareWriteProtectionStatus(&hwwp_enabled) &&
      !hwwp_enabled);
}

bool WriteProtectDisablePhysicalStateHandler::CanSkipEnablingFactoryMode()
    const {
  return cr50_utils_->IsFactoryModeEnabled() ||
         state_.wp_disable_physical().keep_device_open();
}

void WriteProtectDisablePhysicalStateHandler::CheckWriteProtectOffTask() {
  VLOG(1) << "Check write protection";

  if (IsHwwpDisabled()) {
    signal_timer_.Stop();
    OnWriteProtectDisabled();
  }
}

void WriteProtectDisablePhysicalStateHandler::OnWriteProtectDisabled() {
  bool powerwash_required = false;
  if (!CanSkipEnablingFactoryMode()) {
    // Enable cr50 factory mode. This no longer reboots the device, so we need
    // to trigger a reboot ourselves.
    if (!cr50_utils_->EnableFactoryMode()) {
      LOG(ERROR) << "Failed to enable factory mode.";
    }
    if (!IsPowerwashDisabled(working_dir_path_)) {
      powerwash_required = true;
    }
  }

  // Chrome picks up the signal and shows the "Preparing to reboot" message.
  daemon_callback_->GetWriteProtectSignalCallback().Run(false);

  // Request RMA mode powerwash if required, then reboot EC.
  if (powerwash_required) {
    reboot_timer_.Start(
        FROM_HERE, kRebootDelay,
        base::BindOnce(&WriteProtectDisablePhysicalStateHandler::
                           RequestRmaPowerwashAndRebootEc,
                       base::Unretained(this)));
  } else {
    reboot_timer_.Start(
        FROM_HERE, kRebootDelay,
        base::BindOnce(&WriteProtectDisablePhysicalStateHandler::RebootEc,
                       base::Unretained(this)));
  }
}

void WriteProtectDisablePhysicalStateHandler::RequestRmaPowerwashAndRebootEc() {
  DLOG(INFO) << "Requesting RMA mode powerwash";
  daemon_callback_->GetExecuteRequestRmaPowerwashCallback().Run(
      base::BindOnce(&WriteProtectDisablePhysicalStateHandler::
                         RequestRmaPowerwashAndRebootEcCallback,
                     base::Unretained(this)));
}

void WriteProtectDisablePhysicalStateHandler::
    RequestRmaPowerwashAndRebootEcCallback(bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to request RMA mode powerwash";
  }
  RebootEc();
}

void WriteProtectDisablePhysicalStateHandler::RebootEc() {
  DLOG(INFO) << "Rebooting EC after physically removing WP";
  json_store_->SetValue(kEcRebooted, true);
  json_store_->Sync();
  daemon_callback_->GetExecuteRebootEcCallback().Run(
      base::BindOnce(&WriteProtectDisablePhysicalStateHandler::RebootEcCallback,
                     base::Unretained(this)));
}

void WriteProtectDisablePhysicalStateHandler::RebootEcCallback(bool success) {
  // Just an informative callback.
  // TODO(chenghan): Send an error to Chrome when the reboot fails.
  if (!success) {
    LOG(ERROR) << "Failed to reboot EC";
  }
}

}  // namespace rmad
