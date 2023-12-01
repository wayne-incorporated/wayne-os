// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/provision_device_state_handler.h"

#include <openssl/rand.h>

#include <algorithm>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/synchronization/lock.h>
#include <base/task/task_traits.h>
#include <base/task/thread_pool.h>

#include "rmad/constants.h"
#include "rmad/ssfc/ssfc_prober.h"
#include "rmad/system/power_manager_client_impl.h"
#include "rmad/utils/calibration_utils.h"
#include "rmad/utils/cbi_utils_impl.h"
#include "rmad/utils/cmd_utils_impl.h"
#include "rmad/utils/cr50_utils_impl.h"
#include "rmad/utils/cros_config_utils_impl.h"
#include "rmad/utils/dbus_utils.h"
#include "rmad/utils/iio_sensor_probe_utils_impl.h"
#include "rmad/utils/json_store.h"
#include "rmad/utils/vpd_utils_impl.h"
#include "rmad/utils/write_protect_utils_impl.h"

namespace {

constexpr int kStableDeviceSecretSize = 32;

constexpr double kProgressComplete = 1.0;
// TODO(chenghan): Uncomment this when we have a non-blocking error.
// constexpr double kProgressFailedNonblocking = -1.0;
constexpr double kProgressFailedBlocking = -2.0;
constexpr double kProgressInit = 0.0;
constexpr double kProgressGetDestination = 0.2;
constexpr double kProgressGetModelName = 0.3;
constexpr double kProgressWriteSsfc = 0.5;
constexpr double kProgressUpdateStableDeviceSecret = 0.6;
constexpr double kProgressFlushOutVpdCache = 0.7;
constexpr double kProgressResetGbbFlags = 0.8;
constexpr double kProgressSetBoardId = kProgressComplete;

constexpr char kEmptyBoardIdType[] = "ffffffff";
constexpr char kTestBoardIdType[] = "5a5a4352";  // ZZCR.
constexpr char kCustomLabelPvtBoardIdFlags[] = "00003f80";

const std::vector<std::string> kResetGbbFlagsArgv = {
    "/usr/bin/futility", "gbb", "--set", "--flash", "--flags=0"};

}  // namespace

namespace rmad {

ProvisionDeviceStateHandler::ProvisionDeviceStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback),
      working_dir_path_(kDefaultWorkingDirPath),
      should_calibrate_(false),
      sensor_integrity_(false) {
  ssfc_prober_ = std::make_unique<SsfcProberImpl>();
  power_manager_client_ =
      std::make_unique<PowerManagerClientImpl>(GetSystemBus());
  cbi_utils_ = std::make_unique<CbiUtilsImpl>();
  cmd_utils_ = std::make_unique<CmdUtilsImpl>();
  cr50_utils_ = std::make_unique<Cr50UtilsImpl>();
  cros_config_utils_ = std::make_unique<CrosConfigUtilsImpl>();
  write_protect_utils_ = std::make_unique<WriteProtectUtilsImpl>();
  iio_sensor_probe_utils_ = std::make_unique<IioSensorProbeUtilsImpl>();
  vpd_utils_ = std::make_unique<VpdUtilsImpl>();
  status_.set_status(ProvisionStatus::RMAD_PROVISION_STATUS_UNKNOWN);
  status_.set_progress(kProgressInit);
  status_.set_error(ProvisionStatus::RMAD_PROVISION_ERROR_UNKNOWN);
}

ProvisionDeviceStateHandler::ProvisionDeviceStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback,
    const base::FilePath& working_dir_path,
    std::unique_ptr<SsfcProber> ssfc_prober,
    std::unique_ptr<PowerManagerClient> power_manager_client,
    std::unique_ptr<CbiUtils> cbi_utils,
    std::unique_ptr<CmdUtils> cmd_utils,
    std::unique_ptr<Cr50Utils> cr50_utils,
    std::unique_ptr<CrosConfigUtils> cros_config_utils,
    std::unique_ptr<WriteProtectUtils> write_protect_utils,
    std::unique_ptr<IioSensorProbeUtils> iio_sensor_probe_utils,
    std::unique_ptr<VpdUtils> vpd_utils)
    : BaseStateHandler(json_store, daemon_callback),
      working_dir_path_(working_dir_path),
      ssfc_prober_(std::move(ssfc_prober)),
      power_manager_client_(std::move(power_manager_client)),
      cbi_utils_(std::move(cbi_utils)),
      cmd_utils_(std::move(cmd_utils)),
      cr50_utils_(std::move(cr50_utils)),
      cros_config_utils_(std::move(cros_config_utils)),
      write_protect_utils_(std::move(write_protect_utils)),
      iio_sensor_probe_utils_(std::move(iio_sensor_probe_utils)),
      vpd_utils_(std::move(vpd_utils)),
      should_calibrate_(false),
      sensor_integrity_(false) {
  status_.set_status(ProvisionStatus::RMAD_PROVISION_STATUS_UNKNOWN);
  status_.set_progress(kProgressInit);
  status_.set_error(ProvisionStatus::RMAD_PROVISION_ERROR_UNKNOWN);
}

RmadErrorCode ProvisionDeviceStateHandler::InitializeState() {
  if (!state_.has_provision_device() && !RetrieveState()) {
    state_.set_allocated_provision_device(new ProvisionDeviceState);
  }

  if (!task_runner_) {
    task_runner_ = base::ThreadPool::CreateSequencedTaskRunner(
        {base::TaskPriority::BEST_EFFORT, base::MayBlock()});
  }

  // If status_name is set in |json_store_|, it means it has been provisioned.
  // We should restore the status and let users decide.
  ProvisionStatus::Status provision_status = GetProgress().status();
  if (std::string status_name;
      json_store_->GetValue(kProvisionFinishedStatus, &status_name) &&
      ProvisionStatus::Status_Parse(status_name, &provision_status)) {
    UpdateStatus(provision_status, kProgressInit);
    if (provision_status == ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE ||
        provision_status ==
            ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_NON_BLOCKING) {
      InitializeCalibrationTask();
    }
  }

  return RMAD_ERROR_OK;
}

void ProvisionDeviceStateHandler::RunState() {
  if (status_.status() == ProvisionStatus::RMAD_PROVISION_STATUS_UNKNOWN) {
    StartProvision();
  }
  StartStatusTimer();
}

void ProvisionDeviceStateHandler::CleanUpState() {
  StopStatusTimer();
}

BaseStateHandler::GetNextStateCaseReply
ProvisionDeviceStateHandler::GetNextStateCase(const RmadState& state) {
  if (!state.has_provision_device()) {
    LOG(ERROR) << "RmadState missing |provision| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }

  state_ = state;
  StoreState();
  const ProvisionStatus& status = GetProgress();
  switch (state.provision_device().choice()) {
    case ProvisionDeviceState::RMAD_PROVISION_CHOICE_UNKNOWN:
      return NextStateCaseWrapper(RMAD_ERROR_REQUEST_ARGS_MISSING);
    case ProvisionDeviceState::RMAD_PROVISION_CHOICE_CONTINUE:
      switch (status.status()) {
        case ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS:
          return NextStateCaseWrapper(RMAD_ERROR_WAIT);
        case ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE:
          [[fallthrough]];
        case ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_NON_BLOCKING:
          json_store_->SetValue(kProvisionFinishedStatus,
                                ProvisionStatus::Status_Name(status.status()));
          // Schedule a reboot after |kRebootDelay| seconds and return.
          reboot_timer_.Start(FROM_HERE, kRebootDelay, this,
                              &ProvisionDeviceStateHandler::Reboot);
          return NextStateCaseWrapper(GetStateCase(), RMAD_ERROR_EXPECT_REBOOT,
                                      RMAD_ADDITIONAL_ACTIVITY_REBOOT);
        case ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING:
          return NextStateCaseWrapper(RMAD_ERROR_PROVISIONING_FAILED);
        default:
          break;
      }
      break;
    case ProvisionDeviceState::RMAD_PROVISION_CHOICE_RETRY:
      StartProvision();
      StartStatusTimer();
      return NextStateCaseWrapper(RMAD_ERROR_WAIT);
    default:
      break;
  }

  NOTREACHED();
  return NextStateCaseWrapper(RMAD_ERROR_TRANSITION_FAILED);
}

BaseStateHandler::GetNextStateCaseReply
ProvisionDeviceStateHandler::TryGetNextStateCaseAtBoot() {
  // If the status is already complete or non-blocking at startup, we should go
  // to the next state. Otherwise, don't transition.
  switch (GetProgress().status()) {
    case ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE:
      [[fallthrough]];
    case ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_NON_BLOCKING:
      if (should_calibrate_) {
        if (sensor_integrity_) {
          return NextStateCaseWrapper(RmadState::StateCase::kSetupCalibration);
        } else {
          // TODO(genechang): Go to kCheckCalibration for the user to check.
          return NextStateCaseWrapper(RmadState::StateCase::kSetupCalibration);
        }
      } else if (bool wipe_device;
                 json_store_->GetValue(kWipeDevice, &wipe_device) &&
                 !wipe_device) {
        return NextStateCaseWrapper(RmadState::StateCase::kWpEnablePhysical);
      } else {
        return NextStateCaseWrapper(RmadState::StateCase::kFinalize);
      }
    default:
      break;
  }

  return NextStateCaseWrapper(RMAD_ERROR_TRANSITION_FAILED);
}

void ProvisionDeviceStateHandler::InitializeCalibrationTask() {
  // There are several situations:
  // 1. replaced & probed -> calibrate
  // 2. probed only -> skip
  // 3. replaced only w/ mlb repair-> ignore
  // 4. replaced only w/o mlb repair -> error

  InstructionCalibrationStatusMap calibration_map;

  std::set<RmadComponent> replaced_components_need_calibration;
  if (!IsCalibrationDisabled(working_dir_path_)) {
    if (bool mlb_repair;
        json_store_->GetValue(kMlbRepair, &mlb_repair) && mlb_repair) {
      // Potentially everything needs to be calibrated when MLB is repaired.
      for (const RmadComponent component : kComponentsNeedManualCalibration) {
        replaced_components_need_calibration.insert(component);
      }
    } else if (std::vector<std::string> replaced_component_names;
               json_store_->GetValue(kReplacedComponentNames,
                                     &replaced_component_names)) {
      for (const std::string& component_name : replaced_component_names) {
        RmadComponent component;
        CHECK(RmadComponent_Parse(component_name, &component));
        if (kComponentsNeedManualCalibration.contains(component)) {
          replaced_components_need_calibration.insert(component);
        }
      }
    }
  }

  // This is the part where we probe sensors through the iioservice provided by
  // the sensor team, which is different from the runtime probe service.
  std::set<RmadComponent> probed_components = iio_sensor_probe_utils_->Probe();

  sensor_integrity_ =
      CheckSensorStatusIntegrity(replaced_components_need_calibration,
                                 probed_components, &calibration_map);

  // Update probeable components using probe results.
  for (RmadComponent component : probed_components) {
    // Ignore the components that cannot be calibrated.
    if (!kComponentsNeedManualCalibration.contains(component)) {
      continue;
    }

    // 1. replaced & probed -> calibrate
    // 2. probed only -> skip
    if (replaced_components_need_calibration.count(component)) {
      calibration_map[GetCalibrationSetupInstruction(component)][component] =
          CalibrationComponentStatus::RMAD_CALIBRATION_WAITING;
      should_calibrate_ = true;
    } else {
      calibration_map[GetCalibrationSetupInstruction(component)][component] =
          CalibrationComponentStatus::RMAD_CALIBRATION_SKIP;
    }
  }

  if (!SetCalibrationMap(json_store_, calibration_map)) {
    LOG(ERROR) << "Failed to set the calibration map.";
  }
}

bool ProvisionDeviceStateHandler::CheckSensorStatusIntegrity(
    const std::set<RmadComponent>& replaced_components_need_calibration,
    const std::set<RmadComponent>& probed_components,
    InstructionCalibrationStatusMap* calibration_map) {
  // There are several situations:
  // 1. replaced & probed -> calibrate
  // 2. probed only -> skip
  // 3. replaced only w/ mlb repair-> ignore
  // 4. replaced only w/o mlb repair -> V1: log message, V2: let user check

  // Since if it's a mainboard repair, all components are marked as replaced
  // and all situations are valid (cases 1, 2, and 3). In this case, we don't
  // care about those sensors that were marked as replaced but not probed.
  if (bool mlb_repair;
      json_store_->GetValue(kMlbRepair, &mlb_repair) && mlb_repair) {
    return true;
  }

  bool component_integrity = true;
  // Handle sensors marked as replaced but not probed (case 4).
  for (RmadComponent component : replaced_components_need_calibration) {
    if (probed_components.count(component)) {
      continue;
    }
    // 4. replaced only w/o mlb repair -> V1: log message, V2: let user check
    // TODO(genechang): Set to a missing status for displaying messages in V2
    StoreErrorCode(RmadState::kProvisionDevice, RMAD_ERROR_MISSING_COMPONENT);
    component_integrity = false;
  }

  return component_integrity;
}

void ProvisionDeviceStateHandler::SendStatusSignal() {
  const ProvisionStatus& status = GetProgress();
  daemon_callback_->GetProvisionSignalCallback().Run(status);
  if (status.status() != ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS) {
    StopStatusTimer();
  }
}

void ProvisionDeviceStateHandler::StartStatusTimer() {
  StopStatusTimer();
  status_timer_.Start(FROM_HERE, kReportStatusInterval, this,
                      &ProvisionDeviceStateHandler::SendStatusSignal);
}

void ProvisionDeviceStateHandler::StopStatusTimer() {
  if (status_timer_.IsRunning()) {
    status_timer_.Stop();
  }
}

bool ProvisionDeviceStateHandler::GetSsfcFromCrosConfig(
    std::optional<uint32_t>* ssfc) const {
  if (ssfc_prober_->IsSsfcRequired()) {
    if (uint32_t ssfc_value; ssfc_prober_->ProbeSsfc(&ssfc_value)) {
      *ssfc = std::optional<uint32_t>{ssfc_value};
      return true;
    }
    LOG(ERROR) << "Failed to probe SSFC";
    return false;
  }
  *ssfc = std::nullopt;
  return true;
}

void ProvisionDeviceStateHandler::StartProvision() {
  UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS,
               kProgressInit, ProvisionStatus::RMAD_PROVISION_ERROR_UNKNOWN);

  // This should be run on the main thread.
  std::optional<uint32_t> ssfc;
  if (!GetSsfcFromCrosConfig(&ssfc)) {
    // TODO(chenghan): Add a new error enum for this.
    UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                 kProgressFailedBlocking,
                 ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_READ);
    return;
  }

  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&ProvisionDeviceStateHandler::RunProvision,
                                base::Unretained(this), ssfc));
}

void ProvisionDeviceStateHandler::RunProvision(std::optional<uint32_t> ssfc) {
  // We should do all blocking items first, and then do non-blocking items.
  // In this case, once it fails, we can directly update the status to
  // FAILED_BLOCKING or FAILED_NON_BLOCKING based on the failed item.

  bool same_owner = false;
  if (!json_store_->GetValue(kSameOwner, &same_owner)) {
    LOG(ERROR) << "Failed to get device destination from json store";
    UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                 kProgressFailedBlocking,
                 ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_READ);
    return;
  }
  UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS,
               kProgressGetDestination);

  std::string model_name;
  if (!cros_config_utils_->GetModelName(&model_name)) {
    LOG(ERROR) << "Failed to get model name from cros_config.";
    UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                 kProgressFailedBlocking,
                 ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_READ);
    return;
  }
  UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS,
               kProgressGetModelName);

  if (ssfc.has_value()) {
    if (base::PathExists(working_dir_path_.Append(kTestDirPath))) {
      DLOG(INFO) << "Setting SSFC bypassed in test mode.";
      DLOG(INFO) << "SSFC value: " << ssfc.value();
    } else if (!cbi_utils_->SetSsfc(ssfc.value())) {
      // Failed to set SSFC.
      if (IsHwwpDisabled()) {
        UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                     kProgressFailedBlocking,
                     ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_WRITE);
      } else {
        UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                     kProgressFailedBlocking,
                     ProvisionStatus::RMAD_PROVISION_ERROR_WP_ENABLED);
      }
      return;
    }
  }
  UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS,
               kProgressWriteSsfc);

  if (!same_owner) {
    std::string stable_device_secret;
    if (!GenerateStableDeviceSecret(&stable_device_secret)) {
      UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                   kProgressFailedBlocking,
                   ProvisionStatus::RMAD_PROVISION_ERROR_GENERATE_SECRET);
      return;
    }

    // Writing a string to the vpd cache should always succeed.
    if (!vpd_utils_->SetStableDeviceSecret(stable_device_secret)) {
      UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                   kProgressFailedBlocking,
                   ProvisionStatus::RMAD_PROVISION_ERROR_INTERNAL);
      return;
    }
    UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS,
                 kProgressUpdateStableDeviceSecret);
    // TODO(genechang): Reset fingerprint sensor here."
  }

  // VPD is locked by SWWP only and should not be enabled throughout the RMA.
  if (!vpd_utils_->FlushOutRoVpdCache()) {
    if (IsHwwpDisabled()) {
      UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                   kProgressFailedBlocking,
                   ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_WRITE);
    } else {
      UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                   kProgressFailedBlocking,
                   ProvisionStatus::RMAD_PROVISION_ERROR_WP_ENABLED);
    }
    return;
  }
  UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS,
               kProgressFlushOutVpdCache);

  // Reset GBB flags.
  if (std::string output; !cmd_utils_->GetOutput(kResetGbbFlagsArgv, &output)) {
    LOG(ERROR) << "Failed to reset GBB flags";
    LOG(ERROR) << output;
    UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                 kProgressFailedBlocking,
                 ProvisionStatus::RMAD_PROVISION_ERROR_GBB);
    return;
  }
  UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS,
               kProgressResetGbbFlags);

  // Set cr50 board ID if it is not set yet.
  std::string board_id_type, board_id_flags;
  if (!cr50_utils_->GetBoardIdType(&board_id_type)) {
    UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                 kProgressFailedBlocking,
                 ProvisionStatus::RMAD_PROVISION_ERROR_CR50);
    return;
  }
  if (board_id_type == kEmptyBoardIdType) {
    bool is_custom_label = false;
    if (cr50_utils_->GetBoardIdFlags(&board_id_flags) &&
        board_id_flags == kCustomLabelPvtBoardIdFlags) {
      is_custom_label = true;
      // TODO(chenghan): Custom label board ID flags should not be used on a
      //                 non custom label device, but technically cr50 still
      //                 works. Record a metric for it.
      if (!cros_config_utils_->IsCustomLabel()) {
        LOG(ERROR) << "Cr50 board ID flags for custom label should not be used "
                   << "on a non custom label device";
      }
    } else {
      // TODO(chenghan): This is a security violation. Record a metric for it.
      LOG(ERROR) << "Cr50 board ID type is empty in RMA";
    }
    if (!cr50_utils_->SetBoardId(is_custom_label)) {
      UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                   kProgressFailedBlocking,
                   ProvisionStatus::RMAD_PROVISION_ERROR_CR50);
      return;
    }
  } else if (board_id_type == kTestBoardIdType) {
    // TODO(chenghan): Test board ID is not allowed in RMA. Record a metrics for
    //                 it.
    LOG(ERROR) << "Cr50 board ID type cannot be ZZCR in RMA";
    if (base::PathExists(working_dir_path_.Append(kTestDirPath))) {
      DLOG(INFO) << "Cr50 board ID check bypassed";
    } else {
      UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
                   kProgressFailedBlocking,
                   ProvisionStatus::RMAD_PROVISION_ERROR_CR50);
      return;
    }
  }

  UpdateStatus(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE,
               kProgressSetBoardId);
}

void ProvisionDeviceStateHandler::UpdateStatus(ProvisionStatus::Status status,
                                               double progress,
                                               ProvisionStatus::Error error) {
  base::AutoLock scoped_lock(lock_);
  status_.set_status(status);
  status_.set_progress(progress);
  status_.set_error(error);
}

ProvisionStatus ProvisionDeviceStateHandler::GetProgress() const {
  base::AutoLock scoped_lock(lock_);
  return status_;
}

bool ProvisionDeviceStateHandler::GenerateStableDeviceSecret(
    std::string* stable_device_secret) {
  CHECK(stable_device_secret);
  unsigned char buffer[kStableDeviceSecretSize];
  if (RAND_bytes(buffer, kStableDeviceSecretSize) != 1) {
    LOG(ERROR) << "Failed to get random bytes.";
    return false;
  }

  *stable_device_secret = base::HexEncode(buffer, kStableDeviceSecretSize);
  return true;
}

void ProvisionDeviceStateHandler::Reboot() {
  DLOG(INFO) << "Rebooting after updating configs.";
  if (!power_manager_client_->Restart()) {
    LOG(ERROR) << "Failed to reboot";
  }
}

bool ProvisionDeviceStateHandler::IsHwwpDisabled() const {
  bool hwwp_enabled;
  return (
      write_protect_utils_->GetHardwareWriteProtectionStatus(&hwwp_enabled) &&
      !hwwp_enabled);
}

}  // namespace rmad
