// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_PROVISION_DEVICE_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_PROVISION_DEVICE_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <set>

#include <base/files/file_path.h>
#include <base/memory/scoped_refptr.h>
#include <base/synchronization/lock.h>
#include <base/timer/timer.h>

#include "rmad/ssfc/ssfc_prober.h"
#include "rmad/system/power_manager_client.h"
#include "rmad/utils/calibration_utils.h"
#include "rmad/utils/cbi_utils.h"
#include "rmad/utils/cmd_utils.h"
#include "rmad/utils/cr50_utils.h"
#include "rmad/utils/cros_config_utils.h"
#include "rmad/utils/iio_sensor_probe_utils.h"
#include "rmad/utils/json_store.h"
#include "rmad/utils/vpd_utils.h"
#include "rmad/utils/write_protect_utils.h"

namespace rmad {

class ProvisionDeviceStateHandler : public BaseStateHandler {
 public:
  // Report status every second.
  static constexpr base::TimeDelta kReportStatusInterval = base::Seconds(1);

  // Wait for 3 seconds before rebooting.
  static constexpr base::TimeDelta kRebootDelay = base::Seconds(3);

  explicit ProvisionDeviceStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject |working_dir_path_|, mock |ssfc_prober_|,
  // |power_manager_client_|, |cbi_utils_|, |cmd_utils_|, |cr50_utils_|,
  // |cros_config_utils_|, |write_protect_utils_|, |iio_sensor_probe_utils_|,
  // and |vpd_utils_| for testing.
  explicit ProvisionDeviceStateHandler(
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
      std::unique_ptr<VpdUtils> vpd_utils);

  ASSIGN_STATE(RmadState::StateCase::kProvisionDevice);
  SET_REPEATABLE;

  RmadErrorCode InitializeState() override;
  void RunState() override;
  void CleanUpState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;
  GetNextStateCaseReply TryGetNextStateCaseAtBoot() override;

  scoped_refptr<base::SequencedTaskRunner> GetTaskRunner() {
    return task_runner_;
  }

 protected:
  ~ProvisionDeviceStateHandler() override = default;

 private:
  void InitializeCalibrationTask();
  bool CheckSensorStatusIntegrity(
      const std::set<RmadComponent>& replaced_components_need_calibration,
      const std::set<RmadComponent>& probed_components,
      InstructionCalibrationStatusMap* calibration_map);

  void SendStatusSignal();
  void StartStatusTimer();
  void StopStatusTimer();

  bool GetSsfcFromCrosConfig(std::optional<uint32_t>* ssfc) const;
  void StartProvision();
  void RunProvision(std::optional<uint32_t> ssfc);
  void UpdateStatus(ProvisionStatus::Status status,
                    double progress,
                    ProvisionStatus::Error error =
                        ProvisionStatus::RMAD_PROVISION_ERROR_UNKNOWN);
  ProvisionStatus GetProgress() const;

  bool GenerateStableDeviceSecret(std::string* stable_device_secret);
  void Reboot();
  bool IsHwwpDisabled() const;

  base::FilePath working_dir_path_;
  ProvisionStatus status_;

  std::unique_ptr<SsfcProber> ssfc_prober_;
  std::unique_ptr<PowerManagerClient> power_manager_client_;
  std::unique_ptr<CbiUtils> cbi_utils_;
  std::unique_ptr<CmdUtils> cmd_utils_;
  std::unique_ptr<Cr50Utils> cr50_utils_;
  std::unique_ptr<CrosConfigUtils> cros_config_utils_;
  std::unique_ptr<WriteProtectUtils> write_protect_utils_;
  std::unique_ptr<IioSensorProbeUtils> iio_sensor_probe_utils_;
  std::unique_ptr<VpdUtils> vpd_utils_;

  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  base::RepeatingTimer status_timer_;
  base::OneShotTimer reboot_timer_;
  mutable base::Lock lock_;
  bool should_calibrate_;
  bool sensor_integrity_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_PROVISION_DEVICE_STATE_HANDLER_H_
