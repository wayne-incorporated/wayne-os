// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/provision_device_state_handler.h"

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/scoped_refptr.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <brillo/file_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/ssfc/mock_ssfc_prober.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/system/mock_power_manager_client.h"
#include "rmad/utils/json_store.h"
#include "rmad/utils/mock_cbi_utils.h"
#include "rmad/utils/mock_cmd_utils.h"
#include "rmad/utils/mock_cr50_utils.h"
#include "rmad/utils/mock_cros_config_utils.h"
#include "rmad/utils/mock_iio_sensor_probe_utils.h"
#include "rmad/utils/mock_vpd_utils.h"
#include "rmad/utils/mock_write_protect_utils.h"

using testing::_;
using testing::Assign;
using testing::DoAll;
using testing::Eq;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;
using testing::WithArg;

namespace {

constexpr char kTestModelName[] = "TestModelName";
constexpr uint32_t kTestSsfc = 0x1234;

constexpr char kEmptyBoardIdType[] = "ffffffff";
constexpr char kValidBoardIdType[] = "12345678";
constexpr char kInvalidBoardIdType[] = "5a5a4352";  // ZZCR.
constexpr char kPvtBoardIdFlags[] = "00007f80";
constexpr char kCustomLabelPvtBoardIdFlags[] = "00003f80";

struct StateHandlerArgs {
  bool get_model_name_success = true;
  bool get_ssfc_success = true;
  bool need_update_ssfc = true;
  bool set_ssfc_success = true;
  bool set_stable_device_secret_success = true;
  bool flush_vpd = true;
  bool hwwp_enabled = false;
  bool reset_gbb_success = true;
  bool read_board_id_success = true;
  std::string board_id_type = kValidBoardIdType;
  std::string board_id_flags = kPvtBoardIdFlags;
  std::set<rmad::RmadComponent> probed_components = {};
};

constexpr rmad::RmadComponent kComponentNeedCalibration =
    rmad::RMAD_COMPONENT_BASE_ACCELEROMETER;
constexpr rmad::RmadComponent kComponentNeedCalibration2 =
    rmad::RMAD_COMPONENT_LID_ACCELEROMETER;
constexpr rmad::RmadComponent kComponentNoNeedCalibration =
    rmad::RMAD_COMPONENT_BATTERY;

}  // namespace

namespace rmad {

class ProvisionDeviceStateHandlerTest : public StateHandlerTest {
 public:
  // Helper class to mock the callback function to send signal.
  class SignalSender {
   public:
    MOCK_METHOD(void,
                SendProvisionProgressSignal,
                (const ProvisionStatus&),
                (const));
  };

  void QueueStatus(const ProvisionStatus& status) {
    status_history_.push_back(status);
  }

  scoped_refptr<ProvisionDeviceStateHandler> CreateInitializedStateHandler(
      const StateHandlerArgs& args = {}) {
    // Expect signal is always sent.
    ON_CALL(signal_sender_, SendProvisionProgressSignal(_))
        .WillByDefault(WithArg<0>(
            Invoke(this, &ProvisionDeviceStateHandlerTest::QueueStatus)));

    // Mock |SsfcProber|.
    auto mock_ssfc_prober = std::make_unique<NiceMock<MockSsfcProber>>();
    ON_CALL(*mock_ssfc_prober, IsSsfcRequired())
        .WillByDefault(Return(args.need_update_ssfc));
    if (args.need_update_ssfc && args.get_ssfc_success) {
      ON_CALL(*mock_ssfc_prober, ProbeSsfc(_))
          .WillByDefault(DoAll(SetArgPointee<0>(kTestSsfc), Return(true)));
    } else {
      ON_CALL(*mock_ssfc_prober, ProbeSsfc(_)).WillByDefault(Return(false));
    }

    // Mock |PowerManagerClient|.
    reboot_called_ = false;
    auto mock_power_manager_client =
        std::make_unique<NiceMock<MockPowerManagerClient>>();
    ON_CALL(*mock_power_manager_client, Restart())
        .WillByDefault(DoAll(Assign(&reboot_called_, true), Return(true)));

    // Mock |CbiUtils|.
    auto mock_cbi_utils = std::make_unique<NiceMock<MockCbiUtils>>();
    ON_CALL(*mock_cbi_utils, SetSsfc(_))
        .WillByDefault(Return(args.set_ssfc_success));

    // Mock |CmdUtils|.
    auto mock_cmd_utils = std::make_unique<NiceMock<MockCmdUtils>>();
    ON_CALL(*mock_cmd_utils, GetOutput(_, _))
        .WillByDefault(Return(args.reset_gbb_success));

    // Mock |Cr50Utils|.
    auto mock_cr50_utils = std::make_unique<NiceMock<MockCr50Utils>>();
    if (args.read_board_id_success) {
      ON_CALL(*mock_cr50_utils, GetBoardIdType(_))
          .WillByDefault(
              DoAll(SetArgPointee<0>(args.board_id_type), Return(true)));
      ON_CALL(*mock_cr50_utils, GetBoardIdFlags(_))
          .WillByDefault(
              DoAll(SetArgPointee<0>(args.board_id_flags), Return(true)));
    } else {
      ON_CALL(*mock_cr50_utils, GetBoardIdType(_)).WillByDefault(Return(false));
      ON_CALL(*mock_cr50_utils, GetBoardIdFlags(_))
          .WillByDefault(Return(false));
    }
    ON_CALL(*mock_cr50_utils, SetBoardId(_))
        .WillByDefault(Invoke([args](bool is_custom_label) {
          if (args.board_id_type != kEmptyBoardIdType) {
            return false;
          }
          if (is_custom_label) {
            return (args.board_id_flags == kCustomLabelPvtBoardIdFlags);
          }
          return (args.board_id_flags == kPvtBoardIdFlags);
        }));

    // Mock |CrosConfigUtils|.
    auto mock_cros_config_utils =
        std::make_unique<NiceMock<MockCrosConfigUtils>>();
    if (args.get_model_name_success) {
      ON_CALL(*mock_cros_config_utils, GetModelName(_))
          .WillByDefault(DoAll(SetArgPointee<0>(std::string(kTestModelName)),
                               Return(true)));
    } else {
      ON_CALL(*mock_cros_config_utils, GetModelName(_))
          .WillByDefault(Return(false));
    }

    // Mock |WriteProtectUtils|.
    auto mock_write_protect_utils =
        std::make_unique<NiceMock<MockWriteProtectUtils>>();
    ON_CALL(*mock_write_protect_utils, GetHardwareWriteProtectionStatus(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(args.hwwp_enabled), Return(true)));

    // Mock |IioSensorProbeUtils|.
    auto mock_iio_sensor_probe_utils =
        std::make_unique<NiceMock<MockIioSensorProbeUtils>>();
    ON_CALL(*mock_iio_sensor_probe_utils, Probe())
        .WillByDefault(Return(args.probed_components));

    // Mock |VpdUtils|.
    auto mock_vpd_utils = std::make_unique<NiceMock<MockVpdUtils>>();
    ON_CALL(*mock_vpd_utils, SetStableDeviceSecret(_))
        .WillByDefault(Return(args.set_stable_device_secret_success));
    ON_CALL(*mock_vpd_utils, FlushOutRoVpdCache())
        .WillByDefault(Return(args.flush_vpd));

    // Register signal callback.
    daemon_callback_->SetProvisionSignalCallback(
        base::BindRepeating(&SignalSender::SendProvisionProgressSignal,
                            base::Unretained(&signal_sender_)));

    auto handler = base::MakeRefCounted<ProvisionDeviceStateHandler>(
        json_store_, daemon_callback_, GetTempDirPath(),
        std::move(mock_ssfc_prober), std::move(mock_power_manager_client),
        std::move(mock_cbi_utils), std::move(mock_cmd_utils),
        std::move(mock_cr50_utils), std::move(mock_cros_config_utils),
        std::move(mock_write_protect_utils),
        std::move(mock_iio_sensor_probe_utils), std::move(mock_vpd_utils));
    EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
    return handler;
  }

  RmadState CreateProvisionRequest(
      ProvisionDeviceState_ProvisionChoice choice) const {
    RmadState state;
    state.mutable_provision_device()->set_choice(choice);
    return state;
  }

  void ExpectTransitionReboot(
      scoped_refptr<ProvisionDeviceStateHandler> handler) {
    auto [error, state_case] = handler->GetNextStateCase(CreateProvisionRequest(
        ProvisionDeviceState::RMAD_PROVISION_CHOICE_CONTINUE));
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kProvisionDevice);
    EXPECT_FALSE(reboot_called_);
    task_environment_.FastForwardBy(ProvisionDeviceStateHandler::kRebootDelay);
    EXPECT_TRUE(reboot_called_);
  }

  void ExpectTransitionFailedWithError(
      scoped_refptr<ProvisionDeviceStateHandler> handler,
      RmadErrorCode expected_error) {
    auto [error, state_case] = handler->GetNextStateCase(CreateProvisionRequest(
        ProvisionDeviceState::RMAD_PROVISION_CHOICE_CONTINUE));
    EXPECT_EQ(error, expected_error);
    EXPECT_EQ(state_case, RmadState::StateCase::kProvisionDevice);
  }

  void ExpectTransitionSucceededAtBoot(RmadState::StateCase expected_state_case,
                                       const StateHandlerArgs& args = {}) {
    auto handler = CreateInitializedStateHandler(args);
    auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
    EXPECT_EQ(error, RMAD_ERROR_OK);
    EXPECT_EQ(state_case, expected_state_case);
  }

  void ExpectSignal(ProvisionStatus_Status expected_status,
                    ProvisionStatus_Error expected_error =
                        ProvisionStatus::RMAD_PROVISION_ERROR_UNKNOWN) {
    task_environment_.FastForwardBy(
        ProvisionDeviceStateHandler::kReportStatusInterval);
    EXPECT_GE(status_history_.size(), 1);
    EXPECT_EQ(status_history_.back().status(), expected_status);
    EXPECT_EQ(status_history_.back().error(), expected_error);
  }

  void RunHandlerTaskRunner(
      scoped_refptr<ProvisionDeviceStateHandler> handler) {
    handler->GetTaskRunner()->PostTask(FROM_HERE, run_loop_.QuitClosure());
    run_loop_.Run();
  }

 protected:
  NiceMock<SignalSender> signal_sender_;
  std::vector<ProvisionStatus> status_history_;
  bool reboot_called_;

  // Variables for TaskRunner.
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadPoolExecutionMode::ASYNC,
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  base::RunLoop run_loop_;
};

TEST_F(ProvisionDeviceStateHandlerTest, VerifyTestConstant) {
  // Make sure the constants are correct.
  EXPECT_TRUE(
      kComponentsNeedManualCalibration.contains(kComponentNeedCalibration));
  EXPECT_TRUE(
      kComponentsNeedManualCalibration.contains(kComponentNeedCalibration2));
  EXPECT_FALSE(
      kComponentsNeedManualCalibration.contains(kComponentNoNeedCalibration));
}

TEST_F(ProvisionDeviceStateHandlerTest, InitializeState_Succeeded) {
  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  RunHandlerTaskRunner(handler);
}

TEST_F(ProvisionDeviceStateHandlerTest, Clenaup_Succeeded) {
  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  handler->CleanUpState();
  RunHandlerTaskRunner(handler);
}

TEST_F(ProvisionDeviceStateHandlerTest, GetNextStateCase_Succeeded) {
  // Set up environment for different owner.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);

  // Run the state handler.
  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);
}

TEST_F(ProvisionDeviceStateHandlerTest, TryGetNextStateCaseAtBoot_Failed) {
  // Set up environment for different owner.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);

  // TryGetNextStateCaseAtBoot() is called before RunState(), so we don't call
  // RunState() here.
  auto handler = CreateInitializedStateHandler();

  // We should not transition to the next state until provisioning is completed.
  auto [error, state] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_TRANSITION_FAILED);
  EXPECT_EQ(state, RmadState::StateCase::kProvisionDevice);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       TryGetNextStateCaseAtBoot_NeedCalibrationSucceeded_MlbRepair) {
  // Set up environment for MLB repair, which also implies different owner.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  json_store_->SetValue(kMlbRepair, true);
  StateHandlerArgs args = {.probed_components = {kComponentNeedCalibration,
                                                 kComponentNeedCalibration2}};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to SetupCalibration state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kSetupCalibration,
                                  args);

  // Check calibration map. |kComponentNeedCalibration| and
  // |kComponentNeedCalibration2| are scheduled to be calibrated.
  InstructionCalibrationStatusMap calibration_map;
  EXPECT_TRUE(GetCalibrationMap(json_store_, &calibration_map));
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                kComponentNeedCalibration)][kComponentNeedCalibration],
            CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                kComponentNeedCalibration2)][kComponentNeedCalibration2],
            CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       TryGetNextStateCaseAtBoot_NeedCalibrationSucceeded_NonMlbRepair) {
  // Set up environment for different owner and all replaced components need
  // calibration.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  json_store_->SetValue(
      kReplacedComponentNames,
      std::vector<std::string>{RmadComponent_Name(kComponentNeedCalibration),
                               RmadComponent_Name(kComponentNeedCalibration2)});
  StateHandlerArgs args = {.probed_components = {kComponentNeedCalibration,
                                                 kComponentNeedCalibration2}};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to SetupCalibration state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kSetupCalibration,
                                  args);

  // Check calibration map. |kComponentNeedCalibration| and
  // |kComponentNeedCalibration2| are scheduled to be calibrated.
  InstructionCalibrationStatusMap calibration_map;
  EXPECT_TRUE(GetCalibrationMap(json_store_, &calibration_map));
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                kComponentNeedCalibration)][kComponentNeedCalibration],
            CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                kComponentNeedCalibration2)][kComponentNeedCalibration2],
            CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       TryGetNextStateCaseAtBoot_SkipCalibrationSucceeded) {
  // Set up environment for different owner and all replaced components need
  // calibration.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  json_store_->SetValue(
      kReplacedComponentNames,
      std::vector<std::string>{RmadComponent_Name(kComponentNeedCalibration),
                               RmadComponent_Name(kComponentNeedCalibration2)});
  // Bypass calibration.
  EXPECT_TRUE(
      brillo::TouchFile(GetTempDirPath().Append(kDisableCalibrationFilePath)));

  StateHandlerArgs args = {.probed_components = {kComponentNeedCalibration,
                                                 kComponentNeedCalibration2}};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to Finalize state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kFinalize, args);

  // Check calibration map. |kComponentNeedCalibration| and
  // |kComponentNeedCalibration2| are skipped.
  InstructionCalibrationStatusMap calibration_map;
  EXPECT_TRUE(GetCalibrationMap(json_store_, &calibration_map));
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                kComponentNeedCalibration)][kComponentNeedCalibration],
            CalibrationComponentStatus::RMAD_CALIBRATION_SKIP);
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                kComponentNeedCalibration2)][kComponentNeedCalibration2],
            CalibrationComponentStatus::RMAD_CALIBRATION_SKIP);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       TryGetNextStateCaseAtBoot_NoNeedCalibrationSucceeded) {
  // Set up environment for different owner and no replaced components need
  // calibration.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  json_store_->SetValue(kReplacedComponentNames,
                        std::vector<std::string>{
                            RmadComponent_Name(kComponentNoNeedCalibration)});
  StateHandlerArgs args = {.probed_components = {kComponentNoNeedCalibration}};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to Finalize state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kFinalize, args);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       TryGetNextStateCaseAtBoot_ReplacedComponentNotProbedComplete) {
  // Set up environment for different owner and there are replaced components
  // that need calibration, but the component is not probed and it's not an
  // MLB replacement case.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  json_store_->SetValue(kMlbRepair, false);
  json_store_->SetValue(
      kReplacedComponentNames,
      std::vector<std::string>{RmadComponent_Name(kComponentNeedCalibration),
                               RmadComponent_Name(kComponentNeedCalibration2)});
  // Only |kComponentNeedCalibration| is probed.
  StateHandlerArgs args = {.probed_components = {kComponentNeedCalibration}};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to SetupCalibration state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kSetupCalibration,
                                  args);

  // Check calibration map. |kComponentNeedCalibration| is scheduled to be
  // calibrated, while |kComponentNeedCalibration2| is not.
  InstructionCalibrationStatusMap calibration_map;
  EXPECT_TRUE(GetCalibrationMap(json_store_, &calibration_map));
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                kComponentNeedCalibration)][kComponentNeedCalibration],
            CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                                kComponentNeedCalibration2)]
                .count(kComponentNeedCalibration2),
            0);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       TryGetNextStateCaseAtBoot_PartialNeedCalibrationSucceeded) {
  // Set up environment for different owner and there are some replaced
  // components that need calibration.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  json_store_->SetValue(kMlbRepair, false);
  json_store_->SetValue(kReplacedComponentNames,
                        std::vector<std::string>{
                            RmadComponent_Name(kComponentNeedCalibration),
                            RmadComponent_Name(kComponentNoNeedCalibration)});
  StateHandlerArgs args = {.probed_components = {kComponentNeedCalibration,
                                                 kComponentNoNeedCalibration}};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to SetupCalibration state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kSetupCalibration,
                                  args);

  // Check calibration map. |kComponentNeedCalibration| is scheduled to be
  // calibrated, while |kComponentNeedCalibration2| is not.
  InstructionCalibrationStatusMap calibration_map;
  EXPECT_TRUE(GetCalibrationMap(json_store_, &calibration_map));
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                kComponentNeedCalibration)][kComponentNeedCalibration],
            CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
  EXPECT_EQ(calibration_map[GetCalibrationSetupInstruction(
                                kComponentNeedCalibration2)]
                .count(kComponentNeedCalibration2),
            0);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       TryGetNextStateCaseAtBoot_KeepDeviveOpenSucceeded) {
  // Set up environment for same owner and keep user data path.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWipeDevice, false);

  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to WpEnablePhysical state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kWpEnablePhysical);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_UnknownDestinationFailedBlocking) {
  // Set up environment without destination (internal error).
  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_READ);

  // Failed to transition to the next state.
  ExpectTransitionFailedWithError(handler, RMAD_ERROR_PROVISIONING_FAILED);
}

TEST_F(ProvisionDeviceStateHandlerTest, GetNextStateCase_Retry) {
  // Set up environment without destination (internal error).
  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_READ);

  // Failed to transition to the next state.
  ExpectTransitionFailedWithError(handler, RMAD_ERROR_PROVISIONING_FAILED);

  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);

  // Retry.
  auto [error, state_case] = handler->GetNextStateCase(CreateProvisionRequest(
      ProvisionDeviceState::RMAD_PROVISION_CHOICE_RETRY));
  EXPECT_EQ(error, RMAD_ERROR_WAIT);
  EXPECT_EQ(state_case, RmadState::StateCase::kProvisionDevice);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to Finalize state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kFinalize);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_SetStableDeviceSecretFailedBlocking) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Failed to set stable device secret.
  StateHandlerArgs args = {.set_stable_device_secret_success = false};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_INTERNAL);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_GetModelNameFailedBlocking) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Failed to get model name.
  StateHandlerArgs args = {.get_model_name_success = false};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_READ);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_SsfcNotRequiredSucceeded) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // SSFC doesn't need to be updated.
  StateHandlerArgs args = {.need_update_ssfc = false};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to Finalize state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kFinalize, args);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_GetSsfcFailedBlocking) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Failed to get SSFC.
  StateHandlerArgs args = {.get_ssfc_success = false};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_READ);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_SetSsfcFailedBlockingCannotWrite) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateInitializedStateHandler({.set_ssfc_success = false});
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_WRITE);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_SetSsfcFailedBlockingWpEnabled) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateInitializedStateHandler(
      {.set_ssfc_success = false, .hwwp_enabled = true});
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_WP_ENABLED);
}

TEST_F(ProvisionDeviceStateHandlerTest, GetNextStateCase_SetSsfcBypassed) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Bypass setting SSFC.
  EXPECT_TRUE(brillo::TouchFile(GetTempDirPath().Append(kTestDirPath)));

  auto handler = CreateInitializedStateHandler({.set_ssfc_success = false});
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_VpdFlushFailedBlocking) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Failed to flush VPD.
  StateHandlerArgs args = {.flush_vpd = false};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_CANNOT_WRITE);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_ResetGbbFlagsFailedBlocking) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Failed to reset GBB.
  StateHandlerArgs args = {.reset_gbb_success = false};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_GBB);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_CannotReadBoardIdBlocking) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Failed to read board ID.
  StateHandlerArgs args = {.read_board_id_success = false};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_CR50);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_InvalidBoardIdTypeBlocking) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Invalid board ID.
  StateHandlerArgs args = {.board_id_type = kInvalidBoardIdType};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision failed signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_FAILED_BLOCKING,
               ProvisionStatus::RMAD_PROVISION_ERROR_CR50);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_InvalidBoardIdTypeBlocking_Bypass) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Invalid board ID.
  StateHandlerArgs args = {.board_id_type = kInvalidBoardIdType};
  // Bypass board ID check.
  EXPECT_TRUE(brillo::TouchFile(GetTempDirPath().Append(kTestDirPath)));

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to Finalize state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kFinalize, args);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_EmptyBoardIdType_NotCustomLabel_Succeeded) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Empty board ID.
  StateHandlerArgs args = {.board_id_type = kEmptyBoardIdType};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to Finalize state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kFinalize, args);
}

TEST_F(ProvisionDeviceStateHandlerTest,
       GetNextStateCase_EmptyBoardIdType_CustomLabel_Succeeded) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);
  // Empty board ID with custom label flags.
  StateHandlerArgs args = {.board_id_type = kEmptyBoardIdType,
                           .board_id_flags = kCustomLabelPvtBoardIdFlags};

  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // Provision complete signal is sent.
  ExpectSignal(ProvisionStatus::RMAD_PROVISION_STATUS_COMPLETE);

  // A reboot is expected after provisioning succeeds.
  ExpectTransitionReboot(handler);

  // Successfully transition to Finalize state.
  ExpectTransitionSucceededAtBoot(RmadState::StateCase::kFinalize, args);
}

TEST_F(ProvisionDeviceStateHandlerTest, GetNextStateCase_MissingState) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  RunHandlerTaskRunner(handler);

  // No WelcomeScreenState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kProvisionDevice);
}

TEST_F(ProvisionDeviceStateHandlerTest, GetNextStateCase_MissingArgs) {
  // Set up normal environment.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  RunHandlerTaskRunner(handler);

  auto [error, state_case] = handler->GetNextStateCase(CreateProvisionRequest(
      ProvisionDeviceState::RMAD_PROVISION_CHOICE_UNKNOWN));
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_ARGS_MISSING);
  EXPECT_EQ(state_case, RmadState::StateCase::kProvisionDevice);
}

}  // namespace rmad
