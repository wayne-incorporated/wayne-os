// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/memory/scoped_refptr.h>
#include <base/test/task_environment.h>
#include <brillo/file_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/metrics/mock_metrics_utils.h"
#include "rmad/state_handler/repair_complete_state_handler.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/system/mock_power_manager_client.h"
#include "rmad/udev/mock_udev_utils.h"
#include "rmad/udev/udev_device.h"
#include "rmad/utils/mock_crossystem_utils.h"
#include "rmad/utils/mock_sys_utils.h"

using testing::_;
using testing::Assign;
using testing::DoAll;
using testing::Eq;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace {

constexpr char kPowerwashCountFilePath[] = "powerwash_count";

}  // namespace

namespace rmad {

class RepairCompleteStateHandlerTest : public StateHandlerTest {
 public:
  // Helper class to mock the callback function to send signal.
  class SignalSender {
   public:
    MOCK_METHOD(void, SendPowerCableSignal, (bool), (const));
  };

  scoped_refptr<RepairCompleteStateHandler> CreateStateHandler(
      bool* powerwash_requested = nullptr,
      bool* cutoff_requested = nullptr,
      bool* reboot_called = nullptr,
      bool* shutdown_called = nullptr,
      bool* metrics_called = nullptr,
      bool is_cros_debug = true,
      bool record_metrics_success = true,
      bool state_metrics_recorded = true) {
    // Mock |PowerManagerClient|.
    auto mock_power_manager_client =
        std::make_unique<NiceMock<MockPowerManagerClient>>();
    if (reboot_called) {
      ON_CALL(*mock_power_manager_client, Restart())
          .WillByDefault(DoAll(Assign(reboot_called, true), Return(true)));
    } else {
      ON_CALL(*mock_power_manager_client, Restart())
          .WillByDefault(Return(true));
    }
    if (shutdown_called) {
      ON_CALL(*mock_power_manager_client, Shutdown())
          .WillByDefault(DoAll(Assign(shutdown_called, true), Return(true)));
    } else {
      ON_CALL(*mock_power_manager_client, Shutdown())
          .WillByDefault(Return(true));
    }

    // Mock |UdevUtils|.
    auto mock_udev_utils = std::make_unique<NiceMock<MockUdevUtils>>();
    ON_CALL(*mock_udev_utils, EnumerateBlockDevices())
        .WillByDefault(Invoke(
            []() { return std::vector<std::unique_ptr<UdevDevice>>(); }));

    // Mock |CrosSystemUtils|.
    auto mock_crossystem_utils =
        std::make_unique<NiceMock<MockCrosSystemUtils>>();
    ON_CALL(*mock_crossystem_utils,
            GetInt(Eq(CrosSystemUtils::kCrosDebugProperty), _))
        .WillByDefault(
            DoAll(SetArgPointee<1>(is_cros_debug ? 1 : 0), Return(true)));

    // Mock |SysUtils|.
    auto mock_sys_utils = std::make_unique<NiceMock<MockSysUtils>>();
    ON_CALL(*mock_sys_utils, IsPowerSourcePresent())
        .WillByDefault(Return(true));

    // Mock |MetricsUtils|.
    auto mock_metrics_utils = std::make_unique<NiceMock<MockMetricsUtils>>();
    ON_CALL(*mock_metrics_utils, RecordAll(_))
        .WillByDefault(DoAll(Assign(metrics_called, true),
                             Return(record_metrics_success)));

    if (state_metrics_recorded) {
      EXPECT_TRUE(MetricsUtils::UpdateStateMetricsOnStateTransition(
          json_store_, RmadState::STATE_NOT_SET, RmadState::kRepairComplete,
          base::Time::Now().ToDoubleT()));
    }

    // Register signal callback.
    ON_CALL(signal_sender_, SendPowerCableSignal(_)).WillByDefault(Return());
    daemon_callback_->SetPowerCableSignalCallback(
        base::BindRepeating(&SignalSender::SendPowerCableSignal,
                            base::Unretained(&signal_sender_)));

    // Register request powerwash callback.
    daemon_callback_->SetExecuteRequestRmaPowerwashCallback(base::BindRepeating(
        &RepairCompleteStateHandlerTest::RequestRmaPowerwash,
        base::Unretained(this), powerwash_requested));

    // Register request battery cutoff callback.
    daemon_callback_->SetExecuteRequestBatteryCutoffCallback(
        base::BindRepeating(
            &RepairCompleteStateHandlerTest::RequestBatteryCutoff,
            base::Unretained(this), cutoff_requested));

    return base::MakeRefCounted<RepairCompleteStateHandler>(
        json_store_, daemon_callback_, GetTempDirPath(), GetTempDirPath(),
        std::move(mock_power_manager_client), std::move(mock_udev_utils),
        std::move(mock_crossystem_utils), std::move(mock_sys_utils),
        std::move(mock_metrics_utils));
  }

  base::FilePath GetPowerwashCountFilePath() const {
    return GetTempDirPath().AppendASCII(kPowerwashCountFilePath);
  }

  base::FilePath GetDisablePowerwashFilePath() const {
    return GetTempDirPath().AppendASCII(kDisablePowerwashFilePath);
  }

  base::FilePath GetTestDirPath() const {
    return GetTempDirPath().AppendASCII(kTestDirPath);
  }

  void RequestRmaPowerwash(bool* powerwash_requested,
                           base::OnceCallback<void(bool)> callback) {
    if (powerwash_requested) {
      *powerwash_requested = true;
    }
    std::move(callback).Run(true);
  }

  void RequestBatteryCutoff(bool* cutoff_requested,
                            base::OnceCallback<void(bool)> callback) {
    if (cutoff_requested) {
      *cutoff_requested = true;
    }
    std::move(callback).Run(true);
  }

 protected:
  NiceMock<SignalSender> signal_sender_;

  // Variables for TaskRunner.
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(RepairCompleteStateHandlerTest,
       InitializeState_PowerwashRequired_Success) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  EXPECT_TRUE(handler->GetState().repair_complete().powerwash_required());

  int powerwash_count;
  EXPECT_TRUE(json_store_->GetValue(kPowerwashCount, &powerwash_count));
  EXPECT_EQ(powerwash_count, 1);

  handler->RunState();

  // Override signal sender mock.
  EXPECT_CALL(signal_sender_, SendPowerCableSignal(_))
      .WillOnce([](bool is_connected) { EXPECT_TRUE(is_connected); });
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kSignalInterval);

  // Should not send signal after cleanup.
  handler->CleanUpState();
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kSignalInterval);
}

TEST_F(RepairCompleteStateHandlerTest,
       InitializeState_PowerwashNotRequired_NoPowerwashCountFile) {
  // powerwash_count not set.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  EXPECT_FALSE(handler->GetState().repair_complete().powerwash_required());

  int powerwash_count;
  EXPECT_TRUE(json_store_->GetValue(kPowerwashCount, &powerwash_count));
  EXPECT_EQ(powerwash_count, 0);
}

TEST_F(RepairCompleteStateHandlerTest, InitializeState_Fail) {
  // |kWipeDevice| not set.
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(RepairCompleteStateHandlerTest, TryGetNextStateCase_NoUserInput) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
}

TEST_F(RepairCompleteStateHandlerTest,
       GetNextStateCase_PowerwashRequired_Cutoff) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");

  {
    bool powerwash_requested = false, reboot_called = false;
    auto handler =
        CreateStateHandler(&powerwash_requested, nullptr, &reboot_called);
    EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

    handler->RunState();

    RmadState state;
    state.mutable_repair_complete()->set_shutdown(
        RepairCompleteState::RMAD_REPAIR_COMPLETE_BATTERY_CUTOFF);
    state.mutable_repair_complete()->set_powerwash_required(true);

    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_TRUE(powerwash_requested);
    EXPECT_FALSE(reboot_called);

    // Reboot is called after a delay.
    task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
    EXPECT_TRUE(reboot_called);
  }

  // Powerwash is done.
  base::WriteFile(GetPowerwashCountFilePath(), "2\n");

  {
    bool powerwash_requested = false, cutoff_requested = false,
         reboot_called = false, shutdown_called = false, metrics_called = false;
    auto handler =
        CreateStateHandler(&powerwash_requested, &cutoff_requested,
                           &reboot_called, &shutdown_called, &metrics_called);
    EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

    // Check that the state file exists now.
    EXPECT_TRUE(base::PathExists(GetStateFilePath()));

    auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_SHUTDOWN);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
    EXPECT_FALSE(base::PathExists(GetStateFilePath()));

    // Reboot and cutoff are called after a delay.
    task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
    EXPECT_TRUE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(cutoff_requested);
  }
}

TEST_F(RepairCompleteStateHandlerTest,
       GetNextStateCase_PowerwashNotRequired_Reboot) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  bool powerwash_requested = false, cutoff_requested = false,
       reboot_called = false, shutdown_called = false, metrics_called = false;
  auto handler =
      CreateStateHandler(&powerwash_requested, &cutoff_requested,
                         &reboot_called, &shutdown_called, &metrics_called);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  handler->RunState();

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_REBOOT);
  state.mutable_repair_complete()->set_powerwash_required(false);

  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
    EXPECT_FALSE(base::PathExists(GetStateFilePath()));
  }

  // A second call to |GetNextStateCase| before rebooting is fine.
  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
    EXPECT_FALSE(base::PathExists(GetStateFilePath()));
  }

  // Reboot is called after a delay.
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
  EXPECT_TRUE(reboot_called);
  EXPECT_TRUE(metrics_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_FALSE(cutoff_requested);
}

TEST_F(RepairCompleteStateHandlerTest,
       GetNextStateCase_PowerwashNotRequired_Shutdown) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  bool powerwash_requested = false, cutoff_requested = false,
       reboot_called = false, shutdown_called = false, metrics_called = false;
  auto handler =
      CreateStateHandler(&powerwash_requested, &cutoff_requested,
                         &reboot_called, &shutdown_called, &metrics_called);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  handler->RunState();

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_SHUTDOWN);
  state.mutable_repair_complete()->set_powerwash_required(false);

  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_SHUTDOWN);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
    EXPECT_FALSE(base::PathExists(GetStateFilePath()));
  }

  // A second call to |GetNextStateCase| before shutting down is fine.
  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_SHUTDOWN);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
    EXPECT_FALSE(base::PathExists(GetStateFilePath()));
  }

  // Shutdown is called after a delay.
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
  EXPECT_FALSE(reboot_called);
  EXPECT_TRUE(shutdown_called);
  EXPECT_FALSE(cutoff_requested);
}

TEST_F(RepairCompleteStateHandlerTest,
       GetNextStateCase_PowerwashNotRequired_Cutoff) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  bool powerwash_requested = false, cutoff_requested = false,
       reboot_called = false, shutdown_called = false, metrics_called = false;
  auto handler =
      CreateStateHandler(&powerwash_requested, &cutoff_requested,
                         &reboot_called, &shutdown_called, &metrics_called);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  handler->RunState();

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_BATTERY_CUTOFF);
  state.mutable_repair_complete()->set_powerwash_required(false);

  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_SHUTDOWN);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
    EXPECT_FALSE(base::PathExists(GetStateFilePath()));
  }

  // A second call to |GetNextStateCase| before rebooting is fine.
  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_SHUTDOWN);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
    EXPECT_FALSE(base::PathExists(GetStateFilePath()));
  }

  // Reboot and cutoff are called after a delay.
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
  EXPECT_TRUE(reboot_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_TRUE(cutoff_requested);
}

TEST_F(RepairCompleteStateHandlerTest,
       GetNextStateCase_SkipPowerwash_PowerwashDisabledManually) {
  // Powerwash is not done yet, but disabled manually.
  brillo::TouchFile(GetDisablePowerwashFilePath());

  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  bool powerwash_requested = false, cutoff_requested = false,
       reboot_called = false, shutdown_called = false, metrics_called = false;
  auto handler =
      CreateStateHandler(&powerwash_requested, &cutoff_requested,
                         &reboot_called, &shutdown_called, &metrics_called);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  handler->RunState();

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_REBOOT);
  state.mutable_repair_complete()->set_powerwash_required(false);

  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
    EXPECT_FALSE(base::PathExists(GetStateFilePath()));
  }

  // A second call to |GetNextStateCase| before rebooting is fine.
  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
    EXPECT_FALSE(base::PathExists(GetStateFilePath()));
  }

  // Reboot is called after a delay.
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
  EXPECT_TRUE(reboot_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_FALSE(cutoff_requested);
}

TEST_F(RepairCompleteStateHandlerTest,
       GetNextStateCase_SkipPowerwash_PowerwashDisabledInTestMode) {
  // Powerwash is not done yet, but disabled in test mode.
  brillo::TouchFile(GetTestDirPath());

  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  bool powerwash_requested = false, cutoff_requested = false,
       reboot_called = false, shutdown_called = false, metrics_called = false;
  auto handler =
      CreateStateHandler(&powerwash_requested, &cutoff_requested,
                         &reboot_called, &shutdown_called, &metrics_called);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  handler->RunState();

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_REBOOT);
  state.mutable_repair_complete()->set_powerwash_required(false);

  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
  }

  // A second call to |GetNextStateCase| before rebooting is fine.
  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_called);
    EXPECT_FALSE(shutdown_called);
    EXPECT_TRUE(metrics_called);
    EXPECT_FALSE(cutoff_requested);
  }

  // Check that the state file is cleared.
  EXPECT_FALSE(base::PathExists(GetStateFilePath()));

  // Reboot is called after a delay.
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
  EXPECT_TRUE(reboot_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_FALSE(cutoff_requested);
}

TEST_F(RepairCompleteStateHandlerTest,
       GetNextStateCase_PowerwashDisabledManually_NonDebugBuild) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  bool powerwash_requested = false, reboot_called = false;
  auto handler = CreateStateHandler(&powerwash_requested, nullptr,
                                    &reboot_called, nullptr, nullptr, false);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Powerwash is not done yet, but disabled manually.
  // This is ignored in a non-debug build, so we still do a powerwash.
  brillo::TouchFile(GetDisablePowerwashFilePath());

  handler->RunState();

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_BATTERY_CUTOFF);
  state.mutable_repair_complete()->set_powerwash_required(true);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
  EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
  EXPECT_TRUE(powerwash_requested);
  EXPECT_FALSE(reboot_called);

  // Reboot is called after a delay.
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
  EXPECT_TRUE(reboot_called);
}

TEST_F(RepairCompleteStateHandlerTest, GetNextStateCase_MissingState) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // No RepairCompleteState.
  RmadState state;

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);

  // Check that the state file still exists.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));
}

TEST_F(RepairCompleteStateHandlerTest, GetNextStateCase_MissingArgs) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_UNKNOWN);
  state.mutable_repair_complete()->set_powerwash_required(true);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_ARGS_MISSING);
  EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);

  // Check that the state file still exists.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));
}

TEST_F(RepairCompleteStateHandlerTest, GetNextStateCase_ArgsViolation) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_REBOOT);
  state.mutable_repair_complete()->set_powerwash_required(false);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_ARGS_VIOLATION);
  EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);

  // Check that the state file still exists.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));
}

TEST_F(RepairCompleteStateHandlerTest,
       GetNextStateCase_StateMetricsNotRecorded) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  bool powerwash_requested = false, cutoff_requested = false,
       reboot_called = false, shutdown_called = false, metrics_called = false;
  auto handler = CreateStateHandler(&powerwash_requested, &cutoff_requested,
                                    &reboot_called, &shutdown_called,
                                    &metrics_called, true, true, false);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  handler->RunState();

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_BATTERY_CUTOFF);

  auto [error, state_case] = handler->GetNextStateCase(state);
  // Structured metrics recording is expected to fail as current library does
  // not support recording locally without user consent. We shouldn't let it
  // block the flow until the library actually supports it.
  EXPECT_EQ(error, RMAD_ERROR_EXPECT_SHUTDOWN);
  EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_FALSE(metrics_called);
  EXPECT_FALSE(cutoff_requested);

  // Check that the state file is cleared.
  EXPECT_FALSE(base::PathExists(GetStateFilePath()));

  // Cutoff and reboot are called after a delay.
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
  EXPECT_TRUE(reboot_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_TRUE(cutoff_requested);
}

TEST_F(RepairCompleteStateHandlerTest, GetNextStateCase_MetricsFailed) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  bool powerwash_requested = false, cutoff_requested = false,
       reboot_called = false, shutdown_called = false, metrics_called = false;
  auto handler = CreateStateHandler(&powerwash_requested, &cutoff_requested,
                                    &reboot_called, &shutdown_called,
                                    &metrics_called, true, false);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  handler->RunState();

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_BATTERY_CUTOFF);

  auto [error, state_case] = handler->GetNextStateCase(state);
  // Structured metrics recording is expected to fail as current library does
  // not support recording locally without user consent. We shouldn't let it
  // block the flow until the library actually supports it.
  EXPECT_EQ(error, RMAD_ERROR_EXPECT_SHUTDOWN);
  EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_TRUE(metrics_called);
  EXPECT_FALSE(cutoff_requested);

  // Check that the state file is cleared.
  EXPECT_FALSE(base::PathExists(GetStateFilePath()));

  // Cutoff and reboot are called after a delay.
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
  EXPECT_TRUE(reboot_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_TRUE(cutoff_requested);
}

TEST_F(RepairCompleteStateHandlerTest, GetNextStateCase_JsonFailed) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  base::WriteFile(GetPowerwashCountFilePath(), "1\n");
  bool powerwash_requested = false, cutoff_requested = false,
       reboot_called = false, shutdown_called = false, metrics_called = false;
  auto handler =
      CreateStateHandler(&powerwash_requested, &cutoff_requested,
                         &reboot_called, &shutdown_called, &metrics_called);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Check that the state file exists now.
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));

  handler->RunState();

  RmadState state;
  state.mutable_repair_complete()->set_shutdown(
      RepairCompleteState::RMAD_REPAIR_COMPLETE_BATTERY_CUTOFF);

  // Make |json_store_| read-only.
  base::SetPosixFilePermissions(GetStateFilePath(), 0444);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_CANNOT_WRITE);
  EXPECT_EQ(state_case, RmadState::StateCase::kRepairComplete);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_FALSE(metrics_called);
  EXPECT_FALSE(cutoff_requested);

  // Check that the shutdown action won't be called if the state file cannot be
  // cleared.
  task_environment_.FastForwardBy(RepairCompleteStateHandler::kShutdownDelay);
  EXPECT_FALSE(reboot_called);
  EXPECT_FALSE(shutdown_called);
  EXPECT_FALSE(cutoff_requested);
}

}  // namespace rmad
