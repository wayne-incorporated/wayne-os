// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/memory/scoped_refptr.h>
#include <base/test/task_environment.h>
#include <brillo/file_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_constants.h"
#include "rmad/metrics/metrics_utils.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/state_handler/write_protect_disable_rsu_state_handler.h"
#include "rmad/utils/mock_cr50_utils.h"
#include "rmad/utils/mock_crossystem_utils.h"
#include "rmad/utils/mock_write_protect_utils.h"

using testing::_;
using testing::Assign;
using testing::DoAll;
using testing::Eq;
using testing::Ne;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace {

constexpr char kTestChallengeCode[] = "ABCDEFGH";
constexpr char kTestUnlockCode[] = "abcdefgh";
constexpr char kWrongUnlockCode[] = "aaa";
constexpr char kTestHwid[] = "MODEL TEST";
constexpr char kTestUrl[] =
    "https://www.google.com/chromeos/partner/console/"
    "cr50reset?challenge=ABCDEFGH&hwid=MODEL_TEST";

struct StateHandlerArgs {
  bool factory_mode_enabled = false;
  bool is_cros_debug = false;
  bool* powerwash_requested = nullptr;
  bool* reboot_toggled = nullptr;
};

}  // namespace

namespace rmad {

class WriteProtectDisableRsuStateHandlerTest : public StateHandlerTest {
 public:
  scoped_refptr<WriteProtectDisableRsuStateHandler> CreateStateHandler(
      const StateHandlerArgs& args = {}) {
    // Mock |Cr50Utils|.
    auto mock_cr50_utils = std::make_unique<NiceMock<MockCr50Utils>>();
    ON_CALL(*mock_cr50_utils, IsFactoryModeEnabled())
        .WillByDefault(Return(args.factory_mode_enabled));
    ON_CALL(*mock_cr50_utils, GetRsuChallengeCode(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(kTestChallengeCode), Return(true)));
    ON_CALL(*mock_cr50_utils, PerformRsu(Eq(kTestUnlockCode)))
        .WillByDefault(Return(true));
    ON_CALL(*mock_cr50_utils, PerformRsu(Ne(kTestUnlockCode)))
        .WillByDefault(Return(false));

    // Mock |CrosSystemUtils|.
    auto mock_crossystem_utils =
        std::make_unique<NiceMock<MockCrosSystemUtils>>();
    ON_CALL(*mock_crossystem_utils,
            GetString(Eq(CrosSystemUtils::kHwidProperty), _))
        .WillByDefault(DoAll(SetArgPointee<1>(kTestHwid), Return(true)));
    ON_CALL(*mock_crossystem_utils,
            GetInt(Eq(CrosSystemUtils::kCrosDebugProperty), _))
        .WillByDefault(
            DoAll(SetArgPointee<1>(args.is_cros_debug ? 1 : 0), Return(true)));

    // Mock |WriteProtectUtils|.
    auto mock_write_protect_utils =
        std::make_unique<NiceMock<MockWriteProtectUtils>>();
    ON_CALL(*mock_write_protect_utils, GetHardwareWriteProtectionStatus(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(!args.factory_mode_enabled), Return(true)));

    // Register request powerwash feedback.
    daemon_callback_->SetExecuteRequestRmaPowerwashCallback(base::BindRepeating(
        &WriteProtectDisableRsuStateHandlerTest::RequestRmaPowerwash,
        base::Unretained(this), args.powerwash_requested));

    // Register reboot EC callback.
    daemon_callback_->SetExecuteRebootEcCallback(
        base::BindRepeating(&WriteProtectDisableRsuStateHandlerTest::RebootEc,
                            base::Unretained(this), args.reboot_toggled));

    return base::MakeRefCounted<WriteProtectDisableRsuStateHandler>(
        json_store_, daemon_callback_, GetTempDirPath(),
        std::move(mock_cr50_utils), std::move(mock_crossystem_utils),
        std::move(mock_write_protect_utils));
  }

  void RequestRmaPowerwash(bool* request_powerwash,
                           base::OnceCallback<void(bool)> callback) {
    if (request_powerwash) {
      *request_powerwash = true;
    }
    std::move(callback).Run(true);
  }

  void RebootEc(bool* reboot_toggled, base::OnceCallback<void(bool)> callback) {
    if (reboot_toggled) {
      *reboot_toggled = true;
    }
    std::move(callback).Run(true);
  }

 protected:
  // Variables for TaskRunner.
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(WriteProtectDisableRsuStateHandlerTest,
       InitializeState_FactoryModeEnabled) {
  auto handler = CreateStateHandler({.factory_mode_enabled = true});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  EXPECT_EQ(handler->GetState().wp_disable_rsu().rsu_done(), true);
  EXPECT_EQ(handler->GetState().wp_disable_rsu().challenge_code(),
            kTestChallengeCode);
  EXPECT_EQ(handler->GetState().wp_disable_rsu().hwid(), kTestHwid);
  EXPECT_EQ(handler->GetState().wp_disable_rsu().challenge_url(), kTestUrl);

  // Verify the challenge code is not recorded to logs when factory mode is
  // already enabled.
  base::Value logs(base::Value::Type::DICT);
  EXPECT_FALSE(json_store_->GetValue(kLogs, &logs));
}

TEST_F(WriteProtectDisableRsuStateHandlerTest,
       InitializeState_FactoryModeDisabled) {
  auto handler = CreateStateHandler({.factory_mode_enabled = false});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  EXPECT_EQ(handler->GetState().wp_disable_rsu().rsu_done(), false);
  EXPECT_EQ(handler->GetState().wp_disable_rsu().challenge_code(),
            kTestChallengeCode);
  EXPECT_EQ(handler->GetState().wp_disable_rsu().hwid(), kTestHwid);
  EXPECT_EQ(handler->GetState().wp_disable_rsu().challenge_url(), kTestUrl);

  // Verify the challenge code was recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(handler->GetState().wp_disable_rsu().challenge_code(),
            *event.FindDict(kDetails)->FindString(kLogRsuChallengeCode));
  EXPECT_EQ(handler->GetState().wp_disable_rsu().hwid(),
            *event.FindDict(kDetails)->FindString(kLogRsuHwid));
}

TEST_F(WriteProtectDisableRsuStateHandlerTest,
       TryGetNextStateCaseAtBoot_Succeeded) {
  bool powerwash_requested = false, reboot_toggled = false;
  auto handler =
      CreateStateHandler({.factory_mode_enabled = true,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableComplete);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);

  // Check |json_store_|.
  std::string wp_disable_method_name;
  WpDisableMethod wp_disable_method;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableMethod, &wp_disable_method_name));
  EXPECT_TRUE(
      WpDisableMethod_Parse(wp_disable_method_name, &wp_disable_method));
  EXPECT_EQ(wp_disable_method, RMAD_WP_DISABLE_METHOD_RSU);

  // Check if the metrics value set correctly.
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsWpDisableMethod, &wp_disable_method_name));
  EXPECT_TRUE(
      WpDisableMethod_Parse(wp_disable_method_name, &wp_disable_method));
  EXPECT_EQ(wp_disable_method, RMAD_WP_DISABLE_METHOD_RSU);
}

TEST_F(WriteProtectDisableRsuStateHandlerTest,
       TryGetNextStateCaseAtBoot_Failed_FactoryModeDisabled) {
  bool powerwash_requested = false, reboot_toggled = false;
  auto handler =
      CreateStateHandler({.factory_mode_enabled = false,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
}

TEST_F(WriteProtectDisableRsuStateHandlerTest, GetNextStateCase_Succeeded_Rsu) {
  bool powerwash_requested = false, reboot_toggled = false;
  auto handler =
      CreateStateHandler({.factory_mode_enabled = false,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wp_disable_rsu()->set_unlock_code(kTestUnlockCode);

  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_toggled);
  }

  // A second call to |GetNextStateCase| before rebooting is fine.
  {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
    EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);
    EXPECT_FALSE(powerwash_requested);
    EXPECT_FALSE(reboot_toggled);
  }

  task_environment_.FastForwardBy(
      WriteProtectDisableRsuStateHandler::kRebootDelay);
  EXPECT_TRUE(powerwash_requested);
  EXPECT_TRUE(reboot_toggled);
}

TEST_F(WriteProtectDisableRsuStateHandlerTest,
       GetNextStateCase_PowerwashDisabled_CrosDebug) {
  bool powerwash_requested = false, reboot_toggled = false;
  auto handler =
      CreateStateHandler({.factory_mode_enabled = false,
                          .is_cros_debug = true,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  brillo::TouchFile(GetTempDirPath().AppendASCII(kDisablePowerwashFilePath));

  RmadState state;
  state.mutable_wp_disable_rsu()->set_unlock_code(kTestUnlockCode);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);

  task_environment_.FastForwardBy(
      WriteProtectDisableRsuStateHandler::kRebootDelay);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_TRUE(reboot_toggled);
}

TEST_F(WriteProtectDisableRsuStateHandlerTest,
       GetNextStateCase_PowerwashDisabled_NonCrosDebug) {
  bool powerwash_requested = false, reboot_toggled = false;
  auto handler =
      CreateStateHandler({.factory_mode_enabled = false,
                          .is_cros_debug = false,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  brillo::TouchFile(GetTempDirPath().AppendASCII(kDisablePowerwashFilePath));

  RmadState state;
  state.mutable_wp_disable_rsu()->set_unlock_code(kTestUnlockCode);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_EXPECT_REBOOT);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);

  task_environment_.FastForwardBy(
      WriteProtectDisableRsuStateHandler::kRebootDelay);
  EXPECT_TRUE(powerwash_requested);
  EXPECT_TRUE(reboot_toggled);
}

TEST_F(WriteProtectDisableRsuStateHandlerTest, GetNextStateCase_MissingState) {
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // No WriteProtectDisableRsuState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);
}

TEST_F(WriteProtectDisableRsuStateHandlerTest,
       GetNextStateCase_WrongUnlockCode) {
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wp_disable_rsu()->set_unlock_code(kWrongUnlockCode);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_WRITE_PROTECT_DISABLE_RSU_CODE_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);
}

}  // namespace rmad
