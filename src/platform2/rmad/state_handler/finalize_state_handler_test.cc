// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/memory/scoped_refptr.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <brillo/file_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/state_handler/finalize_state_handler.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/utils/json_store.h"
#include "rmad/utils/mock_cr50_utils.h"
#include "rmad/utils/mock_write_protect_utils.h"

using testing::_;
using testing::DoAll;
using testing::Eq;
using testing::InSequence;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

namespace {

constexpr char kValidBoardIdType[] = "12345678";
constexpr char kInvalidBoardIdType[] = "ffffffff";
constexpr char kValidBoardIdFlags[] = "00007f80";
constexpr char kInvalidBoardIdFlags[] = "00007f7f";

struct StateHandlerArgs {
  // First WP check to know if factory mode is enabled.
  // Second WP check after disabling factory mode. WP is expected to be enabled.
  std::vector<bool> hwwp_status_list = {false, true};
  bool enable_swwp_success = true;
  bool disable_factory_mode_success = true;
  std::string board_id_type = kValidBoardIdType;
  std::string board_id_flags = kValidBoardIdFlags;
};

}  // namespace

namespace rmad {

class FinalizeStateHandlerTest : public StateHandlerTest {
 public:
  // Helper class to mock the callback function to send signal.
  class SignalSender {
   public:
    MOCK_METHOD(void,
                SendFinalizeProgressSignal,
                (const FinalizeStatus&),
                (const));
  };

  scoped_refptr<FinalizeStateHandler> CreateInitializedStateHandler(
      const StateHandlerArgs& args = {}) {
    // Mock |Cr50Utils|.
    auto mock_cr50_utils = std::make_unique<NiceMock<MockCr50Utils>>();
    ON_CALL(*mock_cr50_utils, DisableFactoryMode())
        .WillByDefault(Return(args.disable_factory_mode_success));
    ON_CALL(*mock_cr50_utils, GetBoardIdType(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(args.board_id_type), Return(true)));
    ON_CALL(*mock_cr50_utils, GetBoardIdFlags(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(args.board_id_flags), Return(true)));

    // Mock |WriteProtectUtils|.
    auto mock_write_protect_utils =
        std::make_unique<StrictMock<MockWriteProtectUtils>>();
    {
      InSequence seq;
      for (bool enabled : args.hwwp_status_list) {
        EXPECT_CALL(*mock_write_protect_utils,
                    GetHardwareWriteProtectionStatus(_))
            .WillOnce(DoAll(SetArgPointee<0, bool>(enabled), Return(true)));
      }
    }
    EXPECT_CALL(*mock_write_protect_utils, EnableSoftwareWriteProtection())
        .WillRepeatedly(Return(args.enable_swwp_success));

    // Register signal callback.
    daemon_callback_->SetFinalizeSignalCallback(
        base::BindRepeating(&SignalSender::SendFinalizeProgressSignal,
                            base::Unretained(&signal_sender_)));

    // Initialization should always succeed.
    auto handler = base::MakeRefCounted<FinalizeStateHandler>(
        json_store_, daemon_callback_, GetTempDirPath(),
        std::move(mock_cr50_utils), std::move(mock_write_protect_utils));
    EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

    return handler;
  }

  RmadState CreateFinalizeRequest(FinalizeState_FinalizeChoice choice) const {
    RmadState state;
    state.mutable_finalize()->set_choice(choice);
    return state;
  }

  void ExpectTransitionSucceeded(scoped_refptr<FinalizeStateHandler> handler,
                                 const RmadState& state,
                                 RmadState::StateCase expected_state_case) {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, RMAD_ERROR_OK);
    EXPECT_EQ(state_case, expected_state_case);
  }

  void ExpectTransitionFailedWithError(
      scoped_refptr<FinalizeStateHandler> handler,
      const RmadState& state,
      RmadErrorCode expected_error) {
    auto [error, state_case] = handler->GetNextStateCase(state);
    EXPECT_EQ(error, expected_error);
    EXPECT_EQ(state_case, RmadState::StateCase::kFinalize);
  }

  void ExpectSignal(FinalizeStatus_Status expected_status,
                    double expected_progress,
                    FinalizeStatus_Error expected_error =
                        FinalizeStatus::RMAD_FINALIZE_ERROR_UNKNOWN) {
    EXPECT_CALL(signal_sender_, SendFinalizeProgressSignal(_))
        .WillOnce(Invoke([expected_status, expected_progress,
                          expected_error](const FinalizeStatus& status) {
          EXPECT_EQ(status.status(), expected_status);
          EXPECT_DOUBLE_EQ(status.progress(), expected_progress);
          EXPECT_EQ(status.error(), expected_error);
        }));
    task_environment_.FastForwardBy(
        FinalizeStateHandler::kReportStatusInterval);
  }

 protected:
  StrictMock<SignalSender> signal_sender_;

  // Variables for TaskRunner.
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  base::RunLoop run_loop_;
};

TEST_F(FinalizeStateHandlerTest, InitializeState_HwwpDisabled_Succeeded) {
  auto handler = CreateInitializedStateHandler();

  handler->RunState();
  ExpectSignal(FinalizeStatus::RMAD_FINALIZE_STATUS_COMPLETE, 1);
}

TEST_F(FinalizeStateHandlerTest, InitializeState_HwwpEnabled_Succeeded) {
  StateHandlerArgs args = {.hwwp_status_list = {true, true}};
  auto handler = CreateInitializedStateHandler(args);

  handler->RunState();
  ExpectSignal(FinalizeStatus::RMAD_FINALIZE_STATUS_COMPLETE, 1);
}

TEST_F(FinalizeStateHandlerTest, InitializeState_EnableSwwpFailed) {
  StateHandlerArgs args = {.hwwp_status_list = {false},
                           .enable_swwp_success = false};
  auto handler = CreateInitializedStateHandler(args);

  handler->RunState();
  ExpectSignal(FinalizeStatus::RMAD_FINALIZE_STATUS_FAILED_BLOCKING, 0,
               FinalizeStatus::RMAD_FINALIZE_ERROR_CANNOT_ENABLE_SWWP);
}

TEST_F(FinalizeStateHandlerTest, InitializeState_DisableFactoryModeFailed) {
  StateHandlerArgs args = {.hwwp_status_list = {false},
                           .disable_factory_mode_success = false};
  auto handler = CreateInitializedStateHandler(args);

  handler->RunState();
  ExpectSignal(FinalizeStatus::RMAD_FINALIZE_STATUS_FAILED_BLOCKING, 0.5,
               FinalizeStatus::RMAD_FINALIZE_ERROR_CANNOT_ENABLE_HWWP);
}

TEST_F(FinalizeStateHandlerTest, InitializeState_HwwpDisabled) {
  StateHandlerArgs args = {.hwwp_status_list = {false, false}};
  auto handler = CreateInitializedStateHandler(args);

  handler->RunState();
  ExpectSignal(FinalizeStatus::RMAD_FINALIZE_STATUS_FAILED_BLOCKING, 0.8,
               FinalizeStatus::RMAD_FINALIZE_ERROR_CANNOT_ENABLE_HWWP);
}

TEST_F(FinalizeStateHandlerTest, InitializeState_InvalidBoardId) {
  StateHandlerArgs args = {.board_id_type = kInvalidBoardIdType};
  auto handler = CreateInitializedStateHandler(args);

  handler->RunState();
  ExpectSignal(FinalizeStatus::RMAD_FINALIZE_STATUS_FAILED_BLOCKING, 0.9,
               FinalizeStatus::RMAD_FINALIZE_ERROR_CR50);
}

TEST_F(FinalizeStateHandlerTest, InitializeState_InvalidBoardId_Bypass) {
  StateHandlerArgs args = {.board_id_type = kInvalidBoardIdType};
  auto handler = CreateInitializedStateHandler(args);

  // Bypass board ID check.
  EXPECT_TRUE(brillo::TouchFile(GetTempDirPath().AppendASCII(kTestDirPath)));

  handler->RunState();
  ExpectSignal(FinalizeStatus::RMAD_FINALIZE_STATUS_COMPLETE, 1);
}

TEST_F(FinalizeStateHandlerTest, InitializeState_InvalidBoardIdFlags) {
  StateHandlerArgs args = {.board_id_flags = kInvalidBoardIdFlags};
  auto handler = CreateInitializedStateHandler(args);

  handler->RunState();
  ExpectSignal(FinalizeStatus::RMAD_FINALIZE_STATUS_FAILED_BLOCKING, 0.9,
               FinalizeStatus::RMAD_FINALIZE_ERROR_CR50);
}

TEST_F(FinalizeStateHandlerTest, InitializeState_InvalidBoardIdFlags_Bypass) {
  StateHandlerArgs args = {.board_id_flags = kInvalidBoardIdFlags};
  auto handler = CreateInitializedStateHandler(args);

  // Bypass board ID check.
  EXPECT_TRUE(brillo::TouchFile(GetTempDirPath().AppendASCII(kTestDirPath)));

  handler->RunState();
  ExpectSignal(FinalizeStatus::RMAD_FINALIZE_STATUS_COMPLETE, 1);
}

TEST_F(FinalizeStateHandlerTest, GetNextStateCase_Succeeded) {
  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  task_environment_.RunUntilIdle();

  ExpectTransitionSucceeded(
      handler,
      CreateFinalizeRequest(FinalizeState::RMAD_FINALIZE_CHOICE_CONTINUE),
      RmadState::StateCase::kRepairComplete);
}

TEST_F(FinalizeStateHandlerTest, GetNextStateCase_InProgress) {
  auto handler = CreateInitializedStateHandler();
  handler->RunState();

  ExpectTransitionFailedWithError(
      handler,
      CreateFinalizeRequest(FinalizeState::RMAD_FINALIZE_CHOICE_CONTINUE),
      RMAD_ERROR_WAIT);

  task_environment_.RunUntilIdle();
}

TEST_F(FinalizeStateHandlerTest, GetNextStateCase_MissingState) {
  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  task_environment_.RunUntilIdle();

  ExpectTransitionFailedWithError(handler, RmadState(),
                                  RMAD_ERROR_REQUEST_INVALID);
}

TEST_F(FinalizeStateHandlerTest, GetNextStateCase_MissingArgs) {
  auto handler = CreateInitializedStateHandler();
  handler->RunState();
  task_environment_.RunUntilIdle();

  ExpectTransitionFailedWithError(
      handler,
      CreateFinalizeRequest(FinalizeState::RMAD_FINALIZE_CHOICE_UNKNOWN),
      RMAD_ERROR_REQUEST_ARGS_MISSING);
}

TEST_F(FinalizeStateHandlerTest, GetNextStateCase_BlockingFailure_Retry) {
  StateHandlerArgs args = {.hwwp_status_list = {false, false},
                           .disable_factory_mode_success = false};
  auto handler = CreateInitializedStateHandler(args);
  handler->RunState();
  task_environment_.RunUntilIdle();

  // Get blocking failure.
  ExpectTransitionFailedWithError(
      handler,
      CreateFinalizeRequest(FinalizeState::RMAD_FINALIZE_CHOICE_CONTINUE),
      RMAD_ERROR_FINALIZATION_FAILED);

  // Request a retry.
  ExpectTransitionFailedWithError(
      handler, CreateFinalizeRequest(FinalizeState::RMAD_FINALIZE_CHOICE_RETRY),
      RMAD_ERROR_WAIT);

  task_environment_.RunUntilIdle();

  // Still fails.
  ExpectTransitionFailedWithError(
      handler,
      CreateFinalizeRequest(FinalizeState::RMAD_FINALIZE_CHOICE_CONTINUE),
      RMAD_ERROR_FINALIZATION_FAILED);
}

}  // namespace rmad
