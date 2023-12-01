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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/logs/logs_constants.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/state_handler/welcome_screen_state_handler.h"
#include "rmad/system/mock_hardware_verifier_client.h"
#include "rmad/utils/json_store.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

namespace {

constexpr char kUnqualifiedDramErrorStr[] = "Unqualified dram: dram_1234";
constexpr char kUnqualifiedBatteryErrorStr[] =
    "Unqualified battery: battery_5678";
constexpr char kVerificationFailedErrorStr[] =
    "Unqualified dram: dram_1234\nUnqualified battery: battery_5678";
constexpr char kVerificationFailedErrorLogStr[] =
    "Unqualified dram: dram_1234, Unqualified battery: battery_5678";

struct StateHandlerArgs {
  bool hw_verification_request_success = true;
  bool hw_verification_result = true;
};

}  // namespace

namespace rmad {

class WelcomeScreenStateHandlerTest : public StateHandlerTest {
 public:
  // Helper class to mock the callback function to send signal.
  class SignalSender {
   public:
    MOCK_METHOD(void,
                SendHardwareVerificationSignal,
                (const HardwareVerificationResult&),
                (const));
  };

  scoped_refptr<WelcomeScreenStateHandler> CreateInitializedStateHandler(
      const StateHandlerArgs& args = {}) {
    // Mock |HardwareVerifierClient|.
    auto mock_hardware_verifier_client =
        std::make_unique<NiceMock<MockHardwareVerifierClient>>();
    ON_CALL(*mock_hardware_verifier_client, GetHardwareVerificationResult(_, _))
        .WillByDefault(
            [args](bool* is_compliant,
                   std::vector<std::string>* error_strings) {
              if (args.hw_verification_request_success) {
                *is_compliant = args.hw_verification_result;
                if (!args.hw_verification_result) {
                  *error_strings = {kUnqualifiedDramErrorStr,
                                    kUnqualifiedBatteryErrorStr};
                }
              }
              return args.hw_verification_request_success;
            });

    // Register signal callback.
    daemon_callback_->SetHardwareVerificationSignalCallback(
        base::BindRepeating(&SignalSender::SendHardwareVerificationSignal,
                            base::Unretained(&signal_sender_)));

    // Initialization should always succeed.
    auto handler = base::MakeRefCounted<WelcomeScreenStateHandler>(
        json_store_, daemon_callback_,
        std::move(mock_hardware_verifier_client));
    EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

    return handler;
  }

  void ExpectSignal(bool is_compliant, const std::string& error_str) {
    EXPECT_CALL(signal_sender_, SendHardwareVerificationSignal(_))
        .WillOnce(Invoke([is_compliant,
                          error_str](const HardwareVerificationResult& result) {
          EXPECT_EQ(result.is_compliant(), is_compliant);
          EXPECT_EQ(result.error_str(), error_str);
        }));
    task_environment_.RunUntilIdle();
  }

 protected:
  StrictMock<SignalSender> signal_sender_;

  // Variables for TaskRunner.
  base::test::TaskEnvironment task_environment_;
};

TEST_F(WelcomeScreenStateHandlerTest,
       InitializeState_Succeeded_VerificationPass_DoGetStateTask) {
  auto handler = CreateInitializedStateHandler();

  RmadState state = handler->GetState(true);
  ExpectSignal(true, "");

  // Verify the hardware verification result is recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  CHECK_EQ(events->size(), 1);

  const base::Value::Dict* verification_result =
      (*events)[0].GetDict().FindDict(kDetails);
  EXPECT_TRUE(verification_result->FindBool(kLogIsCompliant).has_value());
  EXPECT_TRUE(verification_result->FindBool(kLogIsCompliant).value());
  EXPECT_EQ("", *verification_result->FindString(kLogUnqualifiedComponents));
}

TEST_F(WelcomeScreenStateHandlerTest,
       InitializeState_Succeeded_VerificationPass_NoGetStateTask) {
  auto handler = CreateInitializedStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();
}

TEST_F(WelcomeScreenStateHandlerTest,
       InitializeState_Succeeded_VerificationFail) {
  auto handler =
      CreateInitializedStateHandler({.hw_verification_result = false});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState(true);
  ExpectSignal(false, kVerificationFailedErrorStr);

  // Verify the hardware verification result is recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  CHECK_EQ(events->size(), 1);

  const base::Value::Dict* verification_result =
      (*events)[0].GetDict().FindDict(kDetails);
  EXPECT_TRUE(verification_result->FindBool(kLogIsCompliant).has_value());
  EXPECT_FALSE(verification_result->FindBool(kLogIsCompliant).value());
  EXPECT_EQ(kVerificationFailedErrorLogStr,
            *verification_result->FindString(kLogUnqualifiedComponents));
}

TEST_F(WelcomeScreenStateHandlerTest,
       InitializeState_Succeeded_VerificationCallFail) {
  auto handler =
      CreateInitializedStateHandler({.hw_verification_request_success = false});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(WelcomeScreenStateHandlerTest, GetNextStateCase_Succeeded) {
  auto handler = CreateInitializedStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_welcome()->set_choice(
      WelcomeState::RMAD_CHOICE_FINALIZE_REPAIR);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kComponentsRepair);
}

TEST_F(WelcomeScreenStateHandlerTest, GetNextStateCase_MissingState) {
  auto handler = CreateInitializedStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // No WelcomeScreenState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kWelcome);
}

TEST_F(WelcomeScreenStateHandlerTest, GetNextStateCase_MissingArgs) {
  auto handler = CreateInitializedStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_welcome()->set_choice(WelcomeState::RMAD_CHOICE_UNKNOWN);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_ARGS_MISSING);
  EXPECT_EQ(state_case, RmadState::StateCase::kWelcome);
}

}  // namespace rmad
