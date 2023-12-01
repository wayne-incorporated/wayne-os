// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <vector>

#include <base/check.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "cras/dbus-proxy-mocks.h"
#include "diagnostics/cros_healthd/routines/audio/audio_set_gain.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::WithArg;

constexpr uint8_t target_gain = 42;
constexpr uint64_t target_node_id = 1234567;

class AudioSetGainRoutineTest : public testing::Test {
 protected:
  AudioSetGainRoutineTest() = default;
  AudioSetGainRoutineTest(const AudioSetGainRoutineTest&) = delete;
  AudioSetGainRoutineTest& operator=(const AudioSetGainRoutineTest&) = delete;

  void CreateRoutine() {
    routine_ = std::make_unique<AudioSetGainRoutine>(
        &mock_context_, target_node_id, target_gain);
  }

  org::chromium::cras::ControlProxyMock* mock_cras_proxy() {
    return mock_context_.mock_cras_proxy();
  }

  void SetSetInputNodeGain() {
    EXPECT_CALL(*mock_cras_proxy(),
                SetInputNodeGain(target_node_id, target_gain, _, _))
        .WillOnce(Return(true));
  }

  void SetSetInputNodeGainError() {
    EXPECT_CALL(*mock_cras_proxy(), SetInputNodeGain(_, _, _, _))
        .WillOnce(DoAll(WithArg<2>(Invoke([](brillo::ErrorPtr* error) {
                          *error = brillo::Error::Create(FROM_HERE, "", "", "");
                        })),
                        Return(false)));
  }

  MockContext mock_context_;
  std::unique_ptr<AudioSetGainRoutine> routine_;
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
};

TEST_F(AudioSetGainRoutineTest, DefaultConstruction) {
  CreateRoutine();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
}

TEST_F(AudioSetGainRoutineTest, SuccessfulCase) {
  CreateRoutine();
  SetSetInputNodeGain();

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kPassed);
}

TEST_F(AudioSetGainRoutineTest, SetInputNodeGainError) {
  CreateRoutine();
  SetSetInputNodeGainError();

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kError);
}

}  // namespace
}  // namespace diagnostics
