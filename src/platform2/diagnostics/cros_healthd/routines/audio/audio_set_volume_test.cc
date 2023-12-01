// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "cras/dbus-proxy-mocks.h"
#include "diagnostics/cros_healthd/routines/audio/audio_set_volume.h"
#include "diagnostics/cros_healthd/system/fake_mojo_service.h"
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

constexpr uint8_t target_volume = 42;
constexpr uint64_t target_node_id = 1234567;
constexpr bool target_mute_on = false;

class AudioSetVolumeRoutineTest : public testing::Test {
 protected:
  AudioSetVolumeRoutineTest() = default;
  AudioSetVolumeRoutineTest(const AudioSetVolumeRoutineTest&) = delete;
  AudioSetVolumeRoutineTest& operator=(const AudioSetVolumeRoutineTest&) =
      delete;

  void SetUp() override {
    mock_context_.fake_mojo_service()->InitializeFakeMojoService();
  }

  void CreateRoutine() {
    routine_ = std::make_unique<AudioSetVolumeRoutine>(
        &mock_context_, target_node_id, target_volume, target_mute_on);
  }

  org::chromium::cras::ControlProxyMock* mock_cras_proxy() {
    return mock_context_.mock_cras_proxy();
  }

  void SetSetOutputNodeVolume() {
    EXPECT_CALL(*mock_cras_proxy(),
                SetOutputNodeVolume(target_node_id, target_volume, _, _))
        .WillOnce(Return(true));
  }

  void SetSetOutputNodeVolumeError() {
    EXPECT_CALL(*mock_cras_proxy(), SetOutputNodeVolume(_, _, _, _))
        .WillOnce(DoAll(WithArg<2>(Invoke([](brillo::ErrorPtr* error) {
                          *error = brillo::Error::Create(FROM_HERE, "", "", "");
                        })),
                        Return(false)));
  }

  void SetAudioOutputMuteRequestResult(bool expected_result) {
    mock_context_.fake_mojo_service()
        ->fake_chromium_data_collector()
        .SetAudioOutputMuteRequestResult(expected_result);
  }

  void WaitUntilRoutineFinished(base::OnceClosure callback) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE, std::move(callback),
        // This routine should be finished within 1 second. Set 2 seconds as a
        // safe timeout.
        base::Milliseconds(2000));
  }

  MockContext mock_context_;
  std::unique_ptr<AudioSetVolumeRoutine> routine_;
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
  base::test::TaskEnvironment task_environment_;
};

TEST_F(AudioSetVolumeRoutineTest, DefaultConstruction) {
  CreateRoutine();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
}

TEST_F(AudioSetVolumeRoutineTest, SuccessfulCase) {
  CreateRoutine();
  SetSetOutputNodeVolume();
  SetAudioOutputMuteRequestResult(true);

  routine_->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([&]() {
    EXPECT_EQ(routine_->GetStatus(),
              mojom::DiagnosticRoutineStatusEnum::kPassed);
  }));
}

TEST_F(AudioSetVolumeRoutineTest, SetOutputUserMuteError) {
  CreateRoutine();
  SetSetOutputNodeVolume();
  SetAudioOutputMuteRequestResult(false);

  routine_->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([&]() {
    EXPECT_EQ(routine_->GetStatus(),
              mojom::DiagnosticRoutineStatusEnum::kFailed);
  }));
}

TEST_F(AudioSetVolumeRoutineTest, SetOutputNodeVolumeError) {
  CreateRoutine();
  SetSetOutputNodeVolumeError();
  SetAudioOutputMuteRequestResult(true);

  routine_->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([&]() {
    EXPECT_EQ(routine_->GetStatus(),
              mojom::DiagnosticRoutineStatusEnum::kError);
  }));
}

}  // namespace
}  // namespace diagnostics
