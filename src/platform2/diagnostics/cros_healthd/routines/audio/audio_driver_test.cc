// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/run_loop.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <brillo/errors/error.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "cras/dbus-proxy-mocks.h"
#include "diagnostics/cros_healthd/routines/audio/audio_driver.h"
#include "diagnostics/cros_healthd/routines/routine_observer_for_testing.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::WithArg;

const brillo::VariantDictionary kUnknownDevice = {
    {cras::kDeviceLastOpenResultProperty,
     /*unknown*/ static_cast<uint32_t>(0)}};
const brillo::VariantDictionary kSuccessDevice = {
    {cras::kDeviceLastOpenResultProperty,
     /*success*/ static_cast<uint32_t>(1)}};
const brillo::VariantDictionary kFailureDevice = {
    {cras::kDeviceLastOpenResultProperty,
     /*failure*/ static_cast<uint32_t>(2)}};

class AudioDriverRoutineTest : public testing::Test {
 protected:
  AudioDriverRoutineTest() = default;
  AudioDriverRoutineTest(const AudioDriverRoutineTest&) = delete;
  AudioDriverRoutineTest& operator=(const AudioDriverRoutineTest&) = delete;

  void SetUp() {
    routine_ = std::make_unique<AudioDriverRoutine>(
        &mock_context_, mojom::AudioDriverRoutineArgument::New());
  }

  org::chromium::cras::ControlProxyMock* mock_cras_proxy() {
    return mock_context_.mock_cras_proxy();
  }

  void SetIsInternalCardDetected(bool detected) {
    EXPECT_CALL(*mock_cras_proxy(), IsInternalCardDetected(_, _, _))
        .WillOnce(DoAll(SetArgPointee<0>(detected), Return(true)));
  }

  void SetIsInternalCardDetectedError() {
    EXPECT_CALL(*mock_cras_proxy(), IsInternalCardDetected(_, _, _))
        .WillOnce(DoAll(WithArg<1>(Invoke([](brillo::ErrorPtr* error) {
                          *error = brillo::Error::Create(FROM_HERE, "", "", "");
                        })),
                        Return(false)));
  }

  void SetExpectedNodeInfos(
      const std::vector<brillo::VariantDictionary>& node_info) {
    EXPECT_CALL(*mock_cras_proxy(), GetNodeInfos(_, _, _))
        .WillOnce(DoAll(SetArgPointee<0>(node_info), Return(true)));
  }

  void SetExpectedNodeInfosError() {
    EXPECT_CALL(*mock_cras_proxy(), GetNodeInfos(_, _, _))
        .WillOnce(DoAll(WithArg<1>(Invoke([](brillo::ErrorPtr* error) {
                          *error = brillo::Error::Create(FROM_HERE, "", "", "");
                        })),
                        Return(false)));
  }

  mojom::RoutineStatePtr RunRoutineAndWaitForExit() {
    base::RunLoop run_loop;
    routine_->SetOnExceptionCallback(
        base::BindOnce([](uint32_t error, const std::string& reason) {
          CHECK(false) << "An exception has occurred when it shouldn't have.";
        }));
    RoutineObserverForTesting observer{run_loop.QuitClosure()};
    routine_->AddObserver(observer.receiver_.BindNewPipeAndPassRemote());
    routine_->Start();
    run_loop.Run();
    return std::move(observer.state_);
  }

  void RunRoutineAndWaitForException() {
    base::RunLoop run_loop;
    routine_->SetOnExceptionCallback(base::BindLambdaForTesting(
        [&](uint32_t error, const std::string& reason) { run_loop.Quit(); }));
    routine_->Start();
    run_loop.Run();
  }

  base::test::TaskEnvironment task_environment_;
  MockContext mock_context_;
  std::unique_ptr<AudioDriverRoutine> routine_;
};

// Test that the audio driver routine can run successfully.
TEST_F(AudioDriverRoutineTest, RoutineSuccess) {
  SetIsInternalCardDetected(true);
  SetExpectedNodeInfos({kSuccessDevice, kUnknownDevice});

  mojom::RoutineStatePtr result = RunRoutineAndWaitForExit();
  EXPECT_EQ(result->percentage, 100);
  EXPECT_TRUE(result->state_union->is_finished());
  EXPECT_TRUE(result->state_union->get_finished()->has_passed);
  EXPECT_TRUE(result->state_union->get_finished()
                  ->detail->get_audio_driver()
                  ->internal_card_detected);
  EXPECT_TRUE(result->state_union->get_finished()
                  ->detail->get_audio_driver()
                  ->audio_devices_succeed_to_open);
}

// Test that the routine raises an exception when CRAS API fail.
TEST_F(AudioDriverRoutineTest, CrasIsInternalCardDetectedAPIFail) {
  SetIsInternalCardDetectedError();

  RunRoutineAndWaitForException();
}

// Test that the routine raises an exception when CRAS API fail.
TEST_F(AudioDriverRoutineTest, CrasGetNodesAPIFail) {
  SetIsInternalCardDetected(true);
  SetExpectedNodeInfosError();

  RunRoutineAndWaitForException();
}

// Test that the routine reports failure when no internal card is detected.
TEST_F(AudioDriverRoutineTest, NoInternalCardIsDetected) {
  SetIsInternalCardDetected(false);
  SetExpectedNodeInfos({kSuccessDevice, kUnknownDevice});

  mojom::RoutineStatePtr result = RunRoutineAndWaitForExit();
  EXPECT_EQ(result->percentage, 100);
  EXPECT_TRUE(result->state_union->is_finished());
  EXPECT_FALSE(result->state_union->get_finished()->has_passed);
  EXPECT_FALSE(result->state_union->get_finished()
                   ->detail->get_audio_driver()
                   ->internal_card_detected);
  EXPECT_TRUE(result->state_union->get_finished()
                  ->detail->get_audio_driver()
                  ->audio_devices_succeed_to_open);
}

// Test that the routine reports failure when there is one device that fails to
// open.
TEST_F(AudioDriverRoutineTest, AudioDeviceFailToOpen) {
  SetIsInternalCardDetected(true);
  SetExpectedNodeInfos({kSuccessDevice, kFailureDevice, kUnknownDevice});

  mojom::RoutineStatePtr result = RunRoutineAndWaitForExit();
  EXPECT_EQ(result->percentage, 100);
  EXPECT_TRUE(result->state_union->is_finished());
  EXPECT_FALSE(result->state_union->get_finished()->has_passed);
  EXPECT_TRUE(result->state_union->get_finished()
                  ->detail->get_audio_driver()
                  ->internal_card_detected);
  EXPECT_FALSE(result->state_union->get_finished()
                   ->detail->get_audio_driver()
                   ->audio_devices_succeed_to_open);
}

}  // namespace
}  // namespace diagnostics
