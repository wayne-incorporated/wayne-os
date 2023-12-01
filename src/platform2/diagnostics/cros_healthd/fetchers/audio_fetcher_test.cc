// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <vector>

#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/errors/error.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cras/dbus-proxy-mocks.h"
#include "diagnostics/cros_healthd/fetchers/audio_fetcher.h"
#include "diagnostics/cros_healthd/system/mock_context.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::WithArg;

const brillo::VariantDictionary kInactiveOutputDevice = {
    {cras::kNameProperty, std::string("Inactive output device")},
    {cras::kNodeVolumeProperty, static_cast<uint64_t>(10)},
    {cras::kIsInputProperty, false},
    {cras::kActiveProperty, false}};
const brillo::VariantDictionary kActiveOutputDevice = {
    {cras::kNameProperty, std::string("Active output device")},
    {cras::kNodeVolumeProperty, static_cast<uint64_t>(20)},
    {cras::kIsInputProperty, false},
    {cras::kActiveProperty, true},
    {cras::kNumberOfUnderrunsProperty, static_cast<uint32_t>(13)},
    {cras::kNumberOfSevereUnderrunsProperty, static_cast<uint32_t>(3)}};
const brillo::VariantDictionary kInactiveInputDevice = {
    {cras::kNameProperty, std::string("Inactive input device")},
    {cras::kNodeVolumeProperty, static_cast<uint64_t>(30)},
    {cras::kIsInputProperty, true},
    {cras::kActiveProperty, false}};
const brillo::VariantDictionary kActiveInputDevice = {
    {cras::kNameProperty, std::string("Active input device")},
    {cras::kNodeVolumeProperty, static_cast<uint64_t>(40)},
    {cras::kInputNodeGainProperty, static_cast<uint32_t>(77)},
    {cras::kIsInputProperty, true},
    {cras::kActiveProperty, true}};

struct GetVolumeStateOutput {
  bool output_mute;
  bool input_mute;
  bool output_user_mute;
};

class AudioFetcherTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Set a default behavior for these methods. These may be overridden in
    // tests.
    ON_CALL(*mock_cras_proxy(), GetVolumeState(_, _, _, _, _, _))
        .WillByDefault(Return(true));
    EXPECT_CALL(*mock_cras_proxy(), GetVolumeState(_, _, _, _, _, _))
        .Times(AnyNumber());
    ON_CALL(*mock_cras_proxy(), GetNodeInfos(_, _, _))
        .WillByDefault(Return(true));
    EXPECT_CALL(*mock_cras_proxy(), GetNodeInfos(_, _, _)).Times(AnyNumber());
  }

  org::chromium::cras::ControlProxyMock* mock_cras_proxy() {
    return mock_context_.mock_cras_proxy();
  }

  void SetExpectedVolumeState(bool output_mute,
                              bool input_mute,
                              bool output_user_mute) {
    EXPECT_CALL(*mock_cras_proxy(), GetVolumeState(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<1>(output_mute),
                        SetArgPointee<2>(input_mute),
                        SetArgPointee<3>(output_user_mute), Return(true)));
  }

  void SetExpectedNodeInfos(
      const std::vector<brillo::VariantDictionary>& node_info) {
    EXPECT_CALL(*mock_cras_proxy(), GetNodeInfos(_, _, _))
        .WillOnce(DoAll(SetArgPointee<0>(node_info), Return(true)));
  }

  void SetExpectedVolumeStateError() {
    EXPECT_CALL(*mock_cras_proxy(), GetVolumeState(_, _, _, _, _, _))
        .WillOnce(DoAll(WithArg<4>(Invoke([](brillo::ErrorPtr* error) {
                          *error = brillo::Error::Create(FROM_HERE, "", "", "");
                        })),
                        Return(false)));
  }

  void SetExpectedNodeInfosError() {
    EXPECT_CALL(*mock_cras_proxy(), GetNodeInfos(_, _, _))
        .WillOnce(DoAll(WithArg<1>(Invoke([](brillo::ErrorPtr* error) {
                          *error = brillo::Error::Create(FROM_HERE, "", "", "");
                        })),
                        Return(false)));
  }

  mojom::AudioResultPtr FetchAudioInfoSync() {
    base::test::TestFuture<mojom::AudioResultPtr> future;
    FetchAudioInfo(&mock_context_, future.GetCallback());
    return future.Take();
  }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  MockContext mock_context_;
};

class AudioFetcherGetVolumeStateTest
    : public AudioFetcherTest,
      public testing::WithParamInterface<GetVolumeStateOutput> {
 protected:
  GetVolumeStateOutput params() const { return GetParam(); }
};

// Test that we can fetch all audio metrics correctly.
//
// This is a parameterized test, we test all possible combination of
// GetVolumeState() output.
TEST_P(AudioFetcherGetVolumeStateTest, FetchAudioInfo) {
  const bool output_mute = params().output_mute;
  const bool input_mute = params().input_mute;
  const bool output_user_mute = params().output_user_mute;
  std::string output_device_name =
      brillo::GetVariantValueOrDefault<std::string>(kActiveOutputDevice,
                                                    cras::kNameProperty);
  std::string input_device_name = brillo::GetVariantValueOrDefault<std::string>(
      kActiveInputDevice, cras::kNameProperty);
  uint64_t output_volume = brillo::GetVariantValueOrDefault<uint64_t>(
      kActiveOutputDevice, cras::kNodeVolumeProperty);
  uint32_t input_gain = brillo::GetVariantValueOrDefault<uint32_t>(
      kActiveInputDevice, cras::kInputNodeGainProperty);
  uint32_t underruns = brillo::GetVariantValueOrDefault<uint32_t>(
      kActiveOutputDevice, cras::kNumberOfUnderrunsProperty);
  uint32_t severe_underruns = brillo::GetVariantValueOrDefault<uint32_t>(
      kActiveOutputDevice, cras::kNumberOfSevereUnderrunsProperty);

  SetExpectedVolumeState(output_mute, input_mute, output_user_mute);
  SetExpectedNodeInfos({kActiveOutputDevice, kActiveInputDevice});

  auto audio_result = FetchAudioInfoSync();
  ASSERT_TRUE(audio_result->is_audio_info());

  const auto& audio = audio_result->get_audio_info();
  EXPECT_EQ(output_mute | output_user_mute, audio->output_mute);
  EXPECT_EQ(input_mute, audio->input_mute);
  EXPECT_EQ(output_device_name, audio->output_device_name);
  EXPECT_EQ(output_volume, audio->output_volume);
  EXPECT_EQ(input_device_name, audio->input_device_name);
  EXPECT_EQ(input_gain, audio->input_gain);
  EXPECT_EQ(underruns, audio->underruns);
  EXPECT_EQ(severe_underruns, audio->severe_underruns);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    AudioFetcherGetVolumeStateTest,
    testing::Values(GetVolumeStateOutput{false, false, false},
                    GetVolumeStateOutput{false, false, true},
                    GetVolumeStateOutput{false, true, false},
                    GetVolumeStateOutput{false, true, true},
                    GetVolumeStateOutput{true, false, false},
                    GetVolumeStateOutput{true, false, true},
                    GetVolumeStateOutput{true, true, false},
                    GetVolumeStateOutput{true, true, true}));

// Test no active output device.
TEST_F(AudioFetcherTest, FetchAudioInfoWithoutActiveOutputDevice) {
  auto audio_result = FetchAudioInfoSync();
  ASSERT_TRUE(audio_result->is_audio_info());

  const auto& audio = audio_result->get_audio_info();
  EXPECT_EQ("No active output device", audio->output_device_name);
}

// Test that when GetVolumeState fails.
TEST_F(AudioFetcherTest, FetchAudioInfoGetVolumeStateFail) {
  SetExpectedVolumeStateError();

  auto audio_result = FetchAudioInfoSync();
  ASSERT_TRUE(audio_result->is_error());
  EXPECT_EQ(audio_result->get_error()->type,
            mojom::ErrorType::kSystemUtilityError);
}

// Test that when GetNodeInfos fails.
TEST_F(AudioFetcherTest, FetchAudioInfoGetNodeInfosFail) {
  SetExpectedNodeInfosError();

  auto audio_result = FetchAudioInfoSync();
  ASSERT_TRUE(audio_result->is_error());
  EXPECT_EQ(audio_result->get_error()->type,
            mojom::ErrorType::kSystemUtilityError);
}

}  // namespace
}  // namespace diagnostics
