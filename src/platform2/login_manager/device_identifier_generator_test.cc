// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/device_identifier_generator.h"

#include <stdint.h>
#include <stdlib.h>

#include <map>
#include <set>
#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "login_manager/login_metrics.h"
#include "login_manager/mock_metrics.h"
#include "login_manager/system_utils_impl.h"

using testing::_;
using testing::SaveArg;

namespace login_manager {

namespace {

// A SystemUtils implementation that mocks time.
class FakeSystemUtils : public SystemUtilsImpl {
 public:
  FakeSystemUtils() : time_(0) {}
  FakeSystemUtils(const FakeSystemUtils&) = delete;
  FakeSystemUtils& operator=(const FakeSystemUtils&) = delete;

  ~FakeSystemUtils() override {}

  time_t time(time_t* t) override {
    if (t)
      *t = time_;
    return time_;
  }

  void forward_time(time_t offset) { time_ += offset; }

 private:
  // Current time.
  time_t time_;
};

}  // namespace

class DeviceIdentifierGeneratorTest : public ::testing::Test {
 public:
  DeviceIdentifierGeneratorTest()
      : generator_(&system_utils_, &metrics_),
        state_keys_received_(false),
        last_state_key_generation_status_(
            LoginMetrics::DEPRECATED_STATE_KEY_STATUS_MISSING_IDENTIFIERS) {
    EXPECT_CALL(metrics_, SendStateKeyGenerationStatus(_))
        .WillRepeatedly(SaveArg<0>(&last_state_key_generation_status_));
  }
  DeviceIdentifierGeneratorTest(const DeviceIdentifierGeneratorTest&) = delete;
  DeviceIdentifierGeneratorTest& operator=(
      const DeviceIdentifierGeneratorTest&) = delete;

  ~DeviceIdentifierGeneratorTest() override {}

  // Installs mock data for the required parameters.
  void InitMachineInfo() {
    std::map<std::string, std::string> params;
    params["serial_number"] = "fake-machine-serial-number";
    params["root_disk_serial_number"] = "fake-disk-serial-number";
    params["stable_device_secret_DO_NOT_SHARE"] =
        "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    ASSERT_TRUE(generator_.InitMachineInfo(params));
  }

  void CompletionHandler(const std::vector<std::vector<uint8_t>>& state_keys) {
    state_keys_received_ = true;
    state_keys_ = state_keys;
  }

  void RequestStateKeys(bool expect_immediate_callback) {
    state_keys_received_ = false;
    state_keys_.clear();
    generator_.RequestStateKeys(
        base::BindOnce(&DeviceIdentifierGeneratorTest::CompletionHandler,
                       base::Unretained(this)));
    EXPECT_EQ(expect_immediate_callback, state_keys_received_);
  }

  void CompletionPsmDeviceKeyHandler(const std::string& derived_secret) {
    psm_device_secret_received_ = true;
    psm_derived_secret_ = derived_secret;
  }

  void RequestPsmDeviceActiveSecret(bool expect_immediate_callback) {
    psm_device_secret_received_ = false;
    generator_.RequestPsmDeviceActiveSecret(base::BindOnce(
        &DeviceIdentifierGeneratorTest::CompletionPsmDeviceKeyHandler,
        base::Unretained(this)));
    EXPECT_EQ(expect_immediate_callback, psm_device_secret_received_);
  }

  FakeSystemUtils system_utils_;
  MockMetrics metrics_;

  DeviceIdentifierGenerator generator_;

  bool state_keys_received_;
  std::vector<std::vector<uint8_t>> state_keys_;

  bool psm_device_secret_received_;
  std::string psm_derived_secret_;

  LoginMetrics::StateKeyGenerationStatus last_state_key_generation_status_;
};

TEST_F(DeviceIdentifierGeneratorTest, RequestStateKeys) {
  InitMachineInfo();
  RequestStateKeys(true);
  EXPECT_EQ(LoginMetrics::STATE_KEY_STATUS_GENERATION_METHOD_HMAC_DEVICE_SECRET,
            last_state_key_generation_status_);
  ASSERT_EQ(DeviceIdentifierGenerator::kDeviceStateKeyFutureQuanta,
            state_keys_.size());
}

TEST_F(DeviceIdentifierGeneratorTest,
       RequestPsmDeviceActiveSecretSuccessAfterInitMachineInfo) {
  InitMachineInfo();
  RequestPsmDeviceActiveSecret(true);
  EXPECT_TRUE(psm_device_secret_received_);
}

TEST_F(DeviceIdentifierGeneratorTest,
       RequestPsmDeviceActiveSecretSuccessBeforeInitMachineInfo) {
  // No callback as long as machine info has not been provided.
  RequestPsmDeviceActiveSecret(false);
  InitMachineInfo();
  EXPECT_TRUE(psm_device_secret_received_);

  // Sending machine info twice is harmless and doesn't fire callbacks.
  psm_device_secret_received_ = false;
  InitMachineInfo();
  EXPECT_FALSE(psm_device_secret_received_);
}

TEST_F(DeviceIdentifierGeneratorTest, RequestStateKeysLegacy) {
  std::map<std::string, std::string> params;
  params["serial_number"] = "fake-machine-serial-number";
  params["root_disk_serial_number"] = "fake-disk-serial-number";
  ASSERT_TRUE(generator_.InitMachineInfo(params));
  RequestStateKeys(true);
  EXPECT_EQ(LoginMetrics::STATE_KEY_STATUS_GENERATION_METHOD_IDENTIFIER_HASH,
            last_state_key_generation_status_);
  ASSERT_EQ(DeviceIdentifierGenerator::kDeviceStateKeyFutureQuanta,
            state_keys_.size());
}

TEST_F(DeviceIdentifierGeneratorTest, TimedStateKeys) {
  InitMachineInfo();
  system_utils_.forward_time(base::Days(100).InSeconds());

  // The correct number of state keys gets returned.
  RequestStateKeys(true);
  EXPECT_EQ(LoginMetrics::STATE_KEY_STATUS_GENERATION_METHOD_HMAC_DEVICE_SECRET,
            last_state_key_generation_status_);
  ASSERT_EQ(DeviceIdentifierGenerator::kDeviceStateKeyFutureQuanta,
            state_keys_.size());
  std::vector<std::vector<uint8_t>> initial_state_keys = state_keys_;

  // All state keys are different.
  std::set<std::vector<uint8_t>> state_key_set(state_keys_.begin(),
                                               state_keys_.end());
  EXPECT_EQ(DeviceIdentifierGenerator::kDeviceStateKeyFutureQuanta,
            state_key_set.size());

  // Moving forward just a little yields the same keys.
  system_utils_.forward_time(base::Days(1).InSeconds());
  RequestStateKeys(true);
  EXPECT_EQ(LoginMetrics::STATE_KEY_STATUS_GENERATION_METHOD_HMAC_DEVICE_SECRET,
            last_state_key_generation_status_);
  EXPECT_EQ(initial_state_keys, state_keys_);

  // Jumping to a future quantum results in the state keys rolling forward.
  int64_t step =
      1 << DeviceIdentifierGenerator::kDeviceStateKeyTimeQuantumPower;
  system_utils_.forward_time(2 * step);

  RequestStateKeys(true);
  EXPECT_EQ(LoginMetrics::STATE_KEY_STATUS_GENERATION_METHOD_HMAC_DEVICE_SECRET,
            last_state_key_generation_status_);
  ASSERT_EQ(DeviceIdentifierGenerator::kDeviceStateKeyFutureQuanta,
            state_keys_.size());
  EXPECT_TRUE(std::equal(initial_state_keys.begin() + 2,
                         initial_state_keys.end(), state_keys_.begin()));
}

TEST_F(DeviceIdentifierGeneratorTest, PendingMachineInfo) {
  // No callback as long as machine info has not been provided.
  RequestStateKeys(false);

  // Supplying machine info fires callbacks.
  InitMachineInfo();
  EXPECT_TRUE(state_keys_received_);
  EXPECT_EQ(DeviceIdentifierGenerator::kDeviceStateKeyFutureQuanta,
            state_keys_.size());

  // Sending machine info twice is harmless and doesn't fire callbacks.
  state_keys_received_ = false;
  InitMachineInfo();
  EXPECT_FALSE(state_keys_received_);
}

TEST_F(DeviceIdentifierGeneratorTest, PendingMachineInfoFailure) {
  // No callback as long as machine info has not been provided.
  RequestStateKeys(false);

  // Supplying machine info fires callbacks even if info is missing.
  std::map<std::string, std::string> empty;
  EXPECT_FALSE(generator_.InitMachineInfo(empty));
  EXPECT_TRUE(state_keys_received_);
  EXPECT_EQ(0, state_keys_.size());

  // Later requests get answered immediately.
  RequestStateKeys(true);
  EXPECT_EQ(LoginMetrics::STATE_KEY_STATUS_MISSING_ALL_IDENTIFIERS,
            last_state_key_generation_status_);
  EXPECT_EQ(0, state_keys_.size());
}

TEST_F(DeviceIdentifierGeneratorTest, MissingMachineSerialNumber) {
  std::map<std::string, std::string> params;
  params["root_disk_serial_number"] = "fake-disk-serial-number";
  ASSERT_FALSE(generator_.InitMachineInfo(params));

  RequestStateKeys(true);

  EXPECT_EQ(LoginMetrics::STATE_KEY_STATUS_MISSING_MACHINE_SERIAL_NUMBER,
            last_state_key_generation_status_);
  EXPECT_EQ(0, state_keys_.size());
}

TEST_F(DeviceIdentifierGeneratorTest, MissingDiskSerialNumber) {
  std::map<std::string, std::string> params;
  params["serial_number"] = "fake-machine-serial-number";
  ASSERT_FALSE(generator_.InitMachineInfo(params));

  RequestStateKeys(true);

  EXPECT_EQ(LoginMetrics::STATE_KEY_STATUS_MISSING_DISK_SERIAL_NUMBER,
            last_state_key_generation_status_);
  EXPECT_EQ(0, state_keys_.size());
}

TEST_F(DeviceIdentifierGeneratorTest, ParseMachineInfoSuccess) {
  std::map<std::string, std::string> params;
  EXPECT_TRUE(DeviceIdentifierGenerator::ParseMachineInfo(
      "\"serial_number\"=\"fake-machine-serial-number\"\n"
      "# This is a comment.\n"
      "\"root_disk_serial_number\"=\"fake disk-serial-number\"\n"
      "\"serial_number\"=\"key_collision\"\n"
      "\"stable_device_secret_DO_NOT_SHARE\"="
      "\"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff\"\n",
      &params));
  EXPECT_EQ(3, params.size());
  EXPECT_EQ("fake-machine-serial-number", params["serial_number"]);
  EXPECT_EQ("fake disk-serial-number", params["root_disk_serial_number"]);
}

TEST_F(DeviceIdentifierGeneratorTest, ParseMachineInfoFailure) {
  std::map<std::string, std::string> params;
  EXPECT_FALSE(DeviceIdentifierGenerator::ParseMachineInfo("bad!", &params));
}

}  // namespace login_manager
