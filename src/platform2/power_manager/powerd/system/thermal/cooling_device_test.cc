// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/thermal/cooling_device.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/compiler_specific.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/file_utils.h>
#include <gtest/gtest.h>

#include "power_manager/common/test_main_loop_runner.h"
#include "power_manager/powerd/system/thermal/device_thermal_state.h"
#include "power_manager/powerd/system/thermal/thermal_device_observer.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

// Abort if expected thermal event hasn't been received after this much time.
constexpr base::TimeDelta kUpdateTimeout = base::Seconds(5);

// Frequency with which the cooling device is polled.
constexpr base::TimeDelta kPollInterval = base::Milliseconds(100);

// Simple ThermalDeviceObserver implementation that runs the event loop until
// it receives a thermal state change.
class TestObserver : public ThermalDeviceObserver {
 public:
  TestObserver() = default;
  TestObserver(const TestObserver&) = delete;
  TestObserver& operator=(const TestObserver&) = delete;

  ~TestObserver() override = default;

  // Runs |loop_| until OnThermalChanged() is called.
  bool RunUntilThermalChanged() {
    return loop_runner_.StartLoop(kUpdateTimeout);
  }

  void OnThermalChanged(ThermalDeviceInterface* sensor) override {
    loop_runner_.StopLoop();
  }

 private:
  TestMainLoopRunner loop_runner_;
};

}  // namespace

class CoolingDeviceTest : public TestEnvironment {
 public:
  CoolingDeviceTest() = default;
  CoolingDeviceTest(const CoolingDeviceTest&) = delete;
  CoolingDeviceTest& operator=(const CoolingDeviceTest&) = delete;

  ~CoolingDeviceTest() override = default;

  void SetUp() override {
    CHECK(temp_dir_.CreateUniqueTempDir());
    device_dir_ = temp_dir_.GetPath().Append("cooling_device1");
    CHECK(base::CreateDirectory(device_dir_));

    max_state_file_ = device_dir_.Append("max_state");
    cur_state_file_ = device_dir_.Append("cur_state");
    type_file_ = device_dir_.Append("type");

    WriteMaxState(100);
    WriteCurState(0);
    WriteType("Processor");

    cooling_device_ = std::make_unique<CoolingDevice>(device_dir_);
    cooling_device_->set_poll_interval_for_testing(kPollInterval);
    cooling_device_->AddObserver(&observer_);
  }

  void TearDown() override { cooling_device_->RemoveObserver(&observer_); }

 protected:
  // Helpers to simulate cooling device sysfs files.
  void WriteMaxState(int num) {
    std::string num_string = base::NumberToString(num);
    CHECK(brillo::WriteStringToFile(max_state_file_, num_string));
  }

  void WriteCurState(int num) {
    std::string num_string = base::NumberToString(num);
    CHECK(brillo::WriteStringToFile(cur_state_file_, num_string));
  }

  void WriteType(std::string type) {
    CHECK(brillo::WriteStringToFile(type_file_, type));
  }

  // Temporary directory mimicking a /sys/class/thermal directory.
  base::ScopedTempDir temp_dir_;
  base::FilePath device_dir_;

  // Files mocking actual cooling device sysfs files.
  base::FilePath max_state_file_;
  base::FilePath cur_state_file_;
  base::FilePath type_file_;

  TestObserver observer_;

  std::unique_ptr<CoolingDevice> cooling_device_;
};

TEST_F(CoolingDeviceTest, ProcessorScaling) {
  WriteType("Processor");
  WriteMaxState(100);
  cooling_device_->Init(false /* read_immedieatly */);

  std::pair<int, DeviceThermalState> test_data[] = {
      {0, DeviceThermalState::kNominal},  {10, DeviceThermalState::kFair},
      {50, DeviceThermalState::kSerious}, {80, DeviceThermalState::kCritical},
      {79, DeviceThermalState::kSerious}, {49, DeviceThermalState::kFair},
      {9, DeviceThermalState::kNominal}};

  for (const auto& p : test_data) {
    WriteCurState(p.first);
    ASSERT_TRUE(observer_.RunUntilThermalChanged());
    EXPECT_EQ(p.second, cooling_device_->GetThermalState());
  }
}

TEST_F(CoolingDeviceTest, FanScaling) {
  WriteType("TFN1");
  WriteMaxState(100);
  cooling_device_->Init(false /* read_immedieatly */);

  // No critical state for fan.
  std::pair<int, DeviceThermalState> test_data[] = {
      {0, DeviceThermalState::kNominal},
      {50, DeviceThermalState::kFair},
      {100, DeviceThermalState::kSerious},
      {99, DeviceThermalState::kFair},
      {49, DeviceThermalState::kNominal}};

  for (const auto& p : test_data) {
    WriteCurState(p.first);
    ASSERT_TRUE(observer_.RunUntilThermalChanged());
    EXPECT_EQ(p.second, cooling_device_->GetThermalState());
  }
}

TEST_F(CoolingDeviceTest, ChargerScaling) {
  WriteType("TCHG");
  WriteMaxState(100);
  cooling_device_->Init(false /* read_immedieatly */);

  // No critical state for charger.
  std::pair<int, DeviceThermalState> test_data[] = {
      {0, DeviceThermalState::kNominal},
      {70, DeviceThermalState::kFair},
      {100, DeviceThermalState::kSerious},
      {99, DeviceThermalState::kFair},
      {69, DeviceThermalState::kNominal}};

  for (const auto& p : test_data) {
    WriteCurState(p.first);
    ASSERT_TRUE(observer_.RunUntilThermalChanged());
    EXPECT_EQ(p.second, cooling_device_->GetThermalState());
  }
}

TEST_F(CoolingDeviceTest, OtherScaling) {
  WriteType("thermal-dev-freq");
  WriteMaxState(100);
  cooling_device_->Init(false /* read_immedieatly */);

  std::pair<int, DeviceThermalState> test_data[] = {
      {0, DeviceThermalState::kNominal},  {50, DeviceThermalState::kFair},
      {80, DeviceThermalState::kSerious}, {100, DeviceThermalState::kCritical},
      {99, DeviceThermalState::kSerious}, {79, DeviceThermalState::kFair},
      {49, DeviceThermalState::kNominal}};

  for (const auto& p : test_data) {
    WriteCurState(p.first);
    ASSERT_TRUE(observer_.RunUntilThermalChanged());
    EXPECT_EQ(p.second, cooling_device_->GetThermalState());
  }
}

TEST_F(CoolingDeviceTest, Rounding) {
  WriteType("Processor");
  WriteMaxState(3);
  cooling_device_->Init(false /* read_immedieatly */);

  std::pair<int, DeviceThermalState> test_data[] = {
      {0, DeviceThermalState::kNominal}, {1, DeviceThermalState::kFair},
      {2, DeviceThermalState::kSerious}, {3, DeviceThermalState::kCritical},
      {2, DeviceThermalState::kSerious}, {1, DeviceThermalState::kFair},
      {0, DeviceThermalState::kNominal}};

  for (const auto& p : test_data) {
    WriteCurState(p.first);
    ASSERT_TRUE(observer_.RunUntilThermalChanged());
    EXPECT_EQ(p.second, cooling_device_->GetThermalState());
  }
}

TEST_F(CoolingDeviceTest, ZeroMaxState) {
  WriteType("Processor");
  WriteMaxState(0);
  WriteCurState(0);
  cooling_device_->Init(true /* read_immedieatly */);
  EXPECT_FALSE(observer_.RunUntilThermalChanged());
  EXPECT_EQ(DeviceThermalState::kUnknown, cooling_device_->GetThermalState());
}

}  // namespace power_manager::system
