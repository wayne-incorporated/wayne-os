// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "runtime_probe/functions/generic_battery.h"
#include "runtime_probe/probe_function.h"
#include "runtime_probe/utils/file_test_utils.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

class GenericBatteryTest : public BaseFunctionTest {
 public:
  GenericBatteryTest() {
    SetFile(bat0_path.Append("manufacturer"), "123-ABC");
    SetFile(bat0_path.Append("model_name"), "XYZ-00000");
    SetFile(bat0_path.Append("technology"), "Li-poly");
    SetFile(bat0_path.Append("type"), "Battery");

    // Missing battery sysfs file.
    SetFile(bat1_path.Append("manufacturer"), "123-ABC");
    SetFile(bat1_path.Append("technology"), "Li-poly");
    SetFile(bat1_path.Append("type"), "Battery");

    // Mismatch battery type "USB".
    SetFile(charger_path.Append("manufacturer"), "123-ABC");
    SetFile(charger_path.Append("model_name"), "XYZ-12345");
    SetFile(charger_path.Append("technology"), "Li-poly");
    SetFile(charger_path.Append("type"), "USB");
  }

 protected:
  const base::FilePath bat0_path{"sys/class/power_supply/BAT0"};
  const base::FilePath bat1_path{"sys/class/power_supply/BAT1"};
  const base::FilePath charger_path{"sys/class/power_supply/CHARGER0"};
};

TEST_F(GenericBatteryTest, Succeed) {
  auto ans = CreateProbeResultFromJson(
      base::StringPrintf(R"JSON(
        [
          {
            "charge_full_design": "3920000",
            "chemistry": "LiP",
            "manufacturer": "123-ABCDEF",
            "model_name": "XYZ-00000-ABC",
            "path": "%s",
            "technology": "Li-poly",
            "type": "Battery"
          }
        ]
  )JSON",
                         GetPathUnderRoot(bat0_path).value().c_str()));

  auto debugd = mock_context()->mock_debugd_proxy();
  const std::vector<std::string> kEctoolBatteryOutputs = {
      "Battery 0 info:\n"
      "  OEM name:               123-ABCDEF\n"
      "  Model number:           XYZ-00000-ABC\n"
      "  Chemistry   :           LiP\n"
      "  Serial number:          00C4\n"
      "  Design capacity:        3920 mAh\n",
      // For EC not supporting EC_CMD_BATTERY_GET_STATIC.
      "Battery info:\n"
      "  OEM name:               123-ABCDEF\n"
      "  Model number:           XYZ-00000-ABC\n"
      "  Chemistry   :           LiP\n"
      "  Serial number:          00C4\n"
      "  Design capacity:        3920 mAh\n",
  };
  for (const auto& kEctoolBatteryOutput : kEctoolBatteryOutputs) {
    EXPECT_CALL(*debugd, BatteryFirmware("info", _, _, _))
        .WillOnce(DoAll(SetArgPointee<1>(kEctoolBatteryOutput), Return(true)));
    auto probe_function = CreateProbeFunction<GenericBattery>();
    auto result = probe_function->Eval();
    EXPECT_EQ(result, ans);
  }
}

TEST_F(GenericBatteryTest, CallEctoolFailed) {
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, BatteryFirmware("info", _, _, _))
      .WillOnce(DoAll(Return(false)));
  // "chemistry" and "charge_full_design" from EC will not be added, and
  // "manufacturer" and "model_name" will not be updated.
  auto ans = CreateProbeResultFromJson(
      base::StringPrintf(R"JSON(
    [
      {
        "manufacturer": "123-ABC",
        "model_name": "XYZ-00000",
        "path": "%s",
        "technology": "Li-poly",
        "type": "Battery"
      }
    ]
  )JSON",
                         GetPathUnderRoot(bat0_path).value().c_str()));

  auto probe_function = CreateProbeFunction<GenericBattery>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(GenericBatteryTest, ParseEctoolBatteryFailed) {
  constexpr auto kInvalidEctoolBattery = "Battery info:\n";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, BatteryFirmware("info", _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kInvalidEctoolBattery), Return(true)));

  auto ans = CreateProbeResultFromJson(
      base::StringPrintf(R"JSON(
    [
      {
        "manufacturer": "123-ABC",
        "model_name": "XYZ-00000",
        "path": "%s",
        "technology": "Li-poly",
        "type": "Battery"
      }
    ]
  )JSON",
                         GetPathUnderRoot(bat0_path).value().c_str()));

  auto probe_function = CreateProbeFunction<GenericBattery>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe
