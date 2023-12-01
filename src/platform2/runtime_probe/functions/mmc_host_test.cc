// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "runtime_probe/functions/mmc_host.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

using ::testing::EndsWith;
using ::testing::Eq;
using ::testing::Pointee;

constexpr char kSysClassMmcHostDir[] = "/sys/class/mmc_host";
constexpr char kFakeMmcName[] = "mmcX:1234";

class MmcHostFunctionTest : public BaseFunctionTest {
 protected:
  void SetUp() { probe_function_ = CreateProbeFunction<MmcHostFunction>(); }

  // Returns the string of the real path of the fake mmc host device.
  std::string SetMmcHost(const std::string& dev_name = "mmc0") {
    // Append |dev_name| to pci path to distinguish them. Real pci path won't
    // have that.
    const std::string bus_dev =
        "/sys/devices/pci0000:00/0000:00:08.1" + dev_name;
    const std::string bus_dev_relative_to_sys = "../../../";
    SetSymbolicLink(bus_dev, {kSysClassMmcHostDir, dev_name, "device"});
    // The symbolic link is for getting the bus type.
    SetSymbolicLink({bus_dev_relative_to_sys, "bus", "pci"},
                    {bus_dev, "subsystem"});
    SetFile({bus_dev, "device"}, "0x1111");
    SetFile({bus_dev, "vendor"}, "0x2222");

    return bus_dev + "/mmc_host/" + dev_name;
  }

  std::unique_ptr<ProbeFunction> probe_function_;
};

TEST_F(MmcHostFunctionTest, ProbeMmcHost) {
  SetMmcHost();

  auto result = probe_function_->Eval();
  EXPECT_EQ(result.size(), 1);
  EXPECT_TRUE(result[0].GetDict().FindString("path"));
  EXPECT_TRUE(result[0].GetDict().FindString("bus_type"));
}

TEST_F(MmcHostFunctionTest, NoMmcDeviceAttached) {
  SetMmcHost();

  auto result = probe_function_->Eval();
  EXPECT_EQ(result.size(), 1);
  EXPECT_THAT(result[0].GetDict().FindString("is_emmc_attached"),
              Pointee(Eq("0")));
}

TEST_F(MmcHostFunctionTest, EmmcDeviceAttached) {
  const std::string mmc_host_dev = SetMmcHost();
  SetSymbolicLink({mmc_host_dev, kFakeMmcName},
                  {"/sys/bus/mmc/devices", kFakeMmcName});
  SetFile({mmc_host_dev, kFakeMmcName, "type"}, "MMC");

  auto result = probe_function_->Eval();
  EXPECT_EQ(result.size(), 1);
  EXPECT_THAT(result[0].GetDict().FindString("is_emmc_attached"),
              Pointee(Eq("1")));
}

TEST_F(MmcHostFunctionTest, SDCardDeviceAttached) {
  const std::string mmc_host_dev = SetMmcHost();
  SetSymbolicLink({mmc_host_dev, kFakeMmcName},
                  {"/sys/bus/mmc/devices", kFakeMmcName});
  SetFile({mmc_host_dev, kFakeMmcName, "type"}, "SD");

  auto result = probe_function_->Eval();
  EXPECT_EQ(result.size(), 1);
  EXPECT_THAT(result[0].GetDict().FindString("is_emmc_attached"),
              Pointee(Eq("0")));
}

TEST_F(MmcHostFunctionTest, UnknownDeviceAttached) {
  const std::string mmc_host_dev = SetMmcHost();
  SetSymbolicLink({mmc_host_dev, kFakeMmcName},
                  {"/sys/bus/mmc/devices", kFakeMmcName});
  UnsetPath({mmc_host_dev, kFakeMmcName, "type"});

  auto result = probe_function_->Eval();
  EXPECT_EQ(result.size(), 1);
  EXPECT_THAT(result[0].GetDict().FindString("is_emmc_attached"),
              Pointee(Eq("0")));
}

base::Value::Dict MakeMmcHostArg(
    std::vector<std::pair<std::string, bool>> data) {
  return base::Value::Dict(std::make_move_iterator(data.begin()),
                           std::make_move_iterator(data.end()));
}

TEST_F(MmcHostFunctionTest, FilterIsEmmcAttached) {
  // mmc0 is emmc attached.
  const std::string mmc_host_dev = SetMmcHost("mmc0");
  SetSymbolicLink({mmc_host_dev, kFakeMmcName},
                  {"/sys/bus/mmc/devices", kFakeMmcName});
  SetFile({mmc_host_dev, kFakeMmcName, "type"}, "MMC");

  // mmc1 is not emmc attached.
  SetMmcHost("mmc1");

  // Probe all
  {
    probe_function_ = CreateProbeFunction<MmcHostFunction>();
    auto result = probe_function_->Eval();
    EXPECT_EQ(result.size(), 2);
  }

  // Probe is emmc attached
  {
    probe_function_ = CreateProbeFunction<MmcHostFunction>(
        MakeMmcHostArg({{"is_emmc_attached", true}}));
    auto result = probe_function_->Eval();
    EXPECT_EQ(result.size(), 1);
    EXPECT_THAT(result[0].GetDict().FindString("is_emmc_attached"),
                Pointee(Eq("1")));
    EXPECT_THAT(result[0].GetDict().FindString("path"),
                Pointee(EndsWith("mmc0")));
  }

  // Probe is not eemc attached
  {
    probe_function_ = CreateProbeFunction<MmcHostFunction>(
        MakeMmcHostArg({{"is_emmc_attached", false}}));
    auto result = probe_function_->Eval();
    EXPECT_EQ(result.size(), 1);
    EXPECT_THAT(result[0].GetDict().FindString("is_emmc_attached"),
                Pointee(Eq("0")));
    EXPECT_THAT(result[0].GetDict().FindString("path"),
                Pointee(EndsWith("mmc1")));
  }
}

}  // namespace
}  // namespace runtime_probe
