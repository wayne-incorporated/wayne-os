// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <string>

#include <gtest/gtest.h>
#include <minigbm/minigbm_helpers.h>

#include "runtime_probe/functions/gpu.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

class MockGpuFunction : public GpuFunction {
  using GpuFunction::GpuFunction;

 public:
  int GbmDetectDeviceInfoPath(unsigned int detect_flags,
                              const char* dev_node,
                              ::GbmDeviceInfo* info) const override {
    info->dev_type_flags = fake_gbm_dev_type_flags_;
    return 0;
  }

  // The fake value of gbm device type flags.
  int fake_gbm_dev_type_flags_ = 0;
};

class GpuFunctionTest : public BaseFunctionTest {
 protected:
  void SetPciDevice(const std::string& pci_device_id,
                    const std::map<std::string, std::string> files) {
    SetSymbolicLink({"../../../devices/pci0000:00/0000:00:08.1", pci_device_id},
                    {"sys/bus/pci/devices", pci_device_id});
    for (const auto& file : files) {
      SetFile(
          {"sys/devices/pci0000:00/0000:00:08.1", pci_device_id, file.first},
          file.second);
    }
  }

  void SetPciDeviceDrm(const std::string& pci_device_id,
                       const std::string& drm_device_name) {
    // Set a fake file to create the drm device directory.
    SetDirectory({"sys/devices/pci0000:00/0000:00:08.1", pci_device_id, "drm",
                  drm_device_name});
  }
};

TEST_F(GpuFunctionTest, ProbeGpu) {
  auto probe_function = CreateProbeFunction<MockGpuFunction>();
  SetPciDevice("0000:04:00.0", {
                                   {"class", "0x030000"},
                                   {"vendor", "0x1234"},
                                   {"device", "0x5678"},
                                   {"subsystem_vendor", "0x90ab"},
                                   {"subsystem_device", "0xcdef"},
                               });
  // Class code 0x300001(ProgIf is 0x01) should be probed.
  SetPciDevice("0000:08:00.0", {
                                   {"class", "0x030001"},
                                   {"vendor", "0x1234"},
                                   {"device", "0x5678"},
                                   {"subsystem_vendor", "0x90ab"},
                                   {"subsystem_device", "0xcdef"},
                               });
  // Class code 0x030200 is for 3D controller.
  SetPciDevice("0000:09:00.0", {
                                   {"class", "0x030200"},
                                   {"vendor", "0x1234"},
                                   {"device", "0x5678"},
                                   {"subsystem_vendor", "0x90ab"},
                                   {"subsystem_device", "0xcdef"},
                               });

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "vendor": "0x1234",
        "device": "0x5678",
        "subsystem_vendor": "0x90ab",
        "subsystem_device": "0xcdef"
      },
      {
        "vendor": "0x1234",
        "device": "0x5678",
        "subsystem_vendor": "0x90ab",
        "subsystem_device": "0xcdef"
      },
      {
        "vendor": "0x1234",
        "device": "0x5678",
        "subsystem_vendor": "0x90ab",
        "subsystem_device": "0xcdef"
      }
    ]
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(GpuFunctionTest, NonGpu) {
  auto probe_function = CreateProbeFunction<MockGpuFunction>();
  // Non-display controller (class it not 0x30).
  SetPciDevice("0000:04:00.0", {
                                   {"class", "0x020000"},
                                   {"vendor", "0x1234"},
                                   {"device", "0x5678"},
                                   {"subsystem_vendor", "0x90ab"},
                                   {"subsystem_device", "0xcdef"},
                               });
  // Class code 0x038000(Subclass is 0x80) should not be probed.
  SetPciDevice("0000:08:00.0", {
                                   {"class", "0x038000"},
                                   {"vendor", "0x1234"},
                                   {"device", "0x5678"},
                                   {"subsystem_vendor", "0x90ab"},
                                   {"subsystem_device", "0xcdef"},
                               });

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(GpuFunctionTest, MissField) {
  auto probe_function = CreateProbeFunction<MockGpuFunction>();
  // Each of these miss one field so won't be probed.
  SetPciDevice("0000:04:00.0", {
                                   {"class", "0x030000"},
                                   {"device", "0x5678"},
                                   {"subsystem_vendor", "0x90ab"},
                                   {"subsystem_device", "0xcdef"},
                               });
  SetPciDevice("0000:04:00.1", {
                                   {"class", "0x030000"},
                                   {"vendor", "0x1234"},
                                   {"subsystem_vendor", "0x90ab"},
                                   {"subsystem_device", "0xcdef"},
                               });
  SetPciDevice("0000:04:00.2", {
                                   {"class", "0x030000"},
                                   {"vendor", "0x1234"},
                                   {"device", "0x5678"},
                                   {"subsystem_device", "0xcdef"},
                               });
  SetPciDevice("0000:04:00.3", {
                                   {"class", "0x030000"},
                                   {"vendor", "0x1234"},
                                   {"device", "0x5678"},
                                   {"subsystem_vendor", "0x90ab"},
                               });

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(GpuFunctionTest, MinigbmIsDGPU) {
  auto probe_function = CreateProbeFunction<MockGpuFunction>();
  SetPciDevice("0000:04:00.0", {
                                   {"class", "0x030000"},
                                   {"vendor", "0x1234"},
                                   {"device", "0x5678"},
                                   {"subsystem_vendor", "0x90ab"},
                                   {"subsystem_device", "0xcdef"},
                               });
  SetPciDeviceDrm("0000:04:00.0", "renderD128");
  probe_function->fake_gbm_dev_type_flags_ = GBM_DEV_TYPE_FLAG_DISCRETE;

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "vendor": "0x1234",
        "device": "0x5678",
        "subsystem_vendor": "0x90ab",
        "subsystem_device": "0xcdef"
      }
    ]
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(GpuFunctionTest, MinigbmIsIGPU) {
  auto probe_function = CreateProbeFunction<MockGpuFunction>();
  SetPciDevice("0000:04:00.0", {
                                   {"class", "0x030000"},
                                   {"vendor", "0x1234"},
                                   {"device", "0x5678"},
                                   {"subsystem_vendor", "0x90ab"},
                                   {"subsystem_device", "0xcdef"},
                               });
  SetPciDeviceDrm("0000:04:00.0", "renderD128");
  probe_function->fake_gbm_dev_type_flags_ = 0;

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");
  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe
