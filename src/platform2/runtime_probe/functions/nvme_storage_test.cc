// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <utility>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "runtime_probe/functions/nvme_storage.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

constexpr auto kNvmeDevicePath = "device/device";
constexpr auto kNvmeDriverPath = "device/device/driver";

class MockNvmeStorageFunction : public NvmeStorageFunction {
  using NvmeStorageFunction::NvmeStorageFunction;

 public:
  using NvmeStorageFunction::ProbeFromStorageTool;
  using NvmeStorageFunction::ProbeFromSysfs;
};

class NvmeStorageFunctionTest : public BaseFunctionTest {
 protected:
  // Set up NVMe driver symbolic link and files for |storage_fields| under
  // |device_path|/device/device. For example:
  //   SetNvmeStorage("/XXX/nvme0n1", {{"vendor", "0x01"},
  //                                  {"device", "0x02"}});
  // The function will set "0x01" to file /XXX/nvme0n1/device/device/vendor and
  // "0x02" to file /XXX/nvme0n1/device/device/device, and a symbolic link at
  // /XXX/nvme0n1/device/device/driver pointing to /sys/bus/pci/drivers/nvme
  void SetNvmeStorage(
      std::string device_path,
      std::vector<std::pair<std::string, std::string>> storage_fields) {
    SetDirectory("/sys/bus/pci/drivers/nvme");
    SetSymbolicLink("/sys/bus/pci/drivers/nvme",
                    {device_path, kNvmeDriverPath});
    for (auto& [field, value] : storage_fields) {
      SetFile({device_path, kNvmeDevicePath, field}, value);
    }
  }
};

TEST_F(NvmeStorageFunctionTest, ProbeFromSysfs) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme1_path = GetPathUnderRoot("/sys/class/block/nvme0n1");

  SetNvmeStorage(
      "/sys/class/block/nvme0n1",
      {{"vendor", "0x01"}, {"device", "0x02"}, {"class", "0x000003"}});

  auto result = probe_function->ProbeFromSysfs(nvme1_path);
  auto ans = base::JSONReader::Read(R"JSON(
    {
      "pci_vendor": "0x01",
      "pci_device": "0x02",
      "pci_class": "0x000003",
      "type": "NVMe"
    }
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(NvmeStorageFunctionTest, ProbeFromSysfsNoDriverSymbolicLink) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme1_path = GetPathUnderRoot("/sys/class/block/nvme0n1");

  // No symbolic link to NVMe driver.
  SetFile({"/sys/class/block/nvme0n1", kNvmeDevicePath, "vendor"}, "0x01");
  SetFile({"/sys/class/block/nvme0n1", kNvmeDevicePath, "device"}, "0x02");
  SetFile({"/sys/class/block/nvme0n1", kNvmeDevicePath, "class"}, "0x000003");

  auto result = probe_function->ProbeFromSysfs(nvme1_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(NvmeStorageFunctionTest, ProbeFromSysfsNotNvmeDriver) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme1_path = GetPathUnderRoot("/sys/class/block/nvme0n1");

  // The driver name is not nvme.
  SetDirectory("/sys/bus/pci/drivers/unknown");
  SetSymbolicLink("/sys/bus/pci/drivers/unknown",
                  {"/sys/class/block/nvme0n1", kNvmeDriverPath});
  SetFile({"/sys/class/block/nvme0n1", kNvmeDevicePath, "vendor"}, "0x01");
  SetFile({"/sys/class/block/nvme0n1", kNvmeDevicePath, "device"}, "0x02");
  SetFile({"/sys/class/block/nvme0n1", kNvmeDevicePath, "class"}, "0x000003");

  auto result = probe_function->ProbeFromSysfs(nvme1_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(NvmeStorageFunctionTest, ProbeFromSysfsNoRequiredFields) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme1_path = GetPathUnderRoot("/sys/class/block/nvme0n1");

  // No required field "class".
  SetNvmeStorage("/sys/class/block/nvme0n1",
                 {{"vendor", "0x01"}, {"device", "0x02"}});

  auto result = probe_function->ProbeFromSysfs(nvme1_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(NvmeStorageFunctionTest, ProbeFromStorageTool) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme2_path = GetPathUnderRoot("/sys/class/block/nvme0n2");

  std::string nvme_list = R"JSON(
    {
      "Devices": [
        {
          "DevicePath": "/dev/nvme0n1",
          "Firmware": "12345",
          "ModelNumber": "AAA NVMe 256GB"
        },
        {
          "DevicePath": "/dev/nvme0n2",
          "Firmware": "67890",
          "ModelNumber": "BBB NVMe 256GB"
        }
      ]
    }
  )JSON";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, Nvme("list", _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(nvme_list), Return(true)));

  auto result = probe_function->ProbeFromStorageTool(nvme2_path);
  // Only contain results with the same device path.
  auto ans = base::JSONReader::Read(R"JSON(
    {
      "storage_fw_version": "67890",
      "nvme_model": "BBB NVMe 256GB"
    }
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(NvmeStorageFunctionTest, ProbeFromStorageToolNoFwVersion) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme1_path = GetPathUnderRoot("/sys/class/block/nvme0n1");

  std::string nvme_list = R"JSON(
    {
      "Devices": [
        {
          "DevicePath": "/dev/nvme0n1",
          "ModelNumber": "AAA NVMe 256GB"
        }
      ]
    }
  )JSON";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, Nvme("list", _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(nvme_list), Return(true)));

  auto result = probe_function->ProbeFromStorageTool(nvme1_path);
  // Should not contain field "storage_fw_version"
  auto ans = base::JSONReader::Read(R"JSON(
    {
      "nvme_model": "AAA NVMe 256GB"
    }
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(NvmeStorageFunctionTest, ProbeFromStorageToolNoModelNumber) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme1_path = GetPathUnderRoot("/sys/class/block/nvme0n1");

  std::string nvme_list = R"JSON(
    {
      "Devices": [
        {
          "DevicePath": "/dev/nvme0n1",
          "Firmware": "12345"
        }
      ]
    }
  )JSON";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, Nvme("list", _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(nvme_list), Return(true)));

  auto result = probe_function->ProbeFromStorageTool(nvme1_path);
  // Should not contain field "nvme_model"
  auto ans = base::JSONReader::Read(R"JSON(
    {
      "storage_fw_version": "12345"
    }
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(NvmeStorageFunctionTest, ProbeFromStorageToolDBusCallFailed) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme1_path = GetPathUnderRoot("/sys/class/block/nvme0n1");

  auto debugd = mock_context()->mock_debugd_proxy();
  // D-Bus call to debugd failed.
  EXPECT_CALL(*debugd, Nvme("list", _, _, _)).WillRepeatedly(Return(false));

  auto result = probe_function->ProbeFromStorageTool(nvme1_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(NvmeStorageFunctionTest, ProbeFromStorageToolParseDebugdOutputFailed) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme1_path = GetPathUnderRoot("/sys/class/block/nvme0n1");

  // The output should be json format.
  std::string nvme_list = "invalid format";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, Nvme("list", _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(nvme_list), Return(true)));

  auto result = probe_function->ProbeFromStorageTool(nvme1_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(NvmeStorageFunctionTest, ProbeFromStorageToolInvalidDebugdOutput) {
  auto probe_function = CreateProbeFunction<MockNvmeStorageFunction>();

  auto nvme1_path = GetPathUnderRoot("/sys/class/block/nvme0n1");

  // No required field "Devices".
  std::string nvme_list = R"JSON(
    {}
  )JSON";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, Nvme("list", _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(nvme_list), Return(true)));

  auto result = probe_function->ProbeFromStorageTool(nvme1_path);
  EXPECT_EQ(result, std::nullopt);
}

}  // namespace
}  // namespace runtime_probe
