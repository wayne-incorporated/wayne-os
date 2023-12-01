// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <optional>
#include <utility>

#include <base/files/file_path.h>
#include <base/json/json_reader.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "runtime_probe/functions/mmc_storage.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

constexpr auto kDebugdMmcOption = "extcsd_read";
constexpr auto kMmcType = "MMC";
constexpr auto kMmcBlockPath = "/sys/class/block";

class MockMmcStorageFunction : public MmcStorageFunction {
  using MmcStorageFunction::MmcStorageFunction;

 public:
  using MmcStorageFunction::ProbeFromStorageTool;
  using MmcStorageFunction::ProbeFromSysfs;
};

class MmcStorageFunctionTest : public BaseFunctionTest {
 protected:
  // Set up files for |storage_fields| under |device_path|/device.
  // For example:
  //   SetMmcStorage("/sys/class/block/mmcblk1", {{"type", "MMC"},
  //                                              {"name", "AB1234"}});
  // The function will set "MMC" to file /sys/class/block/mmcblk1/device/type
  // and "AB1234" to file /sys/class/block/mmcblk1/device/name.
  void SetMmcStorage(
      const std::string& device_path,
      const std::vector<std::pair<std::string, std::string>>& storage_fields) {
    for (auto& [field, value] : storage_fields) {
      SetFile({device_path, "device", field}, value);
    }
  }
};

TEST_F(MmcStorageFunctionTest, ProbeFromSysfs) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  auto blk1_path = base::StringPrintf("%s/mmcblk1", kMmcBlockPath);
  SetMmcStorage(blk1_path, {{"type", kMmcType},
                            {"name", "AB1234"},
                            {"oemid", "0x0001"},
                            {"manfid", "0x000002"}});

  auto result = probe_function->ProbeFromSysfs(GetPathUnderRoot(blk1_path));
  auto ans = base::JSONReader::Read(R"JSON(
    {
      "mmc_name": "AB1234",
      "mmc_oemid": "0x0001",
      "mmc_manfid": "0x000002",
      "type": "MMC"
    }
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(MmcStorageFunctionTest, ProbeFromSysfsNonMmcStorage) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  auto blk1_path = base::StringPrintf("%s/mmcblk1", kMmcBlockPath);
  // The type of the storage is "unknown".
  SetMmcStorage(blk1_path, {{"type", "unknown"},
                            {"name", "AB1234"},
                            {"oemid", "0x0001"},
                            {"manfid", "0x000002"}});

  auto result = probe_function->ProbeFromSysfs(GetPathUnderRoot(blk1_path));
  // The result should be std::nullopt for non-mmc storages.
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(MmcStorageFunctionTest, ProbeFromSysfsNoTypeFile) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  auto blk1_path = base::StringPrintf("%s/mmcblk1", kMmcBlockPath);
  // No file for storage type.
  SetMmcStorage(
      blk1_path,
      {{"name", "AB1234"}, {"oemid", "0x0001"}, {"manfid", "0x000002"}});

  auto result = probe_function->ProbeFromSysfs(GetPathUnderRoot(blk1_path));
  // The result should be std::nullopt for storages without type.
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(MmcStorageFunctionTest, ProbeFromSysfsNoRequiredFields) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  auto blk1_path = base::StringPrintf("%s/mmcblk1", kMmcBlockPath);
  // No required field "name".
  SetMmcStorage(
      blk1_path,
      {{"type", kMmcType}, {"oemid", "0x0001"}, {"manfid", "0x000002"}});

  auto result = probe_function->ProbeFromSysfs(GetPathUnderRoot(blk1_path));
  // The result should be std::nullopt for storages without required fields.
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(MmcStorageFunctionTest, ProbeFromSysfsEmptyPath) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  base::FilePath empty_path;
  auto result = probe_function->ProbeFromSysfs(empty_path);
  // The result should be std::nullopt for empty paths.
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(MmcStorageFunctionTest, ProbeFromStorageToolWithAsciiStringFwVersion) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  auto blk1_path = base::StringPrintf("%s/mmcblk1", kMmcBlockPath);
  std::string mmc_extcsd_output = R"(Firmware version:
[FIRMWARE_VERSION[261]]: 0x48
[FIRMWARE_VERSION[260]]: 0x47
[FIRMWARE_VERSION[259]]: 0x46
[FIRMWARE_VERSION[258]]: 0x45
[FIRMWARE_VERSION[257]]: 0x44
[FIRMWARE_VERSION[256]]: 0x43
[FIRMWARE_VERSION[255]]: 0x42
[FIRMWARE_VERSION[254]]: 0x41)";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, Mmc(kDebugdMmcOption, _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(mmc_extcsd_output), Return(true)));

  auto result =
      probe_function->ProbeFromStorageTool(GetPathUnderRoot(blk1_path));
  auto ans = base::JSONReader::Read(R"JSON(
    {
      "storage_fw_version": "4142434445464748 (ABCDEFGH)"
    }
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(MmcStorageFunctionTest, ProbeFromStorageToolWithHexValueFwVersion) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  auto blk1_path = base::StringPrintf("%s/mmcblk1", kMmcBlockPath);
  std::string mmc_extcsd_output = R"(Firmware version:
[FIRMWARE_VERSION[261]]: 0x00
[FIRMWARE_VERSION[260]]: 0x00
[FIRMWARE_VERSION[259]]: 0x00
[FIRMWARE_VERSION[258]]: 0x00
[FIRMWARE_VERSION[257]]: 0x00
[FIRMWARE_VERSION[256]]: 0x00
[FIRMWARE_VERSION[255]]: 0x00
[FIRMWARE_VERSION[254]]: 0x03)";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, Mmc(kDebugdMmcOption, _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(mmc_extcsd_output), Return(true)));

  auto result =
      probe_function->ProbeFromStorageTool(GetPathUnderRoot(blk1_path));
  auto ans = base::JSONReader::Read(R"JSON(
    {
      "storage_fw_version": "0300000000000000 (3)"
    }
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(MmcStorageFunctionTest, ProbeFromStorageToolInvalidFwVersionHexValue) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  auto blk1_path = base::StringPrintf("%s/mmcblk1", kMmcBlockPath);
  // Invalid hex representation 0xZZ.
  std::string invalid_mmc_extcsd_output = R"(Firmware version:
[FIRMWARE_VERSION[261]]: 0xZZ
[FIRMWARE_VERSION[260]]: 0x00
[FIRMWARE_VERSION[259]]: 0x00
[FIRMWARE_VERSION[258]]: 0x00
[FIRMWARE_VERSION[257]]: 0x00
[FIRMWARE_VERSION[256]]: 0x00
[FIRMWARE_VERSION[255]]: 0x00
[FIRMWARE_VERSION[254]]: 0x03)";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, Mmc(kDebugdMmcOption, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(invalid_mmc_extcsd_output), Return(true)));

  auto result =
      probe_function->ProbeFromStorageTool(GetPathUnderRoot(blk1_path));
  // Failed to get the firmware version. Field storage_fw_version should not be
  // probed.
  auto ans = base::JSONReader::Read(R"JSON(
    {}
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(MmcStorageFunctionTest, ProbeFromStorageToolInvalidFwVersionByteCount) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  auto blk1_path = base::StringPrintf("%s/mmcblk1", kMmcBlockPath);
  // The output for firmware version should be 8 bytes, but got only 1 byte.
  std::string invalid_mmc_extcsd_output = R"(Firmware version:
[FIRMWARE_VERSION[261]]: 0x03)";
  auto debugd = mock_context()->mock_debugd_proxy();
  EXPECT_CALL(*debugd, Mmc(kDebugdMmcOption, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(invalid_mmc_extcsd_output), Return(true)));

  auto result =
      probe_function->ProbeFromStorageTool(GetPathUnderRoot(blk1_path));
  // Failed to get the firmware version. Field storage_fw_version should not be
  // probed.
  auto ans = base::JSONReader::Read(R"JSON(
    {}
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(MmcStorageFunctionTest, ProbeFromStorageToolDBusCallFailed) {
  auto probe_function = CreateProbeFunction<MockMmcStorageFunction>();

  auto blk1_path = base::StringPrintf("%s/mmcblk1", kMmcBlockPath);
  auto debugd = mock_context()->mock_debugd_proxy();
  // D-Bus call to debugd failed.
  EXPECT_CALL(*debugd, Mmc(kDebugdMmcOption, _, _, _))
      .WillRepeatedly(Return(false));

  auto result =
      probe_function->ProbeFromStorageTool(GetPathUnderRoot(blk1_path));
  // Failed to get the firmware version. Field storage_fw_version should not be
  // probed.
  auto ans = base::JSONReader::Read(R"JSON(
    {}
  )JSON");
  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe
