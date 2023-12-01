// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <utility>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "runtime_probe/functions/ata_storage.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

constexpr auto kAtaType = "ATA";

class MockAtaStorageFunction : public AtaStorageFunction {
  using AtaStorageFunction::AtaStorageFunction;

 public:
  using AtaStorageFunction::ProbeFromStorageTool;
  using AtaStorageFunction::ProbeFromSysfs;
};

class AtaStorageFunctionTest : public BaseFunctionTest {
 protected:
  // Set up ATA-specific files for |storage_fields| under |device_path|/device.
  // For example:
  //   SetAtaStorage("/XXX/sda1", {{"vendor", "ATA"},
  //                                  {"model", "ABC"}});
  // The function will set "ATA" to file /XXX/sda1/device/vendor and
  // "ABC" to file /XXX/sda1/device/model.
  void SetAtaStorage(
      std::string device_path,
      std::vector<std::pair<std::string, std::string>> storage_fields) {
    for (auto& [field, value] : storage_fields) {
      SetFile({device_path, "device", field}, value);
    }
  }
};

TEST_F(AtaStorageFunctionTest, ProbeFromSysfs) {
  auto probe_function = CreateProbeFunction<MockAtaStorageFunction>();

  auto ata1_path = GetPathUnderRoot("/sys/class/block/sda1");

  SetAtaStorage("/sys/class/block/sda1",
                {{"vendor", kAtaType}, {"model", "ABC 123"}});

  auto result = probe_function->ProbeFromSysfs(ata1_path);
  auto ans = base::JSONReader::Read(R"JSON(
    {
      "ata_model": "ABC 123",
      "ata_vendor": "ATA",
      "type": "ATA"
    }
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(AtaStorageFunctionTest, ProbeFromSysfsEmptyNodePath) {
  auto probe_function = CreateProbeFunction<MockAtaStorageFunction>();

  base::FilePath empty_path;

  SetAtaStorage("/sys/class/block/sda1",
                {{"vendor", kAtaType}, {"model", "ABC 123"}});

  auto result = probe_function->ProbeFromSysfs(empty_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(AtaStorageFunctionTest, ProbeFromSysfsNotAtaVendor) {
  auto probe_function = CreateProbeFunction<MockAtaStorageFunction>();

  auto ata1_path = GetPathUnderRoot("/sys/class/block/sda1");

  // The vendor is "unknown".
  SetAtaStorage("/sys/class/block/sda1",
                {{"vendor", "unknown"}, {"model", "ABC 123"}});

  auto result = probe_function->ProbeFromSysfs(ata1_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(AtaStorageFunctionTest, ProbeFromSysfsNoRequiredFields) {
  auto probe_function = CreateProbeFunction<MockAtaStorageFunction>();

  auto ata1_path = GetPathUnderRoot("/sys/class/block/sda1");

  // No required field "model".
  SetAtaStorage("/sys/class/block/sda1", {{"vendor", kAtaType}});

  auto result = probe_function->ProbeFromSysfs(ata1_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(AtaStorageFunctionTest, ProbeFromStorageTool) {
  auto probe_function = CreateProbeFunction<MockAtaStorageFunction>();

  auto ata1_path = GetPathUnderRoot("/sys/class/block/sda1");

  auto result = probe_function->ProbeFromStorageTool(ata1_path);
  // TODO(b/134981078): Currently the storage fw version of ATA storages is
  // always empty.
  auto ans = base::JSONReader::Read(R"JSON(
    {}
  )JSON");
  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe
