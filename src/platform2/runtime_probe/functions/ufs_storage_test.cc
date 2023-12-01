// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <utility>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "runtime_probe/functions/ufs_storage.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

class MockUfsStorageFunction : public UfsStorageFunction {
  using UfsStorageFunction::UfsStorageFunction;

 public:
  using UfsStorageFunction::ProbeFromStorageTool;
  using UfsStorageFunction::ProbeFromSysfs;
};

class UfsStorageFunctionTest : public BaseFunctionTest {
 protected:
  // Set up ufs-bsg link at |device_abs_path|/../../ufs-bsg0 and UFS-specific
  // files for |storage_fields| under |device_path|/device. For example:
  //   SetUfsStorage("/XXX/sda1", {{"vendor", "ABC"},
  //                              {"model", "DEF"}});
  // The function will set "ABC" to file /XXX/sda1/device/vendor and
  // "DEF" to file /XXX/sda1/device/model.
  void SetUfsStorage(
      std::string device_path,
      std::string device_abs_path,
      std::vector<std::pair<std::string, std::string>> storage_fields) {
    SetDirectory(device_abs_path);
    SetSymbolicLink(device_abs_path, {device_path, "device"});
    SetDirectory({device_abs_path, "../../ufs-bsg0"});
    for (auto& [field, value] : storage_fields) {
      SetFile({device_path, "device", field}, value);
    }
  }
};

TEST_F(UfsStorageFunctionTest, ProbeFromSysfs) {
  auto probe_function = CreateProbeFunction<MockUfsStorageFunction>();

  auto ufs1_path = GetPathUnderRoot("/sys/class/block/sda1");

  SetUfsStorage("/sys/class/block/sda1", "/sys/devices/pci0/XXX/YYY/ZZZ",
                {{"vendor", "ABC"}, {"model", "XXX-256G"}});

  auto result = probe_function->ProbeFromSysfs(ufs1_path);
  auto ans = base::JSONReader::Read(R"JSON(
    {
      "type": "UFS",
      "ufs_model": "XXX-256G",
      "ufs_vendor": "ABC"
    }
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(UfsStorageFunctionTest, ProbeFromSysfsEmptyNodePath) {
  auto probe_function = CreateProbeFunction<MockUfsStorageFunction>();

  base::FilePath empty_path;

  SetUfsStorage("/sys/class/block/sda1", "/sys/devices/pci0/XXX/YYY/ZZZ",
                {{"vendor", "ABC"}, {"model", "XXX-256G"}});

  auto result = probe_function->ProbeFromSysfs(empty_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(UfsStorageFunctionTest, ProbeFromSysfsNoUfsBsg) {
  auto probe_function = CreateProbeFunction<MockUfsStorageFunction>();

  auto ufs1_path = GetPathUnderRoot("/sys/class/block/sda1");

  // Not set up ufs-bsg link.
  SetFile("/sys/class/block/sda1/device/vendor", "ABC");
  SetFile("/sys/class/block/sda1/device/model", "XXX-256G");

  auto result = probe_function->ProbeFromSysfs(ufs1_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(UfsStorageFunctionTest, ProbeFromSysfsNoRequiredFields) {
  auto probe_function = CreateProbeFunction<MockUfsStorageFunction>();

  auto ufs1_path = GetPathUnderRoot("/sys/class/block/sda1");

  // No required field "vendor".
  SetUfsStorage("/sys/class/block/sda1", "/sys/devices/pci0/XXX/YYY/ZZZ",
                {{"model", "XXX-256G"}});

  auto result = probe_function->ProbeFromSysfs(ufs1_path);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(UfsStorageFunctionTest, ProbeFromStorageTool) {
  auto probe_function = CreateProbeFunction<MockUfsStorageFunction>();

  auto ufs1_path = GetPathUnderRoot("/sys/class/block/sda1");

  auto result = probe_function->ProbeFromStorageTool(ufs1_path);
  // No-op for UFS storages currently.
  EXPECT_EQ(result, base::Value{base::Value::Type::DICT});
}

}  // namespace
}  // namespace runtime_probe
