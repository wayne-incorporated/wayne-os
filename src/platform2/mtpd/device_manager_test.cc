// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mtpd/device_manager.h"

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <base/compiler_specific.h>
#include <base/test/task_environment.h>

#include "mtpd/device_event_delegate.h"

namespace mtpd {
namespace {

class DeviceManagerTest : public testing::Test {
 public:
  DeviceManagerTest() = default;
  DeviceManagerTest(const DeviceManagerTest&) = delete;
  DeviceManagerTest& operator=(const DeviceManagerTest&) = delete;

 private:
  // DeviceManager needs the current thread to have a task runner.
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
};

TEST_F(DeviceManagerTest, ParseStorageName) {
  struct ParseStorageNameTestCase {
    const char* input;
    bool expected_result;
    const char* expected_bus;
    uint32_t expected_storage_id;
  } test_cases[] = {
      {"usb:123:4", true, "usb:123", 4},
      {"usb:1,2,3:4", true, "usb:1,2,3", 4},
      {"notusb:123:4", false, "", 0},
      {"usb:123:4:badfield", false, "", 0},
      {"usb:123:not_number", false, "", 0},
  };

  for (const auto& test_case : test_cases) {
    std::string bus;
    uint32_t storage_id = static_cast<uint32_t>(-1);
    bool result =
        DeviceManager::ParseStorageName(test_case.input, &bus, &storage_id);
    EXPECT_EQ(test_case.expected_result, result);
    if (test_case.expected_result) {
      EXPECT_EQ(test_case.expected_bus, bus);
      EXPECT_EQ(test_case.expected_storage_id, storage_id);
    }
  }
}

class TestDeviceEventDelegate : public DeviceEventDelegate {
 public:
  TestDeviceEventDelegate() {}
  TestDeviceEventDelegate(const TestDeviceEventDelegate&) = delete;
  TestDeviceEventDelegate& operator=(const TestDeviceEventDelegate&) = delete;

  ~TestDeviceEventDelegate() {}

  // DeviceEventDelegate implementation.
  void StorageAttached(const std::string& storage_name) override {}
  void StorageDetached(const std::string& storage_name) override {}
};

class TestDeviceManager : public DeviceManager {
 public:
  explicit TestDeviceManager(DeviceEventDelegate* delegate)
      : DeviceManager(delegate) {}
  TestDeviceManager(const TestDeviceManager&) = delete;
  TestDeviceManager& operator=(const TestDeviceManager&) = delete;

  ~TestDeviceManager() {}

  bool AddStorage(const std::string& storage_name,
                  const StorageInfo& storage_info) {
    return AddStorageForTest(storage_name, storage_info);
  }
};

// Devices do not actually have a root node, so one is synthesized.
TEST_F(DeviceManagerTest, GetFileInfoForSynthesizedRootNode) {
  const std::string kDummyStorageName = "usb:1,2:65432";
  StorageInfo dummy_storage_info;
  TestDeviceEventDelegate dummy_device_event_delegate;
  TestDeviceManager device_manager(&dummy_device_event_delegate);
  bool ret = device_manager.AddStorage(kDummyStorageName, dummy_storage_info);
  EXPECT_TRUE(ret);

  std::vector<FileEntry> file_entries;
  std::vector<uint32_t> file_ids;
  file_ids.push_back(0);
  ret = device_manager.GetFileInfo(kDummyStorageName, file_ids, &file_entries);
  EXPECT_TRUE(ret);
  ASSERT_EQ(1U, file_entries.size());
  const FileEntry& file_entry = file_entries[0];

  EXPECT_EQ(0, file_entry.item_id());
  EXPECT_EQ(0, file_entry.parent_id());
  EXPECT_EQ("/", file_entry.file_name());
  EXPECT_EQ(0, file_entry.file_size());
  EXPECT_EQ(0, file_entry.modification_time());
  EXPECT_EQ(LIBMTP_FILETYPE_FOLDER, file_entry.file_type());
}

// Devices do not actually have a root node, and it is not possible to read
// from the synthesized one.
TEST_F(DeviceManagerTest, ReadFileFromSynthesizedRootNodeFails) {
  const std::string kDummyStorageName = "usb:1,2:65432";
  StorageInfo dummy_storage_info;
  TestDeviceEventDelegate dummy_device_event_delegate;
  TestDeviceManager device_manager(&dummy_device_event_delegate);
  bool ret = device_manager.AddStorage(kDummyStorageName, dummy_storage_info);
  EXPECT_TRUE(ret);

  std::vector<uint8_t> data;
  ret = device_manager.ReadFileChunk(kDummyStorageName, 0 /* node id */,
                                     0 /* offset */, 1 /* byte */, &data);
  EXPECT_FALSE(ret);
  EXPECT_TRUE(data.empty());
}

}  // namespace
}  // namespace mtpd
