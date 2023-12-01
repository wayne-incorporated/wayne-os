// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <tuple>
#include <unordered_set>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/location.h>
#include <base/test/task_environment.h>
#include <base/uuid.h>
#include <gtest/gtest.h>

#include "base/files/file_util.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/storage/storage.h"
#include "missive/storage/storage_configuration.h"
#include "missive/storage/storage_util.h"
#include "missive/util/status.h"

namespace reporting {

namespace {
class StorageDirectoryTest : public ::testing::Test {
 public:
  StorageDirectoryTest() = default;

 protected:
  void SetUp() override { ASSERT_TRUE(location_.CreateUniqueTempDir()); }

  base::test::TaskEnvironment task_environment_;
  base::ScopedTempDir location_;
};

TEST_F(StorageDirectoryTest, QueueDirectoriesAreFound) {
  auto storage_options = StorageOptions();
  storage_options.set_directory(location_.GetPath());
  const auto queue_options = storage_options.ProduceQueuesOptionsList();
  // New queues have a generation guid as an extension, e.g.
  // foo/bar/FastBatch.JsK32KLs
  const auto generation_guid =
      base::Uuid::GenerateRandomV4().AsLowercaseString();
  StorageDirectory::Set expected_queue_directories;
  for (const auto& [priority, options] : queue_options) {
    // Remove any existing extension first so that we are certain what the
    // extension is and then add a generation guid as the extension
    const auto queue_directory_filepath =
        options.directory().RemoveExtension().AddExtension(generation_guid);

    ASSERT_TRUE(base::CreateDirectory(queue_directory_filepath));
    expected_queue_directories.emplace(
        std::make_tuple(priority, generation_guid));
  }
  const auto kExpectedNumLegacyQueueDirectories = queue_options.size();
  const auto queue_directories =
      StorageDirectory::FindQueueDirectories(storage_options);

  EXPECT_EQ(queue_directories.size(), kExpectedNumLegacyQueueDirectories);
  EXPECT_EQ(queue_directories, expected_queue_directories);
}

TEST_F(StorageDirectoryTest, LegacyQueueDirectoriesAreFound) {
  auto storage_options = StorageOptions();
  storage_options.set_directory(location_.GetPath());
  const auto queue_options = storage_options.ProduceQueuesOptionsList();
  StorageDirectory::Set expected_queue_directories;
  for (const auto& [priority, options] : queue_options) {
    // Legacy queue directories do not have generation guid extensions, e.g.
    // foo/bar/Security as opposed to foo/bar/Security.XHf45KT
    const auto legacy_queue_filepath = options.directory().RemoveExtension();
    ASSERT_TRUE(base::CreateDirectory(legacy_queue_filepath));

    // Generation guid should be empty
    expected_queue_directories.emplace(
        std::make_tuple(priority, GenerationGuid()));
  }

  const auto kExpectedNumLegacyQueueDirectories = queue_options.size();
  const auto queue_directories =
      StorageDirectory::FindQueueDirectories(storage_options);

  EXPECT_EQ(queue_directories.size(), kExpectedNumLegacyQueueDirectories);
  EXPECT_EQ(queue_directories, expected_queue_directories);
}

TEST_F(StorageDirectoryTest, EmptyQueueDirectoriesAreDeleted) {
  ASSERT_TRUE(
      base::CreateDirectory(location_.GetPath().Append("EmptyDirectory")));
  EXPECT_TRUE(StorageDirectory::DeleteEmptySubdirectories(location_.GetPath()));
}
}  // namespace
}  // namespace reporting
