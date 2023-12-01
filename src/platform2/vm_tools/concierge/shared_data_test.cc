// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/shared_data.h"

#include <unordered_map>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"

namespace vm_tools {
namespace concierge {

TEST(SharedDataTest, TestValidOwnerId) {
  EXPECT_EQ(IsValidOwnerId("abdcefABCDEF0123456789"), true);
}

TEST(SharedDataTest, TestEmptyOwnerId) {
  EXPECT_EQ(IsValidOwnerId(""), false);
}

TEST(SharedDataTest, TestInvalidOwnerId) {
  EXPECT_EQ(IsValidOwnerId("Invalid"), false);
  EXPECT_EQ(IsValidOwnerId("abcd/../012345"), false);
}

TEST(SharedDataTest, TestValidVmName) {
  EXPECT_EQ(IsValidVmName("A Valid VM"), true);
}

TEST(SharedDataTest, TestEmptyVmName) {
  EXPECT_EQ(IsValidVmName(""), false);
}

// Check we get a failure while retrieving the pflash path for an invalid owner
// id.
TEST(SharedDataTest, TestGetPflashMetadataInvalidOwnerId) {
  base::ScopedTempDir temp_root_dir;
  EXPECT_TRUE(temp_root_dir.CreateUniqueTempDir());
  base::FilePath test_root_dir = temp_root_dir.GetPath();

  base::FilePath test_vm_resources_dir =
      test_root_dir.Append(kCrosvmDir).Append(kValidCryptoHomeCharacters);
  EXPECT_TRUE(CreateDirectory(test_vm_resources_dir));

  // Invalid owner id should yield failure."
  std::string invalid_owner_id =
      std::string(kValidCryptoHomeCharacters) + "/./";
  std::optional<PflashMetadata> pflash_metadata_result =
      GetPflashMetadata(invalid_owner_id, "123bru", test_root_dir);
  EXPECT_FALSE(pflash_metadata_result.has_value());
}

// Check the pflash path for a VM.
TEST(SharedDataTest, TestGetPflashMetadataSuccess) {
  base::ScopedTempDir temp_root_dir;
  EXPECT_TRUE(temp_root_dir.CreateUniqueTempDir());
  base::FilePath test_root_dir = temp_root_dir.GetPath();

  base::FilePath test_vm_resources_dir =
      test_root_dir.Append(kCrosvmDir).Append(kValidCryptoHomeCharacters);
  EXPECT_TRUE(CreateDirectory(test_vm_resources_dir));

  // Check the pflash path for a VM."
  std::unordered_map<std::string, std::string> vm_name_to_base64 = {
      {"bru", "YnJ1"}, {"foo", "Zm9v"}};
  for (const auto& kv : vm_name_to_base64) {
    std::optional<PflashMetadata> pflash_metadata_result =
        GetPflashMetadata(kValidCryptoHomeCharacters, kv.first, test_root_dir);
    EXPECT_TRUE(pflash_metadata_result.has_value());
    EXPECT_FALSE(pflash_metadata_result->is_installed);
    // The base64 value for the VM name "bru" is "YnJ1".
    EXPECT_EQ(pflash_metadata_result->path,
              test_vm_resources_dir.Append(kv.second +
                                           std::string(kPflashImageExtension)));
  }
}

}  // namespace concierge
}  // namespace vm_tools
