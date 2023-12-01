// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/flatbuffer_file.h"

#include <optional>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/mock_platform.h"

namespace cryptohome {
namespace {
using ::brillo::Blob;
using ::brillo::BlobFromString;
using ::brillo::BlobToString;
using ::testing::_;
using ::testing::Return;

constexpr char kBuffer[] = "Test-Buffer";

class FlatbufferFileTest : public ::testing::Test {
 protected:
  const ObfuscatedUsername kObfuscatedUsername{"foo@gmail.com"};
  const std::string kTestFile = "FlatbufferTestFile";

  MockPlatform platform_;
  FlatbufferFile flatbuffer_file_{
      &platform_, UserPath(kObfuscatedUsername).Append(kTestFile)};
};

TEST_F(FlatbufferFileTest, StoreAndLoad) {
  // Write to the test file first
  EXPECT_TRUE(
      flatbuffer_file_.StoreFile(BlobFromString(kBuffer), kUSSPersistTimer)
          .ok());
  EXPECT_TRUE(
      platform_.FileExists(UserPath(kObfuscatedUsername).Append(kTestFile)));

  // Load the File and check it matches the stored content.
  CryptohomeStatusOr<Blob> content_status =
      flatbuffer_file_.LoadFile(kUSSLoadPersistedTimer);
  ASSERT_TRUE(content_status.ok());
  EXPECT_EQ(BlobToString(content_status.value()), kBuffer);
}

// Test that if the file is not written properly, |StoreFile| returns false.
TEST_F(FlatbufferFileTest, StoreFailure) {
  EXPECT_CALL(platform_, WriteFileAtomicDurable(_, _, _))
      .WillRepeatedly(Return(false));
  EXPECT_FALSE(
      flatbuffer_file_.StoreFile(BlobFromString(kBuffer), kUSSPersistTimer)
          .ok());
}

// Test that the loading fails when the file doesn't exist.
TEST_F(FlatbufferFileTest, LoadFailureNonExisting) {
  EXPECT_FALSE(flatbuffer_file_.LoadFile(kUSSLoadPersistedTimer).ok());
}

}  // namespace

}  // namespace cryptohome
