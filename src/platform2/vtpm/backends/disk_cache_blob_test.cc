// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/disk_cache_blob.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/database.pb.h"

namespace vtpm {

namespace {

// A fake path that the object under test reads/writes. `/tmp` is chosen for our
// testing.
// Technically it is not perfect to choose `/tmp` because it might not be
// no-disk, but most of operations that could make difference might not be
// detectable in unittet environment, still, and the cost could be worse
// flakiness or staled data on a host machine.
constexpr char kFakePath[] = "/tmp/fake_blob_file";
constexpr char kFakeBlob[] = "blob";
constexpr char kBadKeyData[] = "0806449 7533967";

}  // namespace

class DiskCacheBlobTest : public testing::Test {
 public:
  void SetUp() override { ASSERT_TRUE(base::DeleteFile(fake_path_)); }
  void TearDown() override { ASSERT_TRUE(base::DeleteFile(fake_path_)); }

 protected:
  const base::FilePath fake_path_{std::string{kFakePath}};
  DiskCacheBlob blob_{fake_path_};
};

namespace {

// Starting with no cache file, check if the read operation succeeds. Then,
// write a fake key before reading cached data back.
TEST_F(DiskCacheBlobTest, ClosedLoopTest) {
  std::string blob_out;
  EXPECT_EQ(blob_.Get(blob_out), trunks::TPM_RC_SUCCESS);
  EXPECT_TRUE(blob_out.empty());
  EXPECT_EQ(blob_.Write(kFakeBlob), trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(blob_.Get(blob_out), trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(blob_out, kFakeBlob);
}

// Parsing an incompatible serialized protobuf data should fail `Get()`.
TEST_F(DiskCacheBlobTest, FailureParseError) {
  // Make suse the data type is indeed incompatible.
  BlobData blob_data;
  ASSERT_FALSE(blob_data.ParseFromString(kBadKeyData));

  ASSERT_TRUE(
      base::ImportantFileWriter::WriteFileAtomically(fake_path_, kBadKeyData));

  std::string blob_out;
  EXPECT_NE(blob_.Get(blob_out), trunks::TPM_RC_SUCCESS);
}

}  // namespace

}  // namespace vtpm
