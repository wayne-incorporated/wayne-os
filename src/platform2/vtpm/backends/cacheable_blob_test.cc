// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/cacheable_blob.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/fake_blob.h"
#include "vtpm/backends/fake_writable_blob.h"

namespace vtpm {

namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;

constexpr char kFakeBlob[] = "blob";

}  // namespace

// A placeholder test fixture.
class CacheableBlobTest : public testing::Test {
 protected:
  StrictMock<FakeBlob> mock_key_{kFakeBlob};
  StrictMock<FakeWritableBlob> mock_cache_;
  CacheableBlob cacheable_key_{&mock_key_, &mock_cache_};
};

namespace {

TEST_F(CacheableBlobTest, Success) {
  EXPECT_CALL(mock_cache_, Get(_));
  EXPECT_CALL(mock_key_, Get(_));
  EXPECT_CALL(mock_cache_, Write(_));
  std::string blob;
  EXPECT_EQ(cacheable_key_.Get(blob), trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(blob, kFakeBlob);
  // `FakeWritableBlob::Write()` writes the fake data to its member.
  // Calling `Get()` again returns the cached data.
  EXPECT_CALL(mock_cache_, Get(_));
  blob.clear();
  EXPECT_EQ(cacheable_key_.Get(blob), trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(blob, kFakeBlob);
}

TEST_F(CacheableBlobTest, FailureWriteCache) {
  EXPECT_CALL(mock_cache_, Get(_));
  EXPECT_CALL(mock_key_, Get(_));
  EXPECT_CALL(mock_cache_, Write(_)).WillOnce(Return(trunks::TPM_RC_MEMORY));
  std::string blob;
  EXPECT_EQ(cacheable_key_.Get(blob), trunks::TPM_RC_MEMORY);
}

TEST_F(CacheableBlobTest, FailureGet) {
  EXPECT_CALL(mock_cache_, Get(_));
  EXPECT_CALL(mock_key_, Get(_)).WillOnce(Return(trunks::TPM_RC_MEMORY));
  std::string blob;
  EXPECT_EQ(cacheable_key_.Get(blob), trunks::TPM_RC_MEMORY);
}

TEST_F(CacheableBlobTest, FailureGetCache) {
  EXPECT_CALL(mock_cache_, Get(_)).WillOnce(Return(trunks::TPM_RC_MEMORY));
  std::string blob;
  EXPECT_EQ(cacheable_key_.Get(blob), trunks::TPM_RC_MEMORY);
}

}  // namespace

}  // namespace vtpm
