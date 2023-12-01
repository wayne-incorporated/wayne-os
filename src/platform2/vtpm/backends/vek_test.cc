// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/vek.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/mock_virtual_endorsement.h"

namespace vtpm {

namespace {

using ::testing::Return;
using ::testing::StrictMock;

constexpr char kFakeEk[] = "fake ek";

}  // namespace

// A placeholder test fixture.
class VekTest : public testing::Test {
 protected:
  StrictMock<MockVirtualEndorsement> mock_endorsement_;
  Vek vek_{&mock_endorsement_};
};

namespace {

TEST_F(VekTest, Success) {
  EXPECT_CALL(mock_endorsement_, Create())
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(mock_endorsement_, GetEndorsementKey()).WillOnce(Return(kFakeEk));
  std::string blob_out;
  EXPECT_EQ(vek_.Get(blob_out), trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(blob_out, kFakeEk);
}

TEST_F(VekTest, Failure) {
  EXPECT_CALL(mock_endorsement_, Create())
      .WillOnce(Return(trunks::TPM_RC_FAILURE));
  std::string blob_out;
  EXPECT_EQ(vek_.Get(blob_out), trunks::TPM_RC_FAILURE);
}

}  // namespace

}  // namespace vtpm
