// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/vek_cert.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/mock_virtual_endorsement.h"

namespace vtpm {

namespace {

using ::testing::Return;
using ::testing::StrictMock;

constexpr char kFakeEkCert[] = "fake ek cert";

}  // namespace

// A placeholder test fixture.
class VekCertTest : public testing::Test {
 protected:
  StrictMock<MockVirtualEndorsement> mock_endorsement_;
  VekCert vek_cert_{&mock_endorsement_};
};

namespace {

TEST_F(VekCertTest, Success) {
  EXPECT_CALL(mock_endorsement_, Create())
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(mock_endorsement_, GetEndorsementCertificate())
      .WillOnce(Return(kFakeEkCert));
  std::string blob_out;
  EXPECT_EQ(vek_cert_.Get(blob_out), trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(blob_out, kFakeEkCert);
}

TEST_F(VekCertTest, Failure) {
  EXPECT_CALL(mock_endorsement_, Create())
      .WillOnce(Return(trunks::TPM_RC_FAILURE));
  std::string blob_out;
  EXPECT_EQ(vek_cert_.Get(blob_out), trunks::TPM_RC_FAILURE);
}

}  // namespace

}  // namespace vtpm
