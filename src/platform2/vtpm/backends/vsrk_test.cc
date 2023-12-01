// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/vsrk.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/mock_tpm_utility.h>
#include <trunks/tpm_generated.h>
#include <trunks/trunks_factory_for_test.h>

namespace vtpm {

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

constexpr char kFakeBlob[] = "blob";

}  // namespace

class VsrkTest : public testing::Test {
 public:
  void SetUp() override { factory_.set_tpm_utility(&mock_tpm_utility_); }

 protected:
  StrictMock<trunks::MockTpmUtility> mock_tpm_utility_;
  trunks::TrunksFactoryForTest factory_;
  Vsrk vsrk_{&factory_};
};

namespace {

TEST_F(VsrkTest, Success) {
  EXPECT_CALL(mock_tpm_utility_,
              CreateRestrictedECCKeyPair(trunks::TpmUtility::kDecryptKey, _, _,
                                         _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<7>(kFakeBlob), Return(trunks::TPM_RC_SUCCESS)));
  std::string blob_out;
  EXPECT_EQ(vsrk_.Get(blob_out), trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(blob_out, kFakeBlob);
}

TEST_F(VsrkTest, Failure) {
  EXPECT_CALL(mock_tpm_utility_,
              CreateRestrictedECCKeyPair(trunks::TpmUtility::kDecryptKey, _, _,
                                         _, _, _, _, _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));
  std::string blob_out;
  EXPECT_EQ(vsrk_.Get(blob_out), trunks::TPM_RC_FAILURE);
}

}  // namespace

}  // namespace vtpm
