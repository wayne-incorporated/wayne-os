// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/vek_cert_manager.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/fake_blob.h"

namespace vtpm {

namespace {

constexpr char kFakeCert[] = "fake cert";
constexpr trunks::TPM_NV_INDEX kFakeIndex = 0x00806449;

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrictMock;

}  // namespace

// A placeholder test fixture.
class VekCertManagerTest : public testing::Test {
 protected:
  FakeBlob mock_blob_{kFakeCert};
  VekCertManager manager_{kFakeIndex, &mock_blob_};
};

namespace {

TEST_F(VekCertManagerTest, ReadSuccess) {
  EXPECT_CALL(mock_blob_, Get(_))
      .WillOnce(
          DoAll(SetArgReferee<0>(kFakeCert), Return(trunks::TPM_RC_SUCCESS)));
  std::string data_out;
  EXPECT_EQ(manager_.Read(kFakeIndex, /*password=*/"", data_out),
            trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(data_out, kFakeCert);
}

TEST_F(VekCertManagerTest, FailureReadError) {
  EXPECT_CALL(mock_blob_, Get(_))
      .WillOnce(
          DoAll(SetArgReferee<0>(kFakeCert), Return(trunks::TPM_RC_FAILURE)));
  std::string data_out;
  EXPECT_EQ(manager_.Read(kFakeIndex, /*password=*/"", data_out),
            trunks::TPM_RC_FAILURE);
}

TEST_F(VekCertManagerTest, FailureNonEmptyAuthNotSupported) {
  std::string data_out;
  EXPECT_EQ(manager_.Read(kFakeIndex, "non empty password", data_out),
            trunks::TPM_RC_BAD_AUTH);
}

TEST_F(VekCertManagerTest, FailureWrongIndex) {
  std::string data_out;
  EXPECT_EQ(manager_.Read(kFakeIndex + 1, /*password=*/"", data_out),
            trunks::TPM_RC_NV_SPACE);
}

TEST_F(VekCertManagerTest, GetDataSizeSuccess) {
  EXPECT_CALL(mock_blob_, Get(_))
      .WillOnce(
          DoAll(SetArgReferee<0>(kFakeCert), Return(trunks::TPM_RC_SUCCESS)));
  trunks::UINT16 data_size = 0;
  EXPECT_EQ(manager_.GetDataSize(kFakeIndex, data_size),
            trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(data_size, std::string(kFakeCert).size());
}

TEST_F(VekCertManagerTest, GetDataSizeFailureWrongIndex) {
  trunks::UINT16 data_size = 0;
  EXPECT_EQ(manager_.GetDataSize(kFakeIndex + 1, data_size),
            trunks::TPM_RC_NV_SPACE);
}

TEST_F(VekCertManagerTest, GetAttributesSuccess) {
  trunks::TPMA_NV attributes = 0;
  EXPECT_EQ(manager_.GetAttributes(kFakeIndex, attributes),
            trunks::TPM_RC_SUCCESS);
  EXPECT_NE(attributes, 0);
}

TEST_F(VekCertManagerTest, GetAttributesFailureWrongIndex) {
  trunks::TPMA_NV attributes = 0;
  EXPECT_EQ(manager_.GetAttributes(kFakeIndex + 1, attributes),
            trunks::TPM_RC_NV_SPACE);
}

TEST_F(VekCertManagerTest, GetNameAlgorithmSuccess) {
  trunks::TPMI_ALG_HASH name_algorithm = 0;
  EXPECT_EQ(manager_.GetNameAlgorithm(kFakeIndex, name_algorithm),
            trunks::TPM_RC_SUCCESS);
  EXPECT_EQ(name_algorithm, trunks::TPM_ALG_SHA256);
}

TEST_F(VekCertManagerTest, GetNameAlgorithmFailureWrongIndex) {
  trunks::TPMI_ALG_HASH name_algorithm = 0;
  EXPECT_EQ(manager_.GetNameAlgorithm(kFakeIndex + 1, name_algorithm),
            trunks::TPM_RC_NV_SPACE);
}

TEST_F(VekCertManagerTest, ListHandles) {
  std::vector<trunks::TPM_HANDLE> handles;
  EXPECT_EQ(manager_.ListHandles(handles), trunks::TPM_RC_SUCCESS);
  EXPECT_THAT(handles, ElementsAre(kFakeIndex));
}

}  // namespace

}  // namespace vtpm
