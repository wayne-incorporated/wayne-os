// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/common/gsc_nvram_quoter.h"

#include <string>
#include <vector>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/tpm_utility.h>
extern "C" {
#include <trunks/cr50_headers/virtual_nvmem.h>
}

#include "attestation/common/mock_tpm_utility.h"

namespace attestation {

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

constexpr uint16_t kFakeNvSize = 123;
constexpr char kFakeSigningKey[] = "signing key";
constexpr char kFakeQuote[] = "quote";
constexpr char kFakeQuotedData[] = "quoted data";

class GscNvramQuoterTest : public ::testing::Test {
 public:
  GscNvramQuoterTest() = default;
  ~GscNvramQuoterTest() override = default;

 protected:
  MockTpmUtility mock_tpm_utility_;
  StrictMock<GscNvramQuoter> quoter_{mock_tpm_utility_};
};

TEST_F(GscNvramQuoterTest, GetListForIdentity) {
  EXPECT_THAT(quoter_.GetListForIdentity(), ElementsAre(BOARD_ID, SN_BITS));
}

TEST_F(GscNvramQuoterTest, GetListForVtpmEkCertificate) {
  EXPECT_THAT(quoter_.GetListForVtpmEkCertificate(), ElementsAre(SN_BITS));
}

TEST_F(GscNvramQuoterTest, GetListForEnrollmentCertificate) {
  EXPECT_THAT(quoter_.GetListForEnrollmentCertificate(),
              ElementsAre(BOARD_ID, SN_BITS, RSU_DEVICE_ID));
}

TEST_F(GscNvramQuoterTest, CertifySuccessBoardId) {
  EXPECT_CALL(mock_tpm_utility_, GetNVDataSize(VIRTUAL_NV_INDEX_BOARD_ID, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeNvSize), Return(true)));
  EXPECT_CALL(mock_tpm_utility_, CertifyNV(VIRTUAL_NV_INDEX_BOARD_ID,
                                           kFakeNvSize, kFakeSigningKey, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeQuotedData),
                      SetArgPointee<4>(kFakeQuote), Return(true)));
  Quote quote;
  EXPECT_TRUE(quoter_.Certify(BOARD_ID, kFakeSigningKey, quote));
  EXPECT_EQ(quote.quote(), kFakeQuote);
  EXPECT_EQ(quote.quoted_data(), kFakeQuotedData);
}

TEST_F(GscNvramQuoterTest, CertifySuccessSnBits) {
  EXPECT_CALL(mock_tpm_utility_, GetNVDataSize(VIRTUAL_NV_INDEX_SN_DATA, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeNvSize), Return(true)));
  EXPECT_CALL(mock_tpm_utility_, CertifyNV(VIRTUAL_NV_INDEX_SN_DATA,
                                           kFakeNvSize, kFakeSigningKey, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeQuotedData),
                      SetArgPointee<4>(kFakeQuote), Return(true)));
  Quote quote;
  EXPECT_TRUE(quoter_.Certify(SN_BITS, kFakeSigningKey, quote));
  EXPECT_EQ(quote.quote(), kFakeQuote);
  EXPECT_EQ(quote.quoted_data(), kFakeQuotedData);
}

TEST_F(GscNvramQuoterTest, CertifySuccessRsuDevceId) {
  EXPECT_CALL(mock_tpm_utility_, GetNVDataSize(VIRTUAL_NV_INDEX_RSU_DEV_ID, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeNvSize), Return(true)));
  EXPECT_CALL(mock_tpm_utility_, CertifyNV(VIRTUAL_NV_INDEX_RSU_DEV_ID,
                                           kFakeNvSize, kFakeSigningKey, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeQuotedData),
                      SetArgPointee<4>(kFakeQuote), Return(true)));
  Quote quote;
  EXPECT_TRUE(quoter_.Certify(RSU_DEVICE_ID, kFakeSigningKey, quote));
  EXPECT_EQ(quote.quote(), kFakeQuote);
  EXPECT_EQ(quote.quoted_data(), kFakeQuotedData);
}

TEST_F(GscNvramQuoterTest, CertifySuccessRsaEkCertificate) {
  EXPECT_CALL(mock_tpm_utility_,
              GetNVDataSize(trunks::kRsaEndorsementCertificateIndex, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeNvSize), Return(true)));
  EXPECT_CALL(mock_tpm_utility_,
              CertifyNV(trunks::kRsaEndorsementCertificateIndex, kFakeNvSize,
                        kFakeSigningKey, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeQuotedData),
                      SetArgPointee<4>(kFakeQuote), Return(true)));
  Quote quote;
  EXPECT_TRUE(quoter_.Certify(RSA_PUB_EK_CERT, kFakeSigningKey, quote));
  EXPECT_EQ(quote.quote(), kFakeQuote);
  EXPECT_EQ(quote.quoted_data(), kFakeQuotedData);
}

TEST_F(GscNvramQuoterTest, CertifyFailureCertifyNV) {
  EXPECT_CALL(mock_tpm_utility_, GetNVDataSize(VIRTUAL_NV_INDEX_SN_DATA, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeNvSize), Return(true)));
  EXPECT_CALL(mock_tpm_utility_, CertifyNV(VIRTUAL_NV_INDEX_SN_DATA,
                                           kFakeNvSize, kFakeSigningKey, _, _))
      .WillOnce(Return(false));
  Quote quote;
  EXPECT_FALSE(quoter_.Certify(SN_BITS, kFakeSigningKey, quote));
}

TEST_F(GscNvramQuoterTest, CertifyFailureGetNVDataSize) {
  EXPECT_CALL(mock_tpm_utility_, GetNVDataSize(VIRTUAL_NV_INDEX_SN_DATA, _))
      .WillOnce(Return(false));
  Quote quote;
  EXPECT_FALSE(quoter_.Certify(SN_BITS, kFakeSigningKey, quote));
}

}  // namespace

}  // namespace attestation
