// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/mock_tpm.h"
#include "trunks/mock_tpm_state.h"
#include "trunks/tpm_cache_impl.h"
#include "trunks/tpm_generated.h"
#include "trunks/tpm_utility.h"
#include "trunks/trunks_factory_for_test.h"

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace trunks {

// A test fixture for TpmCache tests.
class TpmCacheTest : public testing::Test {
 public:
  TpmCacheTest() : tpm_cache_impl_(factory_) {
    factory_.set_tpm(&mock_tpm_);
    factory_.set_tpm_state(&mock_tpm_state_);
  }
  ~TpmCacheTest() override = default;

 protected:
  NiceMock<MockTpm> mock_tpm_;
  NiceMock<MockTpmState> mock_tpm_state_;
  TrunksFactoryForTest factory_;
  TpmCacheImpl tpm_cache_impl_;
};

TEST_F(TpmCacheTest, GetSaltingKeyPublicAreaSuccess) {
  TPMT_PUBLIC expected_pub_area;
  expected_pub_area.type = TPM_ALG_ECC;
  expected_pub_area.name_alg = TPM_ALG_SHA256;

  TPM2B_PUBLIC expected_pub_data;
  memset(&expected_pub_data, 0, sizeof(TPM2B_PUBLIC));
  expected_pub_data.public_area = expected_pub_area;
  expected_pub_data.size = sizeof(TPMT_PUBLIC);

  EXPECT_CALL(mock_tpm_, ReadPublicSync(kSaltingKey, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(expected_pub_data), Return(TPM_RC_SUCCESS)));

  // First query goes to the TPM.
  TPMT_PUBLIC actual_pub_area;
  EXPECT_EQ(tpm_cache_impl_.GetSaltingKeyPublicArea(&actual_pub_area),
            TPM_RC_SUCCESS);
  EXPECT_EQ(actual_pub_area.type, expected_pub_area.type);
  EXPECT_EQ(actual_pub_area.name_alg, expected_pub_area.name_alg);

  // Call again and see if it returns from cache directly.
  actual_pub_area.type = TPM_ALG_ERROR;
  actual_pub_area.name_alg = TPM_ALG_ERROR;
  EXPECT_EQ(tpm_cache_impl_.GetSaltingKeyPublicArea(&actual_pub_area),
            TPM_RC_SUCCESS);
  EXPECT_EQ(actual_pub_area.type, expected_pub_area.type);
  EXPECT_EQ(actual_pub_area.name_alg, expected_pub_area.name_alg);
}

TEST_F(TpmCacheTest, GetSaltingKeyPublicAreaEmptyResult) {
  TPM2B_PUBLIC empty_pub_data;
  empty_pub_data.size = 0;

  EXPECT_CALL(mock_tpm_, ReadPublicSync(kSaltingKey, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(empty_pub_data), Return(TPM_RC_SUCCESS)));

  TPMT_PUBLIC pub_area;
  EXPECT_EQ(tpm_cache_impl_.GetSaltingKeyPublicArea(&pub_area), TPM_RC_FAILURE);
}

TEST_F(TpmCacheTest, GetSaltingKeyPublicAreaBadInput) {
  EXPECT_CALL(mock_tpm_, ReadPublicSync(_, _, _, _, _, _)).Times(0);
  EXPECT_EQ(tpm_cache_impl_.GetSaltingKeyPublicArea(nullptr), TPM_RC_FAILURE);
}

TEST_F(TpmCacheTest, GetSaltingKeyPublicAreaTpmError) {
  EXPECT_CALL(mock_tpm_, ReadPublicSync(kSaltingKey, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  TPMT_PUBLIC pub_area;
  EXPECT_EQ(tpm_cache_impl_.GetSaltingKeyPublicArea(&pub_area), TPM_RC_FAILURE);
}

TEST_F(TpmCacheTest, GetBestSupportedKeyTypeEcc) {
  EXPECT_CALL(mock_tpm_state_, IsECCSupported()).WillOnce(Return(true));
  EXPECT_CALL(mock_tpm_state_, IsRSASupported()).Times(0);

  // Call twice. First call gets the info from TPM, and second call returns from
  // cache.
  EXPECT_EQ(tpm_cache_impl_.GetBestSupportedKeyType(), TPM_ALG_ECC);
  EXPECT_EQ(tpm_cache_impl_.GetBestSupportedKeyType(), TPM_ALG_ECC);
}

TEST_F(TpmCacheTest, GetBestSupportedKeyTypeRsa) {
  EXPECT_CALL(mock_tpm_state_, IsECCSupported()).WillOnce(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsRSASupported()).WillOnce(Return(true));
  EXPECT_EQ(tpm_cache_impl_.GetBestSupportedKeyType(), TPM_ALG_RSA);
}

TEST_F(TpmCacheTest, GetBestSupportedKeyTypeTpmError) {
  EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(tpm_cache_impl_.GetBestSupportedKeyType(), TPM_ALG_ERROR);
}

TEST_F(TpmCacheTest, GetBestSupportedKeyTypeNotFound) {
  EXPECT_CALL(mock_tpm_state_, IsECCSupported()).WillOnce(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsRSASupported()).WillOnce(Return(false));
  EXPECT_EQ(tpm_cache_impl_.GetBestSupportedKeyType(), TPM_ALG_ERROR);
}

}  // namespace trunks
