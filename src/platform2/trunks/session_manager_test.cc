// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/session_manager_impl.h"

#include <cstring>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/error_codes.h"
#include "trunks/mock_tpm.h"
#include "trunks/mock_tpm_cache.h"
#include "trunks/mock_tpm_utility.h"
#include "trunks/tpm_constants.h"
#include "trunks/tpm_generated.h"
#include "trunks/trunks_factory_for_test.h"

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace {

// TODO(b/150264096): create a shared HexDecode in libhwsec and use that in this
// file instead.
void HexDecode(const char* hex, size_t expected_length, void* out) {
  std::vector<uint8_t> bytes;
  CHECK(base::HexStringToBytes(hex, &bytes));
  CHECK_EQ(bytes.size(), expected_length);
  memcpy(out, bytes.data(), expected_length);
}

}  // namespace

namespace trunks {

class SessionManagerTest : public testing::Test {
 public:
  SessionManagerTest() : session_manager_(factory_) {}
  ~SessionManagerTest() override {}

  void SetUp() override {
    factory_.set_tpm(&mock_tpm_);
    factory_.set_tpm_cache(&mock_tpm_cache_);
    factory_.set_tpm_utility(&mock_tpm_utility_);
  }

  void SetHandle(TPM_HANDLE handle) {
    session_manager_.session_handle_ = handle;
  }

  TPM2B_PUBLIC_KEY_RSA GetValidRSAPublicKey() {
    const char kValidModulus[] =
        "A1D50D088994000492B5F3ED8A9C5FC8772706219F4C063B2F6A8C6B74D3AD6B"
        "212A53D01DABB34A6261288540D420D3BA59ED279D859DE6227A7AB6BD88FADD"
        "FC3078D465F4DF97E03A52A587BD0165AE3B180FE7B255B7BEDC1BE81CB1383F"
        "E9E46F9312B1EF28F4025E7D332E33F4416525FEB8F0FC7B815E8FBB79CDABE6"
        "327B5A155FEF13F559A7086CB8A543D72AD6ECAEE2E704FF28824149D7F4E393"
        "D3C74E721ACA97F7ADBE2CCF7B4BCC165F7380F48065F2C8370F25F066091259"
        "D14EA362BAF236E3CD8771A94BDEDA3900577143A238AB92B6C55F11DEFAFB31"
        "7D1DC5B6AE210C52B008D87F2A7BFF6EB5C4FB32D6ECEC6505796173951A3167";
    TPM2B_PUBLIC_KEY_RSA rsa;
    rsa.size = 256;
    HexDecode(kValidModulus, rsa.size, rsa.buffer);
    return rsa;
  }

  TPMS_ECC_POINT GetValidEccPoint() {
    const char kEccPublicX[] =
        "C833DFF9E3A01C28CB3256572FA7B133ADE6B71C98BBA2EFD7C236A5659C619C";
    const char kEccPublicY[] =
        "831CFF0AFBAFF18307FDCDB12E50AB73F4DE7A5869A1EA388F38F19AF3BF5324";
    TPMS_ECC_POINT point;

    point.x.size = kEccKeySize;
    point.y.size = kEccKeySize;
    HexDecode(kEccPublicX, point.x.size, point.x.buffer);
    HexDecode(kEccPublicY, point.y.size, point.y.buffer);

    return point;
  }

 protected:
  TrunksFactoryForTest factory_;
  NiceMock<MockTpm> mock_tpm_;
  NiceMock<MockTpmCache> mock_tpm_cache_;
  NiceMock<MockTpmUtility> mock_tpm_utility_;

  // TODO(b/150265750): Create MockHmacAuthorizationDelegate and add unit tests
  // for the RSA and ECC session secret generation workflow.
  HmacAuthorizationDelegate delegate_;
  SessionManagerImpl session_manager_;
};

TEST_F(SessionManagerTest, CloseSessionSuccess) {
  TPM_HANDLE handle = TPM_RH_FIRST;
  SetHandle(handle);
  EXPECT_CALL(mock_tpm_, FlushContextSync(handle, nullptr))
      .WillOnce(Return(TPM_RC_SUCCESS));
  session_manager_.CloseSession();
}

TEST_F(SessionManagerTest, CloseSessionNoHandle) {
  TPM_HANDLE handle = kUninitializedHandle;
  SetHandle(handle);
  EXPECT_CALL(mock_tpm_, FlushContextSync(handle, nullptr)).Times(0);
  session_manager_.CloseSession();
}

TEST_F(SessionManagerTest, GetSessionHandleTest) {
  TPM_HANDLE handle = TPM_RH_FIRST;
  EXPECT_EQ(kUninitializedHandle, session_manager_.GetSessionHandle());
  SetHandle(handle);
  EXPECT_EQ(handle, session_manager_.GetSessionHandle());
}

TEST_F(SessionManagerTest, StartRsaSessionSuccess) {
  TPM_SE session_type = TPM_SE_TRIAL;

  TPMT_PUBLIC public_area{
      .type = TPM_ALG_RSA,
      .name_alg = TPM_ALG_SHA256,
      .object_attributes = trunks::kSensitiveDataOrigin |
                           trunks::kUserWithAuth | trunks::kNoDA |
                           trunks::kDecrypt,
      .parameters =
          TPMU_PUBLIC_PARMS{
              .rsa_detail = TPMS_RSA_PARMS{},
          },
      .unique =
          TPMU_PUBLIC_ID{
              .rsa = GetValidRSAPublicKey(),
          },
  };

  EXPECT_CALL(mock_tpm_cache_, GetSaltingKeyPublicArea(_))
      .WillOnce(DoAll(SetArgPointee<0>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, CreateSaltingKey(_, _)).Times(0);
  TPM_HANDLE handle = TPM_RH_FIRST;
  TPM2B_NONCE nonce;
  nonce.size = 20;
  EXPECT_CALL(mock_tpm_, StartAuthSessionSyncShort(_, handle, _, _,
                                                   session_type, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<8>(nonce), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS,
            session_manager_.StartSession(session_type, handle, "", true, false,
                                          &delegate_));
}

TEST_F(SessionManagerTest, StartEccSessionSuccess) {
  TPM_SE session_type = TPM_SE_TRIAL;

  TPMT_PUBLIC public_area{
      .type = TPM_ALG_ECC,
      .name_alg = TPM_ALG_SHA256,
      .object_attributes = trunks::kSensitiveDataOrigin |
                           trunks::kUserWithAuth | trunks::kNoDA |
                           trunks::kDecrypt,
      .parameters =
          TPMU_PUBLIC_PARMS{
              .ecc_detail = TPMS_ECC_PARMS{},
          },
      .unique =
          TPMU_PUBLIC_ID{
              .ecc = GetValidEccPoint(),
          },
  };

  EXPECT_CALL(mock_tpm_cache_, GetSaltingKeyPublicArea(_))
      .WillOnce(DoAll(SetArgPointee<0>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, CreateSaltingKey(_, _)).Times(0);
  TPM_HANDLE handle = TPM_RH_FIRST;
  TPM2B_NONCE nonce;
  nonce.size = 20;
  EXPECT_CALL(mock_tpm_, StartAuthSessionSyncShort(_, handle, _, _,
                                                   session_type, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<8>(nonce), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(session_manager_.StartSession(session_type, handle, "", true, false,
                                          &delegate_),
            TPM_RC_SUCCESS);
}

TEST_F(SessionManagerTest, StartSessionGetSaltingKeyError) {
  EXPECT_CALL(mock_tpm_cache_, GetSaltingKeyPublicArea(_))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(session_manager_.StartSession(TPM_SE_TRIAL, TPM_RH_NULL, "", true,
                                          false, &delegate_),
            TPM_RC_FAILURE);
}

TEST_F(SessionManagerTest, StartTempSaltingKeySession) {
  TPM_SE session_type = TPM_SE_TRIAL;
  TPM_HANDLE handle = TPM_RH_FIRST;
  EXPECT_CALL(mock_tpm_cache_, GetSaltingKeyPublicArea(_))
      .WillOnce(Return(TPM_RC_HANDLE));
  EXPECT_CALL(mock_tpm_utility_, CreateSaltingKey(_, _))
      .WillOnce(DoAll(SetArgPointee<0>(handle), Return(TPM_RC_SUCCESS)));

  TPMT_PUBLIC public_area{
      .type = TPM_ALG_ECC,
      .name_alg = TPM_ALG_SHA256,
      .parameters =
          TPMU_PUBLIC_PARMS{
              .ecc_detail = TPMS_ECC_PARMS{},
          },
      .unique =
          TPMU_PUBLIC_ID{
              .ecc = GetValidEccPoint(),
          },
  };

  TPM2B_PUBLIC public_data{.public_area = public_area};

  EXPECT_CALL(mock_tpm_, ReadPublicSync(handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_data), Return(TPM_RC_SUCCESS)));

  TPM2B_NONCE nonce;
  nonce.size = 20;
  EXPECT_CALL(mock_tpm_, StartAuthSessionSyncShort(_, handle, _, _,
                                                   session_type, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<8>(nonce), Return(TPM_RC_SUCCESS)));

  EXPECT_EQ(session_manager_.StartSession(session_type, handle, "", true, false,
                                          &delegate_),
            TPM_RC_SUCCESS);
}

TEST_F(SessionManagerTest, StartTempSaltingKeySessionFail) {
  TPM_SE session_type = TPM_SE_TRIAL;
  TPM_HANDLE handle = TPM_RH_FIRST;
  EXPECT_CALL(mock_tpm_cache_, GetSaltingKeyPublicArea(_))
      .WillOnce(Return(TPM_RC_HANDLE));
  EXPECT_CALL(mock_tpm_utility_, CreateSaltingKey(_, _))
      .WillOnce(DoAll(SetArgPointee<0>(handle), Return(TPM_RC_SUCCESS)));

  TPMT_PUBLIC public_area{
      .type = TPM_ALG_ECC,
      .name_alg = TPM_ALG_SHA256,
      .parameters =
          TPMU_PUBLIC_PARMS{
              .ecc_detail = TPMS_ECC_PARMS{},
          },
      .unique =
          TPMU_PUBLIC_ID{
              .ecc = GetValidEccPoint(),
          },
  };

  TPM2B_PUBLIC public_data{.public_area = public_area};

  EXPECT_CALL(mock_tpm_, ReadPublicSync(handle, _, _, _, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(public_data), Return(TPM_RC_FAILURE)));

  EXPECT_EQ(session_manager_.StartSession(session_type, handle, "", true, false,
                                          &delegate_),
            TPM_RC_FAILURE);
}

TEST_F(SessionManagerTest, StartSessionBadSaltingKey) {
  TPMT_PUBLIC public_area{
      .type = TPM_ALG_RSA,
      .object_attributes = trunks::kSensitiveDataOrigin |
                           trunks::kUserWithAuth | trunks::kNoDA |
                           trunks::kDecrypt,
      .parameters =
          TPMU_PUBLIC_PARMS{
              .rsa_detail = TPMS_RSA_PARMS{},
          },
      .unique =
          TPMU_PUBLIC_ID{
              .rsa =
                  TPM2B_PUBLIC_KEY_RSA{
                      .size = 32,
                  },
          },
  };
  EXPECT_CALL(mock_tpm_cache_, GetSaltingKeyPublicArea(_))
      .WillOnce(DoAll(SetArgPointee<0>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TRUNKS_RC_SESSION_SETUP_ERROR,
            session_manager_.StartSession(TPM_SE_TRIAL, TPM_RH_NULL, "", true,
                                          false, &delegate_));
  public_area.type = TPM_ALG_ECC;
  public_area.parameters = TPMU_PUBLIC_PARMS{
      .ecc_detail = TPMS_ECC_PARMS{},
  };
  public_area.unique = TPMU_PUBLIC_ID{
      .ecc =
          TPMS_ECC_POINT{
              .x =
                  TPM2B_ECC_PARAMETER{
                      .size = 1,
                      .buffer = {0},
                  },
              .y =
                  TPM2B_ECC_PARAMETER{
                      .size = 1,
                      .buffer = {0},
                  },
          },
  };
  EXPECT_CALL(mock_tpm_cache_, GetSaltingKeyPublicArea(_))
      .WillOnce(DoAll(SetArgPointee<0>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TRUNKS_RC_SESSION_SETUP_ERROR,
            session_manager_.StartSession(TPM_SE_TRIAL, TPM_RH_NULL, "", true,
                                          false, &delegate_));
}

TEST_F(SessionManagerTest, StartSessionFailure) {
  TPMT_PUBLIC public_area{
      .type = TPM_ALG_RSA,
      .object_attributes = trunks::kSensitiveDataOrigin |
                           trunks::kUserWithAuth | trunks::kNoDA |
                           trunks::kDecrypt,
      .parameters =
          TPMU_PUBLIC_PARMS{
              .rsa_detail = TPMS_RSA_PARMS{},
          },
      .unique =
          TPMU_PUBLIC_ID{
              .rsa = GetValidRSAPublicKey(),
          },
  };
  EXPECT_CALL(mock_tpm_cache_, GetSaltingKeyPublicArea(_))
      .WillOnce(DoAll(SetArgPointee<0>(public_area), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_,
              StartAuthSessionSyncShort(_, TPM_RH_NULL, _, _, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            session_manager_.StartSession(TPM_SE_TRIAL, TPM_RH_NULL, "", true,
                                          false, &delegate_));
}

TEST_F(SessionManagerTest, StartSessionBadNonce) {
  TPM_SE session_type = TPM_SE_TRIAL;
  TPMT_PUBLIC public_area{
      .type = TPM_ALG_RSA,
      .object_attributes = trunks::kSensitiveDataOrigin |
                           trunks::kUserWithAuth | trunks::kNoDA |
                           trunks::kDecrypt,
      .parameters =
          TPMU_PUBLIC_PARMS{
              .rsa_detail = TPMS_RSA_PARMS{},
          },
      .unique =
          TPMU_PUBLIC_ID{
              .rsa = GetValidRSAPublicKey(),
          },
  };
  EXPECT_CALL(mock_tpm_cache_, GetSaltingKeyPublicArea(_))
      .WillOnce(DoAll(SetArgPointee<0>(public_area), Return(TPM_RC_SUCCESS)));
  TPM_HANDLE handle = TPM_RH_FIRST;
  TPM2B_NONCE nonce;
  nonce.size = 0;
  EXPECT_CALL(mock_tpm_, StartAuthSessionSyncShort(_, handle, _, _,
                                                   session_type, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<8>(nonce), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_FAILURE,
            session_manager_.StartSession(session_type, handle, "", true, false,
                                          &delegate_));
}

}  // namespace trunks
