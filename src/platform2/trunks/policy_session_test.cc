// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/policy_session_impl.h"

#include <crypto/sha2.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/error_codes.h"
#include "trunks/mock_session_manager.h"
#include "trunks/mock_tpm.h"
#include "trunks/mock_tpm_utility.h"
#include "trunks/tpm_generated.h"
#include "trunks/trunks_factory_for_test.h"

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;

namespace {

// Returns the total number of bits set in the first |size| elements from
// |array|.
int CountSetBits(const uint8_t* array, size_t size) {
  int res = 0;
  for (size_t i = 0; i < size; ++i) {
    for (int bit_position = 0; bit_position < 8; ++bit_position) {
      if ((array[i] & (1 << bit_position)) != 0) {
        ++res;
      }
    }
  }
  return res;
}

}  // namespace

namespace trunks {

class PolicySessionTest : public testing::Test {
 public:
  PolicySessionTest() {}
  ~PolicySessionTest() override {}

  void SetUp() override {
    factory_.set_session_manager(&mock_session_manager_);
    factory_.set_tpm(&mock_tpm_);
    factory_.set_tpm_utility(&mock_tpm_utility_);
  }

  HmacAuthorizationDelegate* GetHmacDelegate(PolicySessionImpl* session) {
    return &(session->hmac_delegate_);
  }

 protected:
  TrunksFactoryForTest factory_;
  NiceMock<MockSessionManager> mock_session_manager_;
  NiceMock<MockTpm> mock_tpm_;
  NiceMock<MockTpmUtility> mock_tpm_utility_;
};

TEST_F(PolicySessionTest, GetDelegateUninitialized) {
  PolicySessionImpl session(factory_);
  EXPECT_CALL(mock_session_manager_, GetSessionHandle())
      .WillRepeatedly(Return(kUninitializedHandle));
  EXPECT_EQ(nullptr, session.GetDelegate());
}

TEST_F(PolicySessionTest, GetDelegateSuccess) {
  PolicySessionImpl session(factory_);
  EXPECT_EQ(GetHmacDelegate(&session), session.GetDelegate());
}

TEST_F(PolicySessionTest, StartBoundSessionSuccess) {
  PolicySessionImpl session(factory_);
  EXPECT_EQ(TPM_RC_SUCCESS,
            session.StartBoundSession(TPM_RH_FIRST, "auth", true, true));
}

TEST_F(PolicySessionTest, StartBoundSessionFailure) {
  PolicySessionImpl session(factory_);
  TPM_HANDLE handle = TPM_RH_FIRST;
  EXPECT_CALL(mock_session_manager_,
              StartSession(TPM_SE_POLICY, handle, _, true, true, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            session.StartBoundSession(handle, "auth", true, true));
}

TEST_F(PolicySessionTest, StartBoundSessionBadType) {
  PolicySessionImpl session(factory_, TPM_SE_HMAC);
  EXPECT_EQ(SAPI_RC_INVALID_SESSIONS,
            session.StartBoundSession(TPM_RH_FIRST, "auth", true, true));
}

TEST_F(PolicySessionTest, StartUnboundSessionSuccess) {
  PolicySessionImpl session(factory_);
  EXPECT_EQ(TPM_RC_SUCCESS, session.StartUnboundSession(true, true));
}

TEST_F(PolicySessionTest, StartUnboundSessionFailure) {
  PolicySessionImpl session(factory_);
  EXPECT_CALL(mock_session_manager_,
              StartSession(TPM_SE_POLICY, TPM_RH_NULL, _, true, true, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, session.StartUnboundSession(true, true));
}

TEST_F(PolicySessionTest, GetDigestSuccess) {
  PolicySessionImpl session(factory_);
  std::string digest;
  TPM2B_DIGEST policy_digest;
  policy_digest.size = SHA256_DIGEST_SIZE;
  EXPECT_CALL(mock_tpm_, PolicyGetDigestSync(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(policy_digest), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, session.GetDigest(&digest));
  EXPECT_EQ(static_cast<size_t>(SHA256_DIGEST_SIZE), digest.size());
}

TEST_F(PolicySessionTest, GetDigestFailure) {
  PolicySessionImpl session(factory_);
  std::string digest;
  EXPECT_CALL(mock_tpm_, PolicyGetDigestSync(_, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, session.GetDigest(&digest));
}

TEST_F(PolicySessionTest, PolicyORSuccess) {
  PolicySessionImpl session(factory_);
  std::vector<std::string> digests;
  digests.push_back("digest1");
  digests.push_back("digest2");
  digests.push_back("digest3");
  TPML_DIGEST tpm_digests;
  EXPECT_CALL(mock_tpm_, PolicyORSync(_, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&tpm_digests), Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, session.PolicyOR(digests));
  EXPECT_EQ(tpm_digests.count, digests.size());
  EXPECT_EQ(StringFrom_TPM2B_DIGEST(tpm_digests.digests[0]), digests[0]);
  EXPECT_EQ(StringFrom_TPM2B_DIGEST(tpm_digests.digests[1]), digests[1]);
  EXPECT_EQ(StringFrom_TPM2B_DIGEST(tpm_digests.digests[2]), digests[2]);
}

TEST_F(PolicySessionTest, PolicyORBadParam) {
  PolicySessionImpl session(factory_);
  std::vector<std::string> digests;
  // We use 9 here because the maximum number of digests allowed by the TPM
  // is 8. Therefore having 9 digests here should cause the code to fail.
  digests.resize(9);
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER, session.PolicyOR(digests));
}

TEST_F(PolicySessionTest, PolicyORFailure) {
  PolicySessionImpl session(factory_);
  std::vector<std::string> digests;
  EXPECT_CALL(mock_tpm_, PolicyORSync(_, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, session.PolicyOR(digests));
}

TEST_F(PolicySessionTest, PolicyPCRSuccess) {
  PolicySessionImpl session(factory_);
  std::string pcr_digest("digest");
  uint32_t pcr_index = 1;
  TPML_PCR_SELECTION pcr_select;
  TPM2B_DIGEST pcr_value;
  EXPECT_CALL(mock_tpm_, PolicyPCRSync(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&pcr_value), SaveArg<3>(&pcr_select),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, session.PolicyPCR(std::map<uint32_t, std::string>(
                                {{pcr_index, pcr_digest}})));
  uint8_t pcr_select_index = pcr_index / 8;
  uint8_t pcr_select_byte = 1 << (pcr_index % 8);
  EXPECT_EQ(pcr_select.count, 1u);
  EXPECT_EQ(pcr_select.pcr_selections[0].hash, TPM_ALG_SHA256);
  EXPECT_EQ(pcr_select.pcr_selections[0].sizeof_select, PCR_SELECT_MIN);
  EXPECT_EQ(pcr_select.pcr_selections[0].pcr_select[pcr_select_index],
            pcr_select_byte);
  EXPECT_EQ(StringFrom_TPM2B_DIGEST(pcr_value),
            crypto::SHA256HashString(pcr_digest));
}

TEST_F(PolicySessionTest, PolicyMultiplePCRSuccess) {
  PolicySessionImpl session(factory_);
  std::string pcr_digest1("digest1");
  std::string pcr_digest2("digest2");
  std::string pcr_digest3("digest3");
  uint32_t pcr_index1 = 1;
  uint32_t pcr_index2 = 9;
  uint32_t pcr_index3 = 15;
  std::map<uint32_t, std::string> pcr_map({{pcr_index1, pcr_digest1},
                                           {pcr_index2, pcr_digest2},
                                           {pcr_index3, pcr_digest3}});
  TPML_PCR_SELECTION pcr_select;
  TPM2B_DIGEST pcr_value;
  EXPECT_CALL(mock_tpm_, PolicyPCRSync(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&pcr_value), SaveArg<3>(&pcr_select),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_EQ(TPM_RC_SUCCESS, session.PolicyPCR(pcr_map));
  EXPECT_EQ(pcr_select.count, 1u);
  TPMS_PCR_SELECTION pcr_selection = pcr_select.pcr_selections[0];
  EXPECT_EQ(pcr_selection.hash, TPM_ALG_SHA256);
  EXPECT_EQ(pcr_selection.sizeof_select, PCR_SELECT_MIN);
  EXPECT_EQ(3, CountSetBits(pcr_selection.pcr_select, PCR_SELECT_MIN));
  uint8_t pcr_select_index1 = pcr_index1 / 8;
  uint8_t pcr_select_mask1 = 1 << (pcr_index1 % 8);
  uint8_t pcr_select_index2 = pcr_index2 / 8;
  uint8_t pcr_select_mask2 = 1 << (pcr_index2 % 8);
  uint8_t pcr_select_index3 = pcr_index3 / 8;
  uint8_t pcr_select_mask3 = 1 << (pcr_index3 % 8);
  EXPECT_TRUE(pcr_selection.pcr_select[pcr_select_index1] & pcr_select_mask1);
  EXPECT_TRUE(pcr_selection.pcr_select[pcr_select_index2] & pcr_select_mask2);
  EXPECT_TRUE(pcr_selection.pcr_select[pcr_select_index3] & pcr_select_mask3);
  EXPECT_EQ(StringFrom_TPM2B_DIGEST(pcr_value),
            crypto::SHA256HashString(pcr_digest1 + pcr_digest2 + pcr_digest3));
}

TEST_F(PolicySessionTest, PolicyPCRFailure) {
  PolicySessionImpl session(factory_);
  EXPECT_CALL(mock_tpm_, PolicyPCRSync(_, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(
      TPM_RC_FAILURE,
      session.PolicyPCR(std::map<uint32_t, std::string>({{1, "pcr_digest"}})));
}

TEST_F(PolicySessionTest, PolicyPCRTrialWithNoDigest) {
  PolicySessionImpl session(factory_, TPM_SE_TRIAL);
  EXPECT_EQ(SAPI_RC_BAD_PARAMETER,
            session.PolicyPCR(std::map<uint32_t, std::string>({{1, ""}})));
}

TEST_F(PolicySessionTest, PolicyCommandCodeSuccess) {
  PolicySessionImpl session(factory_);
  TPM_CC command_code = TPM_CC_FIRST;
  EXPECT_CALL(mock_tpm_, PolicyCommandCodeSync(_, _, command_code, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS, session.PolicyCommandCode(TPM_CC_FIRST));
}

TEST_F(PolicySessionTest, PolicyCommandCodeFailure) {
  PolicySessionImpl session(factory_);
  EXPECT_CALL(mock_tpm_, PolicyCommandCodeSync(_, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, session.PolicyCommandCode(TPM_CC_FIRST));
}

TEST_F(PolicySessionTest, PolicySigned) {
  PolicySessionImpl session(factory_);
  EXPECT_CALL(mock_tpm_, PolicySignedSyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS,
            session.PolicySigned(1, "", "", "", "", 0, TPMT_SIGNATURE(),
                                 GetHmacDelegate(&session)));
}

TEST_F(PolicySessionTest, PolicyFidoSigned) {
  PolicySessionImpl session(factory_);
  EXPECT_CALL(mock_tpm_, PolicyFidoSignedSync(_, _, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS,
            session.PolicyFidoSigned(1, "", "", {}, TPMT_SIGNATURE(),
                                     GetHmacDelegate(&session)));
}

TEST_F(PolicySessionTest, PolicyAuthValueSuccess) {
  PolicySessionImpl session(factory_);
  EXPECT_CALL(mock_tpm_, PolicyAuthValueSync(_, _, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS, session.PolicyAuthValue());
}

TEST_F(PolicySessionTest, PolicyAuthValueFailure) {
  PolicySessionImpl session(factory_);
  EXPECT_CALL(mock_tpm_, PolicyAuthValueSync(_, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE, session.PolicyAuthValue());
}

TEST_F(PolicySessionTest, EntityAuthorizationForwardingTest) {
  PolicySessionImpl session(factory_);
  std::string test_auth("test_auth");
  session.SetEntityAuthorizationValue(test_auth);
  HmacAuthorizationDelegate* hmac_delegate = GetHmacDelegate(&session);
  std::string entity_auth = hmac_delegate->entity_authorization_value();
  EXPECT_EQ(0, test_auth.compare(entity_auth));
}

TEST_F(PolicySessionTest, PolicyNVSuccessNoOwnerAuth) {
  PolicySessionImpl session(factory_);

  const uint32_t index = 0x100e;
  const uint32_t offset = 0;
  const TPM_EO operation = trunks::TPM_EO_EQ;
  const std::string operand_b = "data";
  const std::string nv_name = "name";
  const std::unique_ptr<AuthorizationDelegate> authorization_delegate =
      factory_.GetPasswordAuthorization("");
  const TPM_HANDLE policy_session_handle = kUninitializedHandle;
  std::string policy_session_name;
  Serialize_TPM_HANDLE(policy_session_handle, &policy_session_name);

  EXPECT_CALL(mock_tpm_utility_, GetNVSpaceName(index, _))
      .WillOnce(DoAll(SetArgPointee<1>(nv_name), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_session_manager_, GetSessionHandle)
      .WillOnce(Return(policy_session_handle));

  trunks::TPM2B_OPERAND called_operand_b;
  EXPECT_CALL(
      mock_tpm_,
      PolicyNVSync(NV_INDEX_FIRST + index, nv_name, NV_INDEX_FIRST + index,
                   nv_name, policy_session_handle, policy_session_name, _,
                   offset, operation, authorization_delegate.get()))
      .WillOnce(DoAll(SaveArg<6>(&called_operand_b), Return(TPM_RC_SUCCESS)));

  EXPECT_EQ(TPM_RC_SUCCESS,
            session.PolicyNV(index, offset, /*using_owner_authorization=*/false,
                             trunks::Make_TPM2B_DIGEST(operand_b),
                             trunks::TPM_EO_EQ, authorization_delegate.get()));
  EXPECT_EQ(operand_b, StringFrom_TPM2B_DIGEST(called_operand_b));
}

TEST_F(PolicySessionTest, PolicyNVSuccessOwnerAuth) {
  PolicySessionImpl session(factory_);

  const uint32_t index = 0x100e;
  const uint32_t offset = 0;
  const TPM_EO operation = trunks::TPM_EO_EQ;
  const std::string operand_b = "data";
  const std::string nv_name = "name";
  const std::unique_ptr<AuthorizationDelegate> authorization_delegate =
      factory_.GetPasswordAuthorization("");
  const TPM_HANDLE policy_session_handle = kUninitializedHandle;
  std::string policy_session_name;
  Serialize_TPM_HANDLE(policy_session_handle, &policy_session_name);
  const TPM_HANDLE owner_handle = TPM_RH_OWNER;
  std::string owner_handle_name;
  trunks::Serialize_TPM_HANDLE(owner_handle, &owner_handle_name);

  EXPECT_CALL(mock_tpm_utility_, GetNVSpaceName(index, _))
      .WillOnce(DoAll(SetArgPointee<1>(nv_name), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_session_manager_, GetSessionHandle)
      .WillOnce(Return(policy_session_handle));

  trunks::TPM2B_OPERAND called_operand_b;
  EXPECT_CALL(
      mock_tpm_,
      PolicyNVSync(owner_handle, owner_handle_name, NV_INDEX_FIRST + index,
                   nv_name, policy_session_handle, policy_session_name, _,
                   offset, operation, authorization_delegate.get()))
      .WillOnce(DoAll(SaveArg<6>(&called_operand_b), Return(TPM_RC_SUCCESS)));

  EXPECT_EQ(TPM_RC_SUCCESS,
            session.PolicyNV(index, offset, /*using_owner_authorization=*/true,
                             trunks::Make_TPM2B_DIGEST(operand_b), operation,
                             authorization_delegate.get()));
  EXPECT_EQ(operand_b, StringFrom_TPM2B_DIGEST(called_operand_b));
}

TEST_F(PolicySessionTest, PolicyNVFailure) {
  PolicySessionImpl session(factory_);

  EXPECT_CALL(mock_tpm_, PolicyNVSync).WillOnce(Return(TPM_RC_FAILURE));

  EXPECT_EQ(
      TPM_RC_FAILURE,
      session.PolicyNV(/*index=*/0x100e, /*offset=*/0,
                       /*using_owner_authorization=*/false,
                       trunks::Make_TPM2B_DIGEST("data"), trunks::TPM_EO_EQ,
                       factory_.GetPasswordAuthorization("").get()));
}

TEST_F(PolicySessionTest, PolicyNVFailureAtGetName) {
  PolicySessionImpl session(factory_);

  EXPECT_CALL(mock_tpm_utility_, GetNVSpaceName)
      .WillOnce(Return(TPM_RC_FAILURE));

  EXPECT_EQ(
      TPM_RC_FAILURE,
      session.PolicyNV(/*index=*/0x100e, /*offset=*/0,
                       /*using_owner_authorization=*/false,
                       trunks::Make_TPM2B_DIGEST("data"), trunks::TPM_EO_EQ,
                       factory_.GetPasswordAuthorization("").get()));
}

}  // namespace trunks
