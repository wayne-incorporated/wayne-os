// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/hmac_session_impl.h"

#include <base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/mock_session_manager.h"
#include "trunks/mock_tpm.h"
#include "trunks/tpm_generated.h"
#include "trunks/trunks_factory_for_test.h"

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;

namespace trunks {

class HmacSessionTest : public testing::Test {
 public:
  HmacSessionTest() {}
  ~HmacSessionTest() override {}

  void SetUp() override {
    factory_.set_tpm(&mock_tpm_);
    factory_.set_session_manager(&mock_session_manager_);
  }

  HmacAuthorizationDelegate* GetHmacDelegate(HmacSessionImpl* session) {
    return &(session->hmac_delegate_);
  }

 protected:
  TrunksFactoryForTest factory_;
  NiceMock<MockTpm> mock_tpm_;
  NiceMock<MockSessionManager> mock_session_manager_;
};

TEST_F(HmacSessionTest, GetDelegateUninitialized) {
  HmacSessionImpl session(factory_);
  EXPECT_CALL(mock_session_manager_, GetSessionHandle())
      .WillRepeatedly(Return(kUninitializedHandle));
  EXPECT_EQ(nullptr, session.GetDelegate());
}

TEST_F(HmacSessionTest, GetDelegateSuccess) {
  HmacSessionImpl session(factory_);
  EXPECT_EQ(GetHmacDelegate(&session), session.GetDelegate());
}

TEST_F(HmacSessionTest, StartBoundSessionSuccess) {
  HmacSessionImpl session(factory_);
  TPM_HANDLE bind_entity = TPM_RH_FIRST;
  EXPECT_CALL(mock_session_manager_,
              StartSession(TPM_SE_HMAC, bind_entity, _, true, true, _))
      .WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_EQ(TPM_RC_SUCCESS,
            session.StartBoundSession(bind_entity, "", true, true));
}

TEST_F(HmacSessionTest, StartBoundSessionFailure) {
  HmacSessionImpl session(factory_);
  TPM_HANDLE bind_entity = TPM_RH_FIRST;
  EXPECT_CALL(mock_session_manager_,
              StartSession(TPM_SE_HMAC, bind_entity, _, true, true, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  EXPECT_EQ(TPM_RC_FAILURE,
            session.StartBoundSession(bind_entity, "", true, true));
}

TEST_F(HmacSessionTest, EntityAuthorizationForwardingTest) {
  HmacSessionImpl session(factory_);
  std::string test_auth("test_auth");
  session.SetEntityAuthorizationValue(test_auth);
  HmacAuthorizationDelegate* hmac_delegate = GetHmacDelegate(&session);
  std::string entity_auth = hmac_delegate->entity_authorization_value();
  EXPECT_EQ(0, test_auth.compare(entity_auth));
}

TEST_F(HmacSessionTest, FutureAuthorizationForwardingTest) {
  HmacSessionImpl session(factory_);
  std::string test_auth("test_auth");
  session.SetFutureAuthorizationValue(test_auth);
  HmacAuthorizationDelegate* hmac_delegate = GetHmacDelegate(&session);
  std::string entity_auth = hmac_delegate->future_authorization_value();
  EXPECT_EQ(0, test_auth.compare(entity_auth));
}

}  // namespace trunks
