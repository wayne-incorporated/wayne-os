// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_MOCK_POLICY_SESSION_H_
#define TRUNKS_MOCK_POLICY_SESSION_H_

#include <map>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "trunks/policy_session.h"

namespace trunks {

class MockPolicySession : public PolicySession {
 public:
  MockPolicySession();
  MockPolicySession(const MockPolicySession&) = delete;
  MockPolicySession& operator=(const MockPolicySession&) = delete;

  ~MockPolicySession() override;

  MOCK_METHOD0(GetDelegate, AuthorizationDelegate*());
  MOCK_METHOD4(StartBoundSession,
               TPM_RC(TPMI_DH_ENTITY bind_entity,
                      const std::string& bind_authorization_value,
                      bool salted,
                      bool enable_encryption));
  MOCK_METHOD2(StartUnboundSession,
               TPM_RC(bool salted, bool enable_encryption));
  MOCK_METHOD1(GetDigest, TPM_RC(std::string*));
  MOCK_METHOD1(PolicyOR, TPM_RC(const std::vector<std::string>&));
  MOCK_METHOD1(PolicyPCR, TPM_RC(const std::map<uint32_t, std::string>&));
  MOCK_METHOD1(PolicyCommandCode, TPM_RC(TPM_CC));
  MOCK_METHOD7(PolicySecret,
               TPM_RC(TPMI_DH_ENTITY,
                      const std::string&,
                      const std::string&,
                      const std::string&,
                      const std::string&,
                      int32_t,
                      AuthorizationDelegate*));
  MOCK_METHOD8(PolicySigned,
               TPM_RC(TPMI_DH_ENTITY,
                      const std::string&,
                      const std::string&,
                      const std::string&,
                      const std::string&,
                      int32_t,
                      const trunks::TPMT_SIGNATURE&,
                      AuthorizationDelegate*));
  MOCK_METHOD6(PolicyFidoSigned,
               TPM_RC(TPMI_DH_ENTITY,
                      const std::string&,
                      const std::string&,
                      const std::vector<FIDO_DATA_RANGE>&,
                      const trunks::TPMT_SIGNATURE&,
                      AuthorizationDelegate*));
  MOCK_METHOD0(PolicyAuthValue, TPM_RC());
  MOCK_METHOD0(PolicyRestart, TPM_RC());
  MOCK_METHOD1(SetEntityAuthorizationValue, void(const std::string&));
  MOCK_METHOD6(PolicyNV,
               TPM_RC(uint32_t,
                      uint32_t,
                      bool,
                      TPM2B_OPERAND,
                      TPM_EO,
                      AuthorizationDelegate*));
};

}  // namespace trunks

#endif  // TRUNKS_MOCK_POLICY_SESSION_H_
