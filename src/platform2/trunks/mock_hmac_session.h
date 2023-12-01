// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_MOCK_HMAC_SESSION_H_
#define TRUNKS_MOCK_HMAC_SESSION_H_

#include <string>

#include <gmock/gmock.h>

#include "trunks/hmac_session.h"

namespace trunks {

class MockHmacSession : public HmacSession {
 public:
  MockHmacSession();
  MockHmacSession(const MockHmacSession&) = delete;
  MockHmacSession& operator=(const MockHmacSession&) = delete;

  ~MockHmacSession() override;

  MOCK_METHOD0(GetDelegate, AuthorizationDelegate*());
  MOCK_METHOD4(StartBoundSession,
               TPM_RC(TPMI_DH_ENTITY bind_entity,
                      const std::string& bind_authorization_value,
                      bool salted,
                      bool enable_encryption));
  MOCK_METHOD2(StartUnboundSession,
               TPM_RC(bool salted, bool enable_encryption));
  MOCK_METHOD1(SetEntityAuthorizationValue, void(const std::string& value));
  MOCK_METHOD1(SetFutureAuthorizationValue, void(const std::string& value));
};

}  // namespace trunks

#endif  // TRUNKS_MOCK_HMAC_SESSION_H_
