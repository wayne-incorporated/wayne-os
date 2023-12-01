// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_MOCK_SESSION_MANAGER_H_
#define TRUNKS_MOCK_SESSION_MANAGER_H_

#include <string>

#include <gmock/gmock.h>

#include "trunks/session_manager.h"

namespace trunks {

class MockSessionManager : public SessionManager {
 public:
  MockSessionManager();
  MockSessionManager(const MockSessionManager&) = delete;
  MockSessionManager& operator=(const MockSessionManager&) = delete;

  ~MockSessionManager() override;

  MOCK_CONST_METHOD0(GetSessionHandle, TPM_HANDLE());
  MOCK_METHOD0(CloseSession, void());
  MOCK_METHOD6(StartSession,
               TPM_RC(TPM_SE,
                      TPMI_DH_ENTITY,
                      const std::string&,
                      bool,
                      bool,
                      HmacAuthorizationDelegate*));
};

}  // namespace trunks

#endif  // TRUNKS_MOCK_SESSION_MANAGER_H_
