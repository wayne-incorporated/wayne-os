// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_SESSION_MANAGER_H_
#define TRUNKS_SESSION_MANAGER_H_

#include <string>

#include "trunks/hmac_authorization_delegate.h"
#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

namespace trunks {

const trunks::TPM_HANDLE kUninitializedHandle = 0;

// This class is used to keep track of a TPM session. Each instance of this
// class is used to account for one instance of a TPM session. Currently
// this class is used by AuthorizationSession instances to keep track of TPM
// sessions.
// Note: This class is not intended to be used independently. However clients
// who want to manually manage their sessions can use this class to Start and
// Close TPM backed Sessions. Example usage:
// std::unique_ptr<SessionManager> session_manager =
//     factory.GetSessionManager();
// session_manager->StartSession(...);
// TPM_HANDLE session_handle = session_manager->GetSessionHandle();
class TRUNKS_EXPORT SessionManager {
 public:
  SessionManager() {}
  SessionManager(const SessionManager&) = delete;
  SessionManager& operator=(const SessionManager&) = delete;

  virtual ~SessionManager() {}

  // This method is used get the handle to the AuthorizationSession managed by
  // this instance.
  virtual TPM_HANDLE GetSessionHandle() const = 0;

  // This method is used to flush all TPM context associated with the current
  // session
  virtual void CloseSession() = 0;

  // This method is used to start a new AuthorizationSession. Once started,
  // GetSessionHandle() can be used to access the handle to the TPM session.
  // If the created sessions is salted, we need to ensure that TPM ownership is
  // taken and the salting key created before this method is called.
  // Returns TPM_RC_SUCCESS and returns the nonces used to create the session
  // on success.
  virtual TPM_RC StartSession(TPM_SE session_type,
                              TPMI_DH_ENTITY bind_entity,
                              const std::string& bind_authorization_value,
                              bool salted,
                              bool enable_encryption,
                              HmacAuthorizationDelegate* delegate) = 0;
};

}  // namespace trunks

#endif  // TRUNKS_SESSION_MANAGER_H_
