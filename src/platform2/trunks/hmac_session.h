// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_HMAC_SESSION_H_
#define TRUNKS_HMAC_SESSION_H_

#include <string>

#include "trunks/tpm_generated.h"

namespace trunks {

class AuthorizationDelegate;

// HmacSession is an interface for managing hmac backed sessions for
// authorization and parameter encryption.
class HmacSession {
 public:
  HmacSession() {}
  HmacSession(const HmacSession&) = delete;
  HmacSession& operator=(const HmacSession&) = delete;

  virtual ~HmacSession() {}

  // Returns an authorization delegate for this session. Ownership of the
  // delegate pointer is retained by the session.
  virtual AuthorizationDelegate* GetDelegate() = 0;

  // Starts a session which is bound to |bind_entity| with
  // |bind_authorization_value|. Encryption is enabled if |enable_encryption| is
  // true. Salting is done if |salted| is true. The session remains active until
  // this object is destroyed or another session is started with a call to
  // Start*Session.
  virtual TPM_RC StartBoundSession(TPMI_DH_ENTITY bind_entity,
                                   const std::string& bind_authorization_value,
                                   bool salted,
                                   bool enable_encryption) = 0;

  // Starts an unbound session. Salting is done if |salted| is true. Encryption
  // is enabled if |enable_encryption| is true. The session remains active until
  // this object is destroyed or another session is started with a call to
  // Start*Session.
  virtual TPM_RC StartUnboundSession(bool salted, bool enable_encryption) = 0;

  // Sets the current entity authorization value. This can be safely called
  // while the session is active and subsequent commands will use the value.
  virtual void SetEntityAuthorizationValue(const std::string& value) = 0;

  // Sets the future_authorization_value field in the HmacDelegate. This
  // is used in response validation for the TPM2_HierarchyChangeAuth command.
  // We need to perform this because the HMAC value returned from
  // HierarchyChangeAuth uses the new auth_value.
  virtual void SetFutureAuthorizationValue(const std::string& value) = 0;
};

}  // namespace trunks

#endif  // TRUNKS_HMAC_SESSION_H_
