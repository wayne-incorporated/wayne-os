// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_POLICY_SESSION_H_
#define TRUNKS_POLICY_SESSION_H_

#include <map>
#include <string>
#include <vector>

#include "trunks/tpm_generated.h"

namespace trunks {

class AuthorizationDelegate;

// PolicySession is an interface for managing policy backed sessions for
// authorization and parameter encryption.
class PolicySession {
 public:
  PolicySession() {}
  PolicySession(const PolicySession&) = delete;
  PolicySession& operator=(const PolicySession&) = delete;

  virtual ~PolicySession() {}

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

  // This method is used to get the current PolicyDigest of the PolicySession.
  virtual TPM_RC GetDigest(std::string* digest) = 0;

  // This method is used to construct a complex policy. It takes a list
  // of policy digests. After the command is executed, the policy represented
  // by this session is the OR of the provided policies.
  virtual TPM_RC PolicyOR(const std::vector<std::string>& digests) = 0;

  // This method binds the PolicySession to a provided PCR map. If the empty
  // string is provided for all the values of the map, the PolicySession is
  // bound to the current PCR values.
  virtual TPM_RC PolicyPCR(const std::map<uint32_t, std::string>& pcr_map) = 0;

  // This method binds the PolicySession to a specified CommandCode.
  // Once called, this Session can only be used to authorize actions on the
  // provided CommandCode.
  virtual TPM_RC PolicyCommandCode(TPM_CC command_code) = 0;

  // This method includes a secret-based authorization to the PolicySession
  // with the following parameters:
  // |auth_entity| - handle of the entity providing authorization.
  // |auth_entity_name| - name of the entity providing authorization.
  // |nonce| - policy nonce for the session (can be empty string).
  // |cp_hash| - digest of the command parameters to which this authorization
  //             is limited (empty string, if not limited).
  // |policy_ref| - reference to a policy relating to the authorization
  //                (can be empty string).
  // |expiration| - relative time in seconds when authorization will expire
  //                (0 if never expires).
  // |delegate| - authorization delegate for |auth_entity|.
  virtual TPM_RC PolicySecret(TPMI_DH_ENTITY auth_entity,
                              const std::string& auth_entity_name,
                              const std::string& nonce,
                              const std::string& cp_hash,
                              const std::string& policy_ref,
                              int32_t expiration,
                              AuthorizationDelegate* delegate) = 0;

  // This method includes a signature-based authorization to the PolicySession
  // with the following parameters:
  // |auth_entity| - handle of the entity providing authorization (that is, of
  //                 the public key entity).
  // |auth_entity_name| - name of the entity providing authorization.
  // |nonce| - policy nonce for the session (can be empty string).
  // |cp_hash| - digest of the command parameters to which this authorization
  //             is limited (empty string, if not limited).
  // |policy_ref| - reference to a policy relating to the authorization
  //                (can be empty string).
  // |expiration| - relative time in seconds when authorization will expire
  //                (0 if never expires).
  // |signature| - signature object that specifies signing algorithm parameters
  //               and (for non-trial sessions) the contents of the signature.
  // |delegate| - authorization delegate for |auth_entity|.
  virtual TPM_RC PolicySigned(TPMI_DH_ENTITY auth_entity,
                              const std::string& auth_entity_name,
                              const std::string& nonce,
                              const std::string& cp_hash,
                              const std::string& policy_ref,
                              int32_t expiration,
                              const trunks::TPMT_SIGNATURE& signature,
                              AuthorizationDelegate* delegate) = 0;

  // This method specifies that Authorization Values need to be included in
  // HMAC computation done by the AuthorizationDelegate.
  virtual TPM_RC PolicyAuthValue() = 0;

  // Reset a policy session to its original state.
  virtual TPM_RC PolicyRestart() = 0;

  // Sets the current entity authorization value. This can be safely called
  // while the session is active and subsequent commands will use the value.
  virtual void SetEntityAuthorizationValue(const std::string& value) = 0;

  // This method includes a signature-based authorization to the PolicySession
  // with the following parameters:
  // |auth_entity| - handle of the entity providing authorization (that is, of
  //                 the public key entity).
  // |auth_entity_name| - name of the entity providing authorization.
  // |auth_data| - Authenticator Data
  // |auth_data_descr| - Descriptors of auth_data.
  //                     It is an array of (UINT16 offset, UINT16 size) tuples,
  //                     which points the part of auth_data for auth hash.
  // |signature| - signature object that specifies signing algorithm parameters
  //               and (for non-trial sessions) the contents of the signature.
  // |delegate| - authorization delegate for |auth_entity|.
  virtual TPM_RC PolicyFidoSigned(
      TPMI_DH_ENTITY auth_entity,
      const std::string& auth_entity_name,
      const std::string& auth_data,
      const std::vector<FIDO_DATA_RANGE>& auth_data_descr,
      const TPMT_SIGNATURE& signature,
      AuthorizationDelegate* delegate) = 0;

  // This method binds the PolicySession to a provided NV index based on the
  // given |offset|, |operand| and |operation|.
  virtual TPM_RC PolicyNV(uint32_t index,
                          uint32_t offset,
                          bool using_owner_authorization,
                          TPM2B_OPERAND operand,
                          TPM_EO operation,
                          AuthorizationDelegate* delegate) = 0;
};

}  // namespace trunks

#endif  // TRUNKS_POLICY_SESSION_H_
