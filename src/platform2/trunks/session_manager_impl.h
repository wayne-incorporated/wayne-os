// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_SESSION_MANAGER_IMPL_H_
#define TRUNKS_SESSION_MANAGER_IMPL_H_

#include "trunks/session_manager.h"

#include <memory>
#include <optional>
#include <string>

#include <brillo/secure_blob.h>
#include <gtest/gtest_prod.h>

#include "trunks/scoped_key_handle.h"
#include "trunks/tpm_generated.h"
#include "trunks/trunks_factory.h"

namespace trunks {

// ECC key size in bytes of the NIST_P-256 curve.
constexpr size_t kEccKeySize = 32;

// This class is used to keep track of a TPM session. Each instance of this
// class is used to account for one instance of a TPM session. Currently
// this class is used by AuthorizationSession instances to keep track of TPM
// sessions.
class TRUNKS_EXPORT SessionManagerImpl : public SessionManager {
 public:
  explicit SessionManagerImpl(const TrunksFactory& factory);
  SessionManagerImpl(const SessionManagerImpl&) = delete;
  SessionManagerImpl& operator=(const SessionManagerImpl&) = delete;

  ~SessionManagerImpl() override;

  TPM_HANDLE GetSessionHandle() const override { return session_handle_; }
  void CloseSession() override;
  TPM_RC StartSession(TPM_SE session_type,
                      TPMI_DH_ENTITY bind_entity,
                      const std::string& bind_authorization_value,
                      bool salted,
                      bool enable_encryption,
                      HmacAuthorizationDelegate* delegate) override;

 private:
  // Generates a session secret, stores it in |salt|, and set the used key
  // handle to |tpm_key|. Also computes its corresponding string
  // |encrypted_salt|, which will be sent to the TPM when starting a new
  // session. TPM can recover the session secret from |encrypted_salt| using its
  // internal private key. The pointers |salt| and |encrypted_salt| must be
  // non-null. Returns TPM_RC_SUCCESS on success or other values on an error.
  //
  // This is a wrapper function. It calls either GenerateRsaSessionSalt() or
  // GenerateEccSessionSalt(), depending on the salting key type.
  TPM_RC GenerateSessionSalt(TPMI_DH_OBJECT* tpm_key,
                             brillo::SecureBlob* salt,
                             std::string* encrypted_salt);

  TPM_RC CreateTempSaltingKey();

  // This factory is only set in the constructor and is used to instantiate
  // The TPM class to forward commands to the TPM chip.
  const TrunksFactory& factory_;

  // This handle keeps track of the TPM session. It is issued by the TPM,
  // and is only modified when a new TPM session is started using
  // StartBoundSession or StartUnboundSession. We use this to keep track of
  // the session handle, so that we can clean it up when this class is
  // destroyed.
  TPM_HANDLE session_handle_;

  // A tempary salting key that will be used for the case that the persistent
  // salting key doesn't exist.
  ScopedKeyHandle temp_salting_key_;
  std::optional<TPM2B_PUBLIC> temp_salting_key_public_data_;

  friend class SessionManagerTest;
};

}  // namespace trunks

#endif  // TRUNKS_SESSION_MANAGER_IMPL_H_
