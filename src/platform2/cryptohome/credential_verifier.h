// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CREDENTIAL_VERIFIER_H_
#define CRYPTOHOME_CREDENTIAL_VERIFIER_H_

#include <string>
#include <utility>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/key_objects.h"

namespace cryptohome {

// General credential verifier interface. Supports both synchronous and
// asynchronous verification. Note that most uses of this should not implement
// this interface directly, and instead should implement one of the "async" or
// "sync" subclasses.
class CredentialVerifier {
 public:
  CredentialVerifier(AuthFactorType auth_factor_type,
                     std::string auth_factor_label,
                     AuthFactorMetadata auth_factor_metadata)
      : auth_factor_type_(auth_factor_type),
        auth_factor_label_(std::move(auth_factor_label)),
        auth_factor_metadata_(std::move(auth_factor_metadata)) {}

  CredentialVerifier(const CredentialVerifier&) = delete;
  CredentialVerifier& operator=(const CredentialVerifier&) = delete;

  virtual ~CredentialVerifier() = default;

  // Accessors for the properties of the factor the verifier was created for.
  AuthFactorType auth_factor_type() const { return auth_factor_type_; }
  const std::string& auth_factor_label() const { return auth_factor_label_; }
  const AuthFactorMetadata& auth_factor_metadata() const {
    return auth_factor_metadata_;
  }

  // Verifies an input against the verifier's internal credentials.
  //
  // This function comes in both synchronous and asynchronous forms. The async
  // form will return through the Status callback, while the synchronous form
  // will just return a yes/no boolean directly.
  //
  // If a verifier can be implemented synchronously without blocking, then both
  // versions of Verify will work. If the verifier cannot be implemented
  // synchronously, then only the async version will function normally; the sync
  // version will always return false.
  virtual bool Verify(const AuthInput& input) const = 0;
  virtual void Verify(const AuthInput& input,
                      StatusCallback callback) const = 0;

 private:
  const AuthFactorType auth_factor_type_;
  const std::string auth_factor_label_;
  const AuthFactorMetadata auth_factor_metadata_;
};

// Abstract base implementation of a synchronous verifier.
class SyncCredentialVerifier : public CredentialVerifier {
 public:
  using CredentialVerifier::CredentialVerifier;

  // The Verify interface is implemented by calling VerifySync.
  bool Verify(const AuthInput& input) const final;
  void Verify(const AuthInput& input, StatusCallback callback) const final;

 private:
  // Synchronous implementation of "Verify". Should return OK on successful
  // verification, false otherwise.
  virtual CryptohomeStatus VerifySync(const AuthInput& input) const = 0;
};

// Abstract base implementation of an asynchronous verifier.
class AsyncCredentialVerifier : public CredentialVerifier {
 public:
  using CredentialVerifier::CredentialVerifier;

  // The Verify interface is implemented by calling VerifySync.
  bool Verify(const AuthInput& input) const final;
  void Verify(const AuthInput& input, StatusCallback callback) const final;

 private:
  // Asynchronous implementation of "Verify". Should implement the exact same
  // interface that the two-argument Verify is expected to implement.
  virtual void VerifyAsync(const AuthInput& input,
                           StatusCallback callback) const = 0;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CREDENTIAL_VERIFIER_H_
