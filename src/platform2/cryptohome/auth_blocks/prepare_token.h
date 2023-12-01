// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_PREPARE_TOKEN_H_
#define CRYPTOHOME_AUTH_BLOCKS_PREPARE_TOKEN_H_

#include <memory>
#include <utility>

#include <base/functional/callback.h>
#include <libhwsec-foundation/status/status_chain.h>

#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/error/cryptohome_error.h"

namespace cryptohome {

// Token that represents an active prepared auth factor. The token can be used
// to terminate the factor, and should automatically do so upon destruction.
//
// Note to subclass implementers: you should include a TerminateOnDestruction
// member in your subclass, to ensure you get the correct destructor behavior.
class PreparedAuthFactorToken {
 public:
  // Standard callback for function that accept a token. The callback will be
  // passed either a valid token on success, or a not-OK status on failure.
  using Consumer = base::OnceCallback<void(
      CryptohomeStatusOr<std::unique_ptr<PreparedAuthFactorToken>>)>;

  // Tokens cannot be copied, since they represent a unique active factor. When
  // they are destroyed they will automatically terminate the factor, although
  // the Status of this termination is lost in that case.
  explicit PreparedAuthFactorToken(AuthFactorType auth_factor_type)
      : auth_factor_type_(auth_factor_type) {}
  PreparedAuthFactorToken(const PreparedAuthFactorToken&) = delete;
  PreparedAuthFactorToken& operator=(const PreparedAuthFactorToken&) = delete;
  virtual ~PreparedAuthFactorToken() = default;

  // The type of the auth factor that this token is used for.
  AuthFactorType auth_factor_type() const { return auth_factor_type_; }

  // Terminate the factor. Returns a status reporting any errors with the
  // termination process, but note that the factor is considered terminated
  // after the call regardless of the result. Subsequent calls to terminate will
  // do nothing and return OK.
  CryptohomeStatus Terminate() {
    if (!terminated_) {
      terminated_ = true;
      return TerminateAuthFactor();
    }
    return ::hwsec_foundation::status::OkStatus<error::CryptohomeError>();
  }

 protected:
  // Helpful RAII style class that will ensure that Terminate() is called upon
  // destruction. Subclasses should include this as their last member. Making it
  // the last member is important because you'll almost certainly want your
  // TerminateAuthFactor implementation to be called before any of the other
  // member variables are destroyed.
  class TerminateOnDestruction {
   public:
    explicit TerminateOnDestruction(PreparedAuthFactorToken& token)
        : token_(token) {}
    TerminateOnDestruction(const TerminateOnDestruction&) = delete;
    TerminateOnDestruction& operator=(const TerminateOnDestruction&) = delete;
    ~TerminateOnDestruction() { static_cast<void>(token_.Terminate()); }

   private:
    PreparedAuthFactorToken& token_;
  };

 private:
  // Override in subclasses to implement termination. Will be called exactly
  // once in the lifetime of the token.
  virtual CryptohomeStatus TerminateAuthFactor() = 0;

  bool terminated_ = false;
  const AuthFactorType auth_factor_type_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_PREPARE_TOKEN_H_
