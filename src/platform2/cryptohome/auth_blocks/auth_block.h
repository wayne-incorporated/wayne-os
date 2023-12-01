// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_AUTH_BLOCK_H_
#define CRYPTOHOME_AUTH_BLOCKS_AUTH_BLOCK_H_

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <base/functional/callback.h>

#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/vault_keyset.h"

namespace cryptohome {

// Defined in cryptohome_metrics.h
enum DerivationType : int;

// This is a pure virtual interface designed to be implemented by the different
// authentication methods - U2F, PinWeaver, TPM backed passwords, etc. - so that
// they take some arbitrary user input and give out a key.
class AuthBlock {
 public:
  // Enumeration used during derive operations to indicate suggested actions for
  // auth blocks which are valid but sub-optimal in some way (e.g. the block is
  // using an old or obsolete format, or a weaker policy).
  enum class SuggestedAction {
    // Indicates that it would be best to re-create the block. This is usually
    // used when the block is obsolete in some manner that can be fixed by
    // replacing the existing block with a freshly created one. Note that as a
    // side effect this may even change the block type of the factor.
    kRecreate,
  };

  virtual ~AuthBlock() = default;

  // If the operation succeeds, |key_blobs| will contain the constructed
  // KeyBlobs, AuthBlockState will be populated in |auth_block_state| and
  // |error| will be an ok status. On failure, error will be populated,
  // and should not rely on the value of key_blobs and auth_block_state.
  using CreateCallback = base::OnceCallback<void(
      CryptohomeStatus error,
      std::unique_ptr<KeyBlobs> key_blobs,
      std::unique_ptr<AuthBlockState> auth_block_state)>;

  // This is implemented by concrete auth methods to create a fresh key from
  // user input.
  // This asynchronous API receives a callback to construct the KeyBlobs with
  // the released TPM secrets in an unblocking way. Once the callback is done,
  // on success, error will be an ok status, KeyBlobs and AuthBlockState will be
  // populated. On Failure, the error is assigned the related error value, the
  // value of KeyBlobs and AuthBlockState are not valid to use.
  virtual void Create(const AuthInput& user_input, CreateCallback callback) = 0;

  // On success, |error| will be OK and |key_blobs| will be populated with the
  // derived key. The value of |suggested_action| may also be set if there are
  // any suggested actions with the block, but even if this is set the result of
  // the derivation is still considered valid. On failure, |error| will be
  // populated and both |key_blobs| and |suggested_action| are undefined.
  using DeriveCallback =
      base::OnceCallback<void(CryptohomeStatus error,
                              std::unique_ptr<KeyBlobs> key_blobs,
                              std::optional<SuggestedAction> suggested_action)>;

  // This is implemented by concrete auth methods to map the user secret
  // input/credentials into a key.
  // This asynchronous API receives a callback to construct the KeyBlobs with
  // the released TPM secrets in an unblocking way. Once the callback is done,
  // on success, error will be an ok status, KeyBlobs will be populated. On
  // Failure, error is assigned the related error value, the value of KeyBlobs
  // are not valid to use.
  virtual void Derive(const AuthInput& auth_input,
                      const AuthBlockState& state,
                      DeriveCallback callback) = 0;

  // This is optionally implemented by concrete auth factor methods which need
  // to execute additional steps before removal of the AuthFactor from disk.
  virtual void PrepareForRemoval(const AuthBlockState& state,
                                 StatusCallback callback) {
    // By default, do nothing. Subclasses can provide custom behavior.
    return std::move(callback).Run(
        hwsec_foundation::status::OkStatus<error::CryptohomeCryptoError>());
  }

  // If the operation succeeds, |auth_input| will contain the constructed
  // AuthInput used for Derive, |auth_factor| will contain the selected
  // AuthFactor, and |error| will be an ok status. On failure, error will be
  // populated, and should not rely on the value of auth_input and auth_factor.
  using SelectFactorCallback =
      base::OnceCallback<void(CryptohomeStatus error,
                              std::optional<AuthInput> auth_input,
                              std::optional<AuthFactor> auth_factor)>;

  // This asynchronous API receives a callback to construct the AuthInput used
  // for deriving key blobs, and to select the correct AuthFactor that should be
  // used for deriving the key blobs in the candidates |auth_factors|.
  virtual void SelectFactor(const AuthInput& auth_input,
                            std::vector<AuthFactor> auth_factors,
                            SelectFactorCallback callback) {
    std::move(callback).Run(
        hwsec_foundation::status::MakeStatus<error::CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocAuthBlockSelectFactorNotSupported),
            error::ErrorActionSet(
                {error::PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        std::nullopt, std::nullopt);
  }

  DerivationType derivation_type() const { return derivation_type_; }

 protected:
  // This is a virtual interface that should not be directly constructed.
  explicit AuthBlock(DerivationType derivation_type)
      : derivation_type_(derivation_type) {}

 private:
  // For UMA - keeps track of the encryption type used in Derive().
  const DerivationType derivation_type_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_AUTH_BLOCK_H_
