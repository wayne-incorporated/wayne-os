// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_H_
#define CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_H_

#include <memory>
#include <optional>
#include <string>

#include <libhwsec-foundation/status/status_chain_or.h>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/storage/file_system_keyset.h"

namespace cryptohome {

// An AuthFactor is a value that identifies a particular instance of a factor by
// type and label and which contains a copy of all of the metadata and block
// state.
class AuthFactor {
 public:
  AuthFactor(AuthFactorType type,
             const std::string& label,
             const AuthFactorMetadata& metadata,
             const AuthBlockState& auth_block_state);

  AuthFactor(const AuthFactor&) = default;
  AuthFactor& operator=(const AuthFactor&) = default;
  AuthFactor(AuthFactor&&) = default;
  AuthFactor& operator=(AuthFactor&&) = default;

  ~AuthFactor() = default;

  const AuthFactorType& type() const { return type_; }
  const std::string& label() const { return label_; }
  const AuthFactorMetadata& metadata() const { return metadata_; }
  const AuthBlockState& auth_block_state() const { return auth_block_state_; }

 private:
  // The auth factor public information.
  AuthFactorType type_;
  std::string label_;
  AuthFactorMetadata metadata_;
  // Contains the data that the auth factor needs for deriving the secret.
  AuthBlockState auth_block_state_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_H_
