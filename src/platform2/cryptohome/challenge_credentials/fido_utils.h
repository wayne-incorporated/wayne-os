// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains utility functions to create FIDO MakeCredential and
// GetAssertion requests.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_FIDO_UTILS_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_FIDO_UTILS_H_

#include <memory>
#include <string>
#include <vector>

#include <base/time/time.h>
#include <cryptohome/proto_bindings/fido.pb.h>
#include <cryptohome/proto_bindings/rpc.pb.h>

namespace cryptohome {

using FidoPKCredCreationOptionsPtr =
    std::unique_ptr<cryptohome::fido::PublicKeyCredentialCreationOptions>;
using FidoPKCredRequestOptionsPtr =
    std::unique_ptr<cryptohome::fido::PublicKeyCredentialRequestOptions>;

// This function maps a Chrome OS user id to a FIDO security key user id.
// FIDO standard requires a 32-byte id but Chrome OS account_id is of
// variable length. The FIDO user id is calculated as
// SHA256(account_id).
std::vector<uint8_t> GetFidoUserId(const std::string& account_id);

FidoPKCredCreationOptionsPtr BuildFidoMakeCredentialOptions(
    std::unique_ptr<cryptohome::fido::PublicKeyCredentialUserEntity> user,
    std::unique_ptr<cryptohome::fido::PublicKeyCredentialRpEntity> rp,
    std::vector<uint8_t> challenge,
    std::vector<cryptohome::fido::PublicKeyCredentialDescriptor>
        exclude_credentials,
    base::TimeDelta adjusted_timeout,
    std::unique_ptr<cryptohome::fido::CableRegistration>
        cable_registration_data,
    cryptohome::fido::ProtectionPolicy protection_policy,
    bool use_hmac_secret, /* create hmac_secret */
    bool enforce_protection_policy,
    std::string appid_exclude);

// Create FIDO MakeCredential option with default settings. Returns nullptr
// if error happens. The caller should check the return value.
FidoPKCredCreationOptionsPtr BuildFidoMakeCredentialOptions(
    const cryptohome::AccountIdentifier& account,
    const std::vector<uint8_t>& challenge,
    bool create_hmac_secret);

// Create GetAssertion option.
FidoPKCredRequestOptionsPtr BuildFidoGetAssertionOptions(
    std::vector<uint8_t> challenge,
    int64_t adjusted_timeout,
    std::string relying_party_id,
    std::vector<cryptohome::fido::PublicKeyCredentialDescriptor>
        allow_credentials,
    std::string appid,
    std::vector<cryptohome::fido::CableAuthentication>
        cable_authentication_data);

// Create GetAssertion option with default settings.
FidoPKCredRequestOptionsPtr BuildFidoGetAssertionOptions(
    std::vector<uint8_t> challenge,
    std::string relying_party_id,
    std::string appid);

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_FIDO_UTILS_H_
