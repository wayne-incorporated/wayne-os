// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_SIGNATURE_SEALING_STRUCTURES_PROTO_H_
#define CRYPTOHOME_SIGNATURE_SEALING_STRUCTURES_PROTO_H_

#include <optional>

#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <cryptohome/proto_bindings/key.pb.h>

#include "cryptohome/flatbuffer_schemas/structures.h"
#include "cryptohome/signature_sealed_data.pb.h"
#include "cryptohome/vault_keyset.pb.h"

namespace cryptohome {
namespace proto {

ChallengeSignatureAlgorithm ToProto(structure::ChallengeSignatureAlgorithm obj);
structure::ChallengeSignatureAlgorithm FromProto(
    ChallengeSignatureAlgorithm obj);

std::optional<structure::ChallengeSignatureAlgorithm> FromProto(
    user_data_auth::SmartCardSignatureAlgorithm obj);

SignatureSealedData ToProto(const hwsec::SignatureSealedData& obj);
hwsec::SignatureSealedData FromProto(const SignatureSealedData& obj);

SerializedVaultKeyset_SignatureChallengeInfo ToProto(
    const structure::SignatureChallengeInfo& obj);
structure::SignatureChallengeInfo FromProto(
    const SerializedVaultKeyset_SignatureChallengeInfo& obj);

ChallengePublicKeyInfo ToProto(const structure::ChallengePublicKeyInfo& obj);
structure::ChallengePublicKeyInfo FromProto(const ChallengePublicKeyInfo& obj);

}  // namespace proto
}  // namespace cryptohome

#endif  // CRYPTOHOME_SIGNATURE_SEALING_STRUCTURES_PROTO_H_
