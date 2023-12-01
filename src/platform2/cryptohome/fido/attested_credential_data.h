// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FIDO_ATTESTED_CREDENTIAL_DATA_H_
#define CRYPTOHOME_FIDO_ATTESTED_CREDENTIAL_DATA_H_

#include <memory>
#include <optional>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include "base/component_export.h"
#include "base/containers/span.h"
#include "cryptohome/fido/fido_constants.h"

namespace cryptohome {
namespace fido_device {

class PublicKey;

// https://www.w3.org/TR/2017/WD-webauthn-20170505/#sec-attestation-data
class AttestedCredentialData {
 public:
  // Parses an |AttestedCredentialData| from a prefix of |*buffer|. Returns
  // nullopt on error, or else the parse return and a (possibly empty) suffix of
  // |buffer| that was not parsed.
  static std::optional<
      std::pair<AttestedCredentialData, base::span<const uint8_t>>>
  ConsumeFromCtapResponse(base::span<const uint8_t> buffer);

  static std::optional<AttestedCredentialData> CreateFromU2fRegisterResponse(
      base::span<const uint8_t> u2f_data,
      std::unique_ptr<PublicKey> public_key);

  // Moveable.
  AttestedCredentialData(AttestedCredentialData&& other);
  AttestedCredentialData& operator=(AttestedCredentialData&& other);

  ~AttestedCredentialData();

  const std::vector<uint8_t>& credential_id() const { return credential_id_; }

  // Returns true iff the AAGUID is all zero bytes.
  bool IsAaguidZero() const;

  const PublicKey* GetPublicKey() const;

  // Invoked when sending "none" attestation statement to the relying party.
  // Replaces AAGUID with zero bytes.
  void DeleteAaguid();

  // Produces a byte array consisting of:
  // * AAGUID (16 bytes)
  // * Len (2 bytes)
  // * Credential Id (Len bytes)
  // * Credential Public Key.
  std::vector<uint8_t> SerializeAsBytes() const;

  AttestedCredentialData(
      base::span<const uint8_t, kAaguidLength> aaguid,
      base::span<const uint8_t, kCredentialIdLengthLength> credential_id_length,
      std::vector<uint8_t> credential_id,
      std::unique_ptr<PublicKey> public_key);
  AttestedCredentialData(const AttestedCredentialData&) = delete;
  AttestedCredentialData& operator=(const AttestedCredentialData&) = delete;

  uint16_t GetCredentialIdLength();

  std::string ToString();

 private:
  // The 16-byte AAGUID of the authenticator.
  std::array<uint8_t, kAaguidLength> aaguid_;

  // Big-endian length of the credential (i.e. key handle).
  std::array<uint8_t, kCredentialIdLengthLength> credential_id_length_;

  std::vector<uint8_t> credential_id_;

  std::unique_ptr<PublicKey> public_key_;
};

}  // namespace fido_device
}  // namespace cryptohome

#endif  // CRYPTOHOME_FIDO_ATTESTED_CREDENTIAL_DATA_H_
