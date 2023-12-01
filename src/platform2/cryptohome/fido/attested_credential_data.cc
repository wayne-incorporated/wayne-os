// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fido/attested_credential_data.h"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>

#include <base/numerics/safe_math.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/cbor/reader.h>

#include "cryptohome/fido/ec_public_key.h"
#include "cryptohome/fido/fido_constants.h"
#include "cryptohome/fido/fido_parsing_utils.h"
#include "cryptohome/fido/public_key.h"
#include "cryptohome/fido/utils.h"

namespace cryptohome {
namespace fido_device {

// static
std::optional<std::pair<AttestedCredentialData, base::span<const uint8_t>>>
AttestedCredentialData::ConsumeFromCtapResponse(
    base::span<const uint8_t> buffer) {
  if (buffer.size() < kAaguidLength)
    return std::nullopt;

  auto aaguid = buffer.first<kAaguidLength>();
  buffer = buffer.subspan(kAaguidLength);

  if (buffer.size() < kCredentialIdLengthLength)
    return std::nullopt;

  auto credential_id_length_span = buffer.first<kCredentialIdLengthLength>();
  const size_t credential_id_length =
      (base::strict_cast<size_t>(credential_id_length_span[0]) << 8) |
      base::strict_cast<size_t>(credential_id_length_span[1]);
  buffer = buffer.subspan(kCredentialIdLengthLength);

  if (buffer.size() < credential_id_length)
    return std::nullopt;

  auto credential_id = buffer.first(credential_id_length);
  buffer = buffer.subspan(credential_id_length);

  // The public key is a CBOR map and is thus variable length. Therefore the
  // CBOR parser needs to be invoked to find its length, even though the result
  // is discarded.
  size_t bytes_read;
  if (!cbor::Reader::Read(buffer, &bytes_read)) {
    return std::nullopt;
  }

  // Only EC Public key is supported for now.
  auto credential_public_key =
      ECPublicKey::ParseECPublicKey(buffer.first(bytes_read));
  if (!credential_public_key)
    return std::nullopt;

  buffer = buffer.subspan(bytes_read);
  return std::make_pair(
      AttestedCredentialData(aaguid, credential_id_length_span,
                             fido_parsing_utils::Materialize(credential_id),
                             std::move(credential_public_key)),
      buffer);
}

// static
std::optional<AttestedCredentialData>
AttestedCredentialData::CreateFromU2fRegisterResponse(
    base::span<const uint8_t> u2f_data, std::unique_ptr<PublicKey> public_key) {
  // TODO(crbug/799075): Introduce a CredentialID class to do this extraction.
  // Extract the length of the credential (i.e. of the U2FResponse key
  // handle). Length is big endian.
  std::vector<uint8_t> extracted_length =
      fido_parsing_utils::Extract(u2f_data, kU2fKeyHandleLengthOffset, 1);

  if (extracted_length.empty()) {
    return std::nullopt;
  }

  // For U2F register request, device AAGUID is set to zeros.
  std::array<uint8_t, kAaguidLength> aaguid = {};

  // Note that U2F responses only use one byte for length.
  std::array<uint8_t, kCredentialIdLengthLength> credential_id_length = {
      0, extracted_length[0]};

  // Extract the credential id (i.e. key handle).
  std::vector<uint8_t> credential_id = fido_parsing_utils::Extract(
      u2f_data, kU2fKeyHandleOffset,
      base::strict_cast<size_t>(credential_id_length[1]));

  if (credential_id.empty()) {
    return std::nullopt;
  }

  return AttestedCredentialData(aaguid, credential_id_length,
                                std::move(credential_id),
                                std::move(public_key));
}

AttestedCredentialData::AttestedCredentialData(AttestedCredentialData&& other) =
    default;

AttestedCredentialData& AttestedCredentialData::operator=(
    AttestedCredentialData&& other) = default;

AttestedCredentialData::~AttestedCredentialData() = default;

bool AttestedCredentialData::IsAaguidZero() const {
  return std::all_of(aaguid_.begin(), aaguid_.end(),
                     [](uint8_t v) { return v == 0; });
}

void AttestedCredentialData::DeleteAaguid() {
  std::fill(aaguid_.begin(), aaguid_.end(), 0);
}

std::vector<uint8_t> AttestedCredentialData::SerializeAsBytes() const {
  std::vector<uint8_t> attestation_data;
  fido_parsing_utils::Append(&attestation_data, aaguid_);
  fido_parsing_utils::Append(&attestation_data, credential_id_length_);
  fido_parsing_utils::Append(&attestation_data, credential_id_);
  fido_parsing_utils::Append(&attestation_data, public_key_->EncodeAsCOSEKey());
  return attestation_data;
}

const PublicKey* AttestedCredentialData::GetPublicKey() const {
  return public_key_.get();
}

uint16_t AttestedCredentialData::GetCredentialIdLength() {
  uint16_t length;
  fido::ReadBigEndian<uint16_t>(
      reinterpret_cast<const char*>(&credential_id_length_[0]), &length);
  return length;
}

std::string AttestedCredentialData::ToString() {
  std::stringstream ss;
  ss << "attested data: {"
     << "aaguid: " << base::HexEncode(aaguid_.data(), aaguid_.size()) << ", "
     << "credential length: " << GetCredentialIdLength() << ", "
     << "credential id: "
     << base::HexEncode(credential_id_.data(), credential_id_.size()) << ", "
     << "credential: " << public_key_->ToString();
  return ss.str();
}

AttestedCredentialData::AttestedCredentialData(
    base::span<const uint8_t, kAaguidLength> aaguid,
    base::span<const uint8_t, kCredentialIdLengthLength> credential_id_length,
    std::vector<uint8_t> credential_id,
    std::unique_ptr<PublicKey> public_key)
    : aaguid_(fido_parsing_utils::Materialize(aaguid)),
      credential_id_length_(
          fido_parsing_utils::Materialize(credential_id_length)),
      credential_id_(std::move(credential_id)),
      public_key_(std::move(public_key)) {}

}  // namespace fido_device
}  // namespace cryptohome
