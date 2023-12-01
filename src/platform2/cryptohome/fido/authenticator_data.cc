// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fido/authenticator_data.h"

#include <optional>

#include <base/big_endian.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/cbor/diagnostic_writer.h>
#include <chromeos/cbor/reader.h>
#include <chromeos/cbor/writer.h>
#include <sstream>
#include <utility>

#include "cryptohome/fido/attested_credential_data.h"
#include "cryptohome/fido/fido_parsing_utils.h"
#include "cryptohome/fido/utils.h"

namespace cryptohome {
namespace fido_device {

namespace {

constexpr size_t kAttestedCredentialDataOffset =
    kRpIdHashLength + kFlagsLength + kSignCounterLength;
}  // namespace

// static
std::optional<AuthenticatorData> AuthenticatorData::DecodeAuthenticatorData(
    base::span<const uint8_t> auth_data) {
  if (auth_data.size() < kAttestedCredentialDataOffset)
    return std::nullopt;
  auto application_parameter = auth_data.first<kRpIdHashLength>();
  uint8_t flag_byte = auth_data[kRpIdHashLength];
  auto counter =
      auth_data.subspan<kRpIdHashLength + kFlagsLength, kSignCounterLength>();

  auth_data = auth_data.subspan(kAttestedCredentialDataOffset);
  std::optional<AttestedCredentialData> attested_credential_data;
  if (flag_byte & static_cast<uint8_t>(Flag::kAttestation)) {
    auto maybe_result =
        AttestedCredentialData::ConsumeFromCtapResponse(auth_data);
    if (!maybe_result) {
      return std::nullopt;
    }
    std::tie(attested_credential_data, auth_data) = std::move(*maybe_result);
  }

  std::optional<cbor::Value> extensions;
  if (flag_byte & static_cast<uint8_t>(Flag::kExtensionDataIncluded)) {
    cbor::Reader::DecoderError error;
    extensions = cbor::Reader::Read(auth_data, &error);
    if (!extensions) {
      LOG(ERROR) << "CBOR decoding of authenticator data extensions failed ("
                 << cbor::Reader::ErrorCodeToString(error) << ") from "
                 << base::HexEncode(auth_data.data(), auth_data.size());
      return std::nullopt;
    }
    if (!extensions->is_map()) {
      LOG(ERROR) << "Incorrect CBOR structure of authenticator data extensions";
      return std::nullopt;
    }
  } else if (!auth_data.empty()) {
    return std::nullopt;
  }

  return AuthenticatorData(application_parameter, flag_byte, counter,
                           std::move(attested_credential_data),
                           std::move(extensions));
}

// static
std::optional<AuthenticatorData> AuthenticatorData::ParseMakeCredentialResponse(
    const std::vector<uint8_t>& input) {
  base::span<const uint8_t> buffer(input.data(), input.size());
  // The response is an attestation object.
  std::optional<cbor::Value> attestation_obj = cbor::Reader::Read(buffer);
  if (!attestation_obj || !attestation_obj->is_map()) {
    LOG(ERROR) << "Attestation object is not a CBOR map.";
    return std::nullopt;
  }
  const auto& attestation_obj_map = attestation_obj->GetMap();

  // format
  auto it = attestation_obj_map.find(cbor::Value(kFormatKey));
  if (it == attestation_obj_map.end()) {
    LOG(ERROR) << "Missing format key.";
    return std::nullopt;
  }
  if (!it->second.is_string()) {
    LOG(ERROR) << "Invalid format.";
    return std::nullopt;
  }
  std::string format = it->second.GetString();

  // authenticator data
  it = attestation_obj_map.find(cbor::Value(kAuthDataKey));
  if (it == attestation_obj_map.end() || !it->second.is_bytestring()) {
    LOG(ERROR) << "Invalid AuthData value type.";
    return std::nullopt;
  }
  std::vector<uint8_t> auth_data_buffer(it->second.GetBytestring());
  base::span<const uint8_t> auth_data(auth_data_buffer.data(),
                                      auth_data_buffer.size());
  auto authenticator_data =
      AuthenticatorData::DecodeAuthenticatorData(auth_data);
  if (!authenticator_data) {
    LOG(INFO) << "Failed to parse authenticator data.";
    return std::nullopt;
  }
  return authenticator_data;
}

AuthenticatorData::AuthenticatorData(
    base::span<const uint8_t, kRpIdHashLength> application_parameter,
    uint8_t flags,
    base::span<const uint8_t, kSignCounterLength> counter,
    std::optional<AttestedCredentialData> data,
    std::optional<cbor::Value> extensions)
    : application_parameter_(
          fido_parsing_utils::Materialize(application_parameter)),
      flags_(flags),
      counter_(fido_parsing_utils::Materialize(counter)),
      attested_data_(std::move(data)),
      extensions_(std::move(extensions)) {
  DCHECK(!extensions_ || extensions_->is_map());
  DCHECK_EQ((flags_ & static_cast<uint8_t>(Flag::kExtensionDataIncluded)) != 0,
            !!extensions_);
  DCHECK_EQ(((flags_ & static_cast<uint8_t>(Flag::kAttestation)) != 0),
            !!attested_data_);
}

AuthenticatorData::AuthenticatorData(AuthenticatorData&& other) = default;
AuthenticatorData& AuthenticatorData::operator=(AuthenticatorData&& other) =
    default;

AuthenticatorData::~AuthenticatorData() = default;

void AuthenticatorData::DeleteDeviceAaguid() {
  if (!attested_data_)
    return;

  attested_data_->DeleteAaguid();
}

std::vector<uint8_t> AuthenticatorData::SerializeToByteArray() const {
  std::vector<uint8_t> authenticator_data;
  fido_parsing_utils::Append(&authenticator_data, application_parameter_);
  authenticator_data.insert(authenticator_data.end(), flags_);
  fido_parsing_utils::Append(&authenticator_data, counter_);

  if (attested_data_) {
    // Attestations are returned in registration responses but not in assertion
    // responses.
    fido_parsing_utils::Append(&authenticator_data,
                               attested_data_->SerializeAsBytes());
  }

  if (extensions_) {
    const auto maybe_extensions = cbor::Writer::Write(*extensions_);
    if (maybe_extensions) {
      fido_parsing_utils::Append(&authenticator_data, *maybe_extensions);
    }
  }

  return authenticator_data;
}

unsigned int AuthenticatorData::GetCounter() {
  uint32_t counter;
  fido::ReadBigEndian<uint32_t>(reinterpret_cast<const char*>(&counter_[0]),
                                &counter);
  return counter;
}

std::string AuthenticatorData::PrintFlags() {
  std::stringstream ss;
  ss << "[UP:" << obtained_user_presence() << "|"
     << "UV: " << obtained_user_verification() << "|"
     << "AT:" << attestation_credential_included() << "|"
     << "ED: " << extension_data_included() << "]";
  return ss.str();
}

std::string AuthenticatorData::ToString() {
  std::stringstream ss;
  ss << "flags: " << PrintFlags() << ", ";
  ss << "counter: " << GetCounter() << ", ";
  ss << "attested data: " << attested_data_->ToString();
  return ss.str();
}

std::vector<uint8_t> AuthenticatorData::GetCredentialId() const {
  if (!attested_data_)
    return std::vector<uint8_t>();
  return attested_data_->credential_id();
}

}  // namespace fido_device
}  // namespace cryptohome
