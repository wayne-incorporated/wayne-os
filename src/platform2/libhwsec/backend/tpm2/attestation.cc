// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/attestation.h"

#include <memory>
#include <optional>
#include <string>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <crypto/scoped_openssl_types.h>
#include <crypto/sha2.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <trunks/tpm_generated.h>

#include "libhwsec/backend/tpm2/static_utils.h"
#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/status.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::status::MakeStatus;
using trunks::TPM_RC;
using trunks::TPM_RC_SUCCESS;

namespace hwsec {

StatusOr<attestation::Quote> AttestationTpm2::Quote(
    DeviceConfigs device_configs, Key key) {
  if (device_configs.none()) {
    return MakeStatus<TPMError>("No device config specified",
                                TPMRetryAction::kNoRetry);
  }

  attestation::Quote quote;
  ASSIGN_OR_RETURN(const KeyTpm2& key_data, key_management_.GetKeyData(key));
  ASSIGN_OR_RETURN(const ConfigTpm2::PcrMap& pcr_map,
                   config_.ToPcrMap(device_configs),
                   _.WithStatus<TPMError>("Failed to get PCR map"));

  if (pcr_map.size() == 1) {
    int pcr = pcr_map.begin()->first;
    ASSIGN_OR_RETURN(const std::string& value, config_.ReadPcr(pcr),
                     _.WithStatus<TPMError>("Failed to read PCR"));
    quote.set_quoted_pcr_value(value);
  }

  std::unique_ptr<trunks::AuthorizationDelegate> delegate =
      context_.GetTrunksFactory().GetPasswordAuthorization("");

  trunks::TPMT_SIG_SCHEME scheme;
  scheme.details.any.hash_alg = trunks::TPM_ALG_SHA256;
  ASSIGN_OR_RETURN(scheme.scheme,
                   signing_.GetSignAlgorithm(key_data, SigningOptions{}),
                   _.WithStatus<TPMError>("Failed to get signing algorithm"));

  trunks::TPML_PCR_SELECTION pcr_select;
  pcr_select.count = 1;
  ASSIGN_OR_RETURN(pcr_select.pcr_selections[0],
                   config_.ToPcrSelection(device_configs),
                   _.WithStatus<TPMError>(
                       "Failed to convert device configs to PCR selection"));

  const trunks::TPM_HANDLE& key_handle = key_data.key_handle;
  std::string key_name;
  RETURN_IF_ERROR(MakeStatus<TPM2Error>(context_.GetTpmUtility().GetKeyName(
                      key_handle, &key_name)))
      .WithStatus<TPMError>("Failed to get key name");

  trunks::TPM2B_ATTEST quoted_struct;
  trunks::TPMT_SIGNATURE signature;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTrunksFactory().GetTpm()->QuoteSync(
          key_handle, key_name,
          trunks::Make_TPM2B_DATA("") /* No qualifying data */, scheme,
          pcr_select, &quoted_struct, &signature, delegate.get())))
      .WithStatus<TPMError>("Failed to quote");

  if (device_configs[DeviceConfig::kDeviceModel]) {
    if (StatusOr<std::string> hwid = config_.GetHardwareID(); !hwid.ok()) {
      LOG(WARNING) << "Failed to get Hardware ID: " << hwid.status();
    } else {
      quote.set_pcr_source_hint(hwid.value());
    }
  }
  ASSIGN_OR_RETURN(const std::string& sig,
                   SerializeFromTpmSignature(signature));
  quote.set_quote(sig);

  if (quoted_struct.size > sizeof(quoted_struct.attestation_data)) {
    return MakeStatus<TPMError>("Quoted struct overflow",
                                TPMRetryAction::kNoRetry);
  }
  quote.set_quoted_data(StringFrom_TPM2B_ATTEST(quoted_struct));

  return quote;
}

// TODO(b/141520502): Verify the quote against expected output.
StatusOr<bool> AttestationTpm2::IsQuoted(DeviceConfigs device_configs,
                                         const attestation::Quote& quote) {
  if (device_configs.none()) {
    return MakeStatus<TPMError>("No device config specified",
                                TPMRetryAction::kNoRetry);
  }
  if (!quote.has_quoted_data()) {
    return MakeStatus<TPMError>("Invalid attestation::Quote",
                                TPMRetryAction::kNoRetry);
  }

  std::string quoted_data = quote.quoted_data();

  trunks::TPMS_ATTEST quoted_struct;
  RETURN_IF_ERROR(MakeStatus<TPM2Error>(trunks::Parse_TPMS_ATTEST(
                      &quoted_data, &quoted_struct, nullptr)))
      .WithStatus<TPMError>("Failed to parse TPMS_ATTEST");

  if (quoted_struct.magic != trunks::TPM_GENERATED_VALUE) {
    return MakeStatus<TPMError>("Bad magic value", TPMRetryAction::kNoRetry);
  }
  if (quoted_struct.type != trunks::TPM_ST_ATTEST_QUOTE) {
    return MakeStatus<TPMError>("Not a quote", TPMRetryAction::kNoRetry);
  }

  const trunks::TPML_PCR_SELECTION& pcr_select =
      quoted_struct.attested.quote.pcr_select;
  if (pcr_select.count != 1) {
    return MakeStatus<TPMError>("Wrong number of PCR selection",
                                TPMRetryAction::kNoRetry);
  }
  const trunks::TPMS_PCR_SELECTION& pcr_selection =
      pcr_select.pcr_selections[0];

  ASSIGN_OR_RETURN(trunks::TPMS_PCR_SELECTION expected_pcr_selection,
                   config_.ToPcrSelection(device_configs),
                   _.WithStatus<TPMError>(
                       "Failed to convert device configs to PCR selection"));

  if (pcr_selection.sizeof_select != expected_pcr_selection.sizeof_select) {
    return MakeStatus<TPMError>("Size of pcr_selections mismatched",
                                TPMRetryAction::kNoRetry);
  }

  for (int i = 0; i < pcr_selection.sizeof_select; ++i) {
    if (pcr_selection.pcr_select[i] != expected_pcr_selection.pcr_select[i]) {
      return false;
    }
  }
  return true;
}

}  // namespace hwsec
