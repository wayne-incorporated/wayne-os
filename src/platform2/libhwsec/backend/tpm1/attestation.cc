// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/attestation.h"

#include <arpa/inet.h>
#include <base/hash/sha1.h>
#include <base/sys_byteorder.h>
#include <string>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

constexpr unsigned int kDigestSize = sizeof(TPM_DIGEST);
constexpr size_t kSelectBitmapSize = 2;

// Builds the serialized TPM_PCR_COMPOSITE stream, where |pcr_index| is the PCR
// index, and |quoted_pcr_value| is the value of the register.
StatusOr<std::string> buildPcrComposite(uint32_t pcr_index,
                                        const std::string& quoted_pcr_value) {
  if (pcr_index < kSelectBitmapSize * 8) {
    return MakeStatus<TPMError>("PCR index is out of range",
                                TPMRetryAction::kNoRetry);
  }
  // Builds the PCR composite header.
  struct __attribute__((packed)) {
    // Corresponding to TPM_PCR_SELECTION.sizeOfSelect.
    uint16_t select_size;
    // Corresponding to TPM_PCR_SELECTION.pcrSelect.
    uint8_t select_bitmap[kSelectBitmapSize];
    // Corresponding to  TPM_PCR_COMPOSITE.valueSize.
    uint32_t value_size;
  } composite_header = {0};
  static_assert(sizeof(composite_header) ==
                    sizeof(uint16_t) + kSelectBitmapSize + sizeof(uint32_t),
                "Expect no padding between composite struct.");
  // Sets to 2 bytes.
  composite_header.select_size = base::HostToNet16(2u);
  composite_header.select_bitmap[pcr_index / 8] = 1 << (pcr_index % 8);
  composite_header.value_size = base::HostToNet32(quoted_pcr_value.size());
  const char* buffer = reinterpret_cast<const char*>(&composite_header);
  return std::string(buffer, sizeof(composite_header)) + quoted_pcr_value;
}

}  // namespace

StatusOr<attestation::Quote> AttestationTpm1::Quote(
    DeviceConfigs device_configs, Key key) {
  if (device_configs.none()) {
    return MakeStatus<TPMError>("Quote with no device config specified",
                                TPMRetryAction::kNoRetry);
  }

  attestation::Quote quote;
  ASSIGN_OR_RETURN(const ConfigTpm1::PcrMap& pcr_map,
                   config_.ToPcrMap(device_configs),
                   _.WithStatus<TPMError>("Failed to get PCR map"));
  if (pcr_map.size() == 1) {
    int pcr = pcr_map.begin()->first;
    ASSIGN_OR_RETURN(const brillo::Blob& value, config_.ReadPcr(pcr),
                     _.WithStatus<TPMError>("Failed to read PCR"));
    quote.set_quoted_pcr_value(BlobToString(value));
  }

  ASSIGN_OR_RETURN(ScopedTssPcrs && pcr_select,
                   config_.ToPcrSelection(device_configs),
                   _.WithStatus<TPMError>(
                       "Failed to convert device configs to PCR selection"));

  ASSIGN_OR_RETURN(const KeyTpm1& key_data, key_management_.GetKeyData(key));
  ASSIGN_OR_RETURN(TSS_HTPM tpm_handle, tss_helper_.GetUserTpmHandle());
  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());
  // Generate the quote.
  TSS_VALIDATION validation = {};
  // Here we use well-known string value for consistency with AttestationTpm2,
  // which doesn't supply any qualifying data from caller while in TPM 1.2
  // it's required to have non-empty external data.
  BYTE well_known_external_data[kDigestSize] = {};
  validation.ulExternalDataLength = kDigestSize;
  validation.rgbExternalData = well_known_external_data;
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_TPM_Quote(
          tpm_handle, key_data.key_handle, pcr_select, &validation)))
      .WithStatus<TPMError>("Failed to call Ospi_TPM_Quote");
  ScopedTssMemory scoped_signed_data(overalls_, context, validation.rgbData);
  ScopedTssMemory scoped_signature(overalls_, context,
                                   validation.rgbValidationData);

  if (device_configs[DeviceConfig::kDeviceModel]) {
    if (StatusOr<std::string> hwid = config_.GetHardwareID(); !hwid.ok()) {
      LOG(WARNING) << "Failed to get Hardware ID: " << hwid.status();
    } else {
      quote.set_pcr_source_hint(hwid.value());
    }
  }
  quote.set_quoted_data(std::string(
      validation.rgbData, validation.rgbData + validation.ulDataLength));
  quote.set_quote(std::string(
      validation.rgbValidationData,
      validation.rgbValidationData + validation.ulValidationDataLength));

  return quote;
}

StatusOr<bool> AttestationTpm1::IsQuoted(DeviceConfigs device_configs,
                                         const attestation::Quote& quote) {
  if (device_configs.none()) {
    return MakeStatus<TPMError>("No device config specified",
                                TPMRetryAction::kNoRetry);
  }
  if (device_configs.count() > 1) {
    return MakeStatus<TPMError>(
        "Verifying quote for Multiple device configs is unsupported",
        TPMRetryAction::kNoRetry);
  }
  if (!quote.has_quoted_pcr_value() || !quote.has_quoted_data()) {
    return MakeStatus<TPMError>("Invalid attestation::Quote",
                                TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(const ConfigTpm1::PcrMap& pcr_map,
                   config_.ToPcrMap(device_configs),
                   _.WithStatus<TPMError>("Failed to get PCR map"));
  if (pcr_map.size() != 1) {
    return MakeStatus<TPMError>("Wrong number of PCR specified",
                                TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(
      const std::string& pcr_composite,
      buildPcrComposite(pcr_map.begin()->first, quote.quoted_pcr_value()));
  // Checks that the quoted value matches the given PCR value by reconstructing
  // the TPM_PCR_COMPOSITE structure the TPM would create.
  const std::string pcr_digest = base::SHA1HashString(pcr_composite);

  const std::string signed_data = quote.quoted_data();
  // The PCR digest should appear starting at 8th byte of the quoted data. See
  // the TPM_QUOTE_INFO structure.
  if (signed_data.length() < pcr_digest.length() + 8) {
    return MakeStatus<TPMError>("Quoted data is too short",
                                TPMRetryAction::kNoRetry);
  }
  if (!std::equal(pcr_digest.begin(), pcr_digest.end(),
                  signed_data.begin() + 8)) {
    return false;
  }
  return true;
}

}  // namespace hwsec
