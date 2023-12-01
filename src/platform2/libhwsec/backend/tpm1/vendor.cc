// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/vendor.h"

#include <cinttypes>
#include <cstdint>
#include <string>
#include <utility>

#include <base/strings/stringprintf.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

#include "libhwsec/backend/tpm1/static_utils.h"
#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/error/tpm_manager_error.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::Sha256;
using hwsec_foundation::TestRocaVulnerable;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

constexpr uint8_t kIfxFieldUpgradeRequest[] = {0x11, 0x00, 0x00};
constexpr uint32_t kFieldUpgradeInfo2Size = 106;

Status ParseIFXFirmwarePackage(
    overalls::Overalls& overalls,
    uint64_t* offset,
    uint8_t* buffer,
    uint64_t capacity,
    IFXFieldUpgradeInfo::FirmwarePackage& firmware_package) {
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Orspi_UnloadBlob_UINT32_s(
      offset, &firmware_package.package_id, buffer, capacity)));
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Orspi_UnloadBlob_UINT32_s(
      offset, &firmware_package.version, buffer, capacity)));
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Orspi_UnloadBlob_UINT32_s(
      offset, &firmware_package.stale_version, buffer, capacity)));
  return OkStatus();
}

}  // namespace

Status VendorTpm1::EnsureVersionInfo() {
  if (version_info_.has_value()) {
    return OkStatus();
  }

  tpm_manager::GetVersionInfoRequest request;
  tpm_manager::GetVersionInfoReply reply;

  if (brillo::ErrorPtr err; !tpm_manager_.GetVersionInfo(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMManagerError>(reply.status()));

  version_info_ = std::move(reply);
  return OkStatus();
}

StatusOr<uint32_t> VendorTpm1::GetFamily() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->family();
}

StatusOr<uint64_t> VendorTpm1::GetSpecLevel() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->spec_level();
}

StatusOr<uint32_t> VendorTpm1::GetManufacturer() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->manufacturer();
}

StatusOr<uint32_t> VendorTpm1::GetTpmModel() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->tpm_model();
}

StatusOr<uint64_t> VendorTpm1::GetFirmwareVersion() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->firmware_version();
}

StatusOr<brillo::Blob> VendorTpm1::GetVendorSpecific() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return brillo::BlobFromString(version_info_->vendor_specific());
}

StatusOr<int32_t> VendorTpm1::GetFingerprint() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  // The exact encoding doesn't matter as long as its unambiguous, stable and
  // contains all information present in the version fields.
  std::string encoded_parameters = base::StringPrintf(
      "%08" PRIx32 "%016" PRIx64 "%08" PRIx32 "%08" PRIx32 "%016" PRIx64
      "%016zx",
      version_info_->family(), version_info_->spec_level(),
      version_info_->manufacturer(), version_info_->tpm_model(),
      version_info_->firmware_version(),
      version_info_->vendor_specific().size());
  encoded_parameters.append(version_info_->vendor_specific());

  brillo::Blob hash = Sha256(brillo::BlobFromString(encoded_parameters));

  // Return the first 31 bits from |hash|.
  uint32_t result = static_cast<uint32_t>(hash[0]) |
                    static_cast<uint32_t>(hash[1]) << 8 |
                    static_cast<uint32_t>(hash[2]) << 16 |
                    static_cast<uint32_t>(hash[3]) << 24;
  return result & 0x7fffffff;
}

StatusOr<bool> VendorTpm1::IsSrkRocaVulnerable() {
  ASSIGN_OR_RETURN(ScopedKey srk,
                   key_management_.GetPersistentKey(
                       KeyManagement::PersistentKeyType::kStorageRootKey));

  ASSIGN_OR_RETURN(const KeyTpm1& srk_data,
                   key_management_.GetKeyData(srk.GetKey()));

  ASSIGN_OR_RETURN(
      const crypto::ScopedRSA& public_srk,
      ParseRsaFromTpmPubkeyBlob(overalls_, srk_data.cache.pubkey_blob),
      _.WithStatus<TPMError>("Failed to parse RSA public key"));

  const BIGNUM* n = nullptr;
  RSA_get0_key(public_srk.get(), &n, nullptr, nullptr);

  return TestRocaVulnerable(n);
}

StatusOr<brillo::Blob> VendorTpm1::GetRsuDeviceId() {
  return MakeStatus<TPMError>("Unsupported command", TPMRetryAction::kNoRetry);
}

StatusOr<IFXFieldUpgradeInfo> VendorTpm1::GetIFXFieldUpgradeInfo() {
  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  ASSIGN_OR_RETURN(TSS_HTPM tpm_handle, tss_helper_.GetUserTpmHandle());

  uint32_t length;
  ScopedTssMemory response(overalls_, context);
  brillo::Blob request(
      kIfxFieldUpgradeRequest,
      kIfxFieldUpgradeRequest + sizeof(kIfxFieldUpgradeRequest));
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_TPM_FieldUpgrade(
          tpm_handle, request.size(), request.data(), &length, response.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_TPM_FieldUpgrade");

  // Parse the response.
  uint64_t offset = 0;
  uint16_t size = 0;
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Orspi_UnloadBlob_UINT16_s(
      &offset, &size, response.value(), length)));

  if (size != length - sizeof(uint16_t)) {
    return MakeStatus<TPMError>("FieldUpgrade response size mismatch",
                                TPMRetryAction::kNoRetry);
  }

  if (size != kFieldUpgradeInfo2Size) {
    return MakeStatus<TPMError>("Unknown FieldUpgrade response size",
                                TPMRetryAction::kNoRetry);
  }

  IFXFieldUpgradeInfo info = {};
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Orspi_UnloadBlob_UINT16_s(
      &offset, nullptr, response.value(), length)));

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Orspi_UnloadBlob_UINT16_s(
      &offset, &info.max_data_size, response.value(), length)));

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Orspi_UnloadBlob_UINT16_s(
      &offset, nullptr, response.value(), length)));

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Orspi_UnloadBlob_UINT32_s(
      &offset, nullptr, response.value(), length)));

  offset += 34;

  RETURN_IF_ERROR(ParseIFXFirmwarePackage(overalls_, &offset, response.value(),
                                          length, info.bootloader));

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Orspi_UnloadBlob_UINT16_s(
      &offset, nullptr, response.value(), length)));

  RETURN_IF_ERROR(ParseIFXFirmwarePackage(overalls_, &offset, response.value(),
                                          length, info.firmware[0]));

  RETURN_IF_ERROR(ParseIFXFirmwarePackage(overalls_, &offset, response.value(),
                                          length, info.firmware[1]));

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Orspi_UnloadBlob_UINT16_s(
      &offset, &info.status, response.value(), length)));

  RETURN_IF_ERROR(ParseIFXFirmwarePackage(overalls_, &offset, response.value(),
                                          length, info.process_fw));

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Orspi_UnloadBlob_UINT16_s(
      &offset, nullptr, response.value(), length)));

  offset += 6;

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Orspi_UnloadBlob_UINT16_s(
      &offset, &info.field_upgrade_counter, response.value(), length)));

  return info;
}

Status VendorTpm1::DeclareTpmFirmwareStable() {
  // No-op on TPM1.2
  return OkStatus();
}

StatusOr<VendorTpm1::RwVersion> VendorTpm1::GetRwVersion() {
  return MakeStatus<TPMError>("Unimplemented", TPMRetryAction::kNoRetry);
}

StatusOr<brillo::Blob> VendorTpm1::SendRawCommand(const brillo::Blob& command) {
  return MakeStatus<TPMError>("Unimplemented", TPMRetryAction::kNoRetry);
}

}  // namespace hwsec
