// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/vendor.h"

#include <array>
#include <cinttypes>
#include <cstdint>
#include <string>
#include <utility>

#include <base/strings/stringprintf.h>
#include <base/sys_byteorder.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>
#include <trunks/tpm_generated.h>
#include <trunks/tpm_utility.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/error/tpm_manager_error.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::Sha256;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

// From src/platform/cr50/chip/g/upgrade_fw.h.
struct signed_header_version {
  uint32_t minor;
  uint32_t major;
  uint32_t epoch;
} __attribute__((__packed__));

struct first_response_pdu {
  uint32_t return_value;
  uint32_t protocol_version;
  uint32_t backup_ro_offset;
  uint32_t backup_rw_offset;
  struct signed_header_version shv[2];
  uint32_t keyid[2];
} __attribute__((__packed__));

Status GetResponseStatus(const std::string& response) {
  std::string buffer(response);

  trunks::TPM_ST tag;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(trunks::Parse_TPM_ST(&buffer, &tag, nullptr)))
      .WithStatus<TPMError>("Failed to parse response tag");

  trunks::UINT32 response_size;
  RETURN_IF_ERROR(MakeStatus<TPM2Error>(
                      trunks::Parse_UINT32(&buffer, &response_size, nullptr)))
      .WithStatus<TPMError>("Failed to parse response size");

  if (response_size != response.size()) {
    return MakeStatus<TPMError>("Mismatch response size",
                                TPMRetryAction::kNoRetry);
  }

  trunks::TPM_RC rc;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(trunks::Parse_TPM_RC(&buffer, &rc, nullptr)))
      .WithStatus<TPMError>("Failed to parse TPM_RC");

  return MakeStatus<TPM2Error>(rc);
}

}  // namespace

Status VendorTpm2::EnsureVersionInfo() {
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

StatusOr<uint32_t> VendorTpm2::GetFamily() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->family();
}

StatusOr<uint64_t> VendorTpm2::GetSpecLevel() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->spec_level();
}

StatusOr<uint32_t> VendorTpm2::GetManufacturer() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->manufacturer();
}

StatusOr<uint32_t> VendorTpm2::GetTpmModel() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->tpm_model();
}

StatusOr<uint64_t> VendorTpm2::GetFirmwareVersion() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return version_info_->firmware_version();
}

StatusOr<brillo::Blob> VendorTpm2::GetVendorSpecific() {
  RETURN_IF_ERROR(EnsureVersionInfo());

  return brillo::BlobFromString(version_info_->vendor_specific());
}

StatusOr<int32_t> VendorTpm2::GetFingerprint() {
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

StatusOr<bool> VendorTpm2::IsSrkRocaVulnerable() {
  return false;
}

StatusOr<brillo::Blob> VendorTpm2::GetRsuDeviceId() {
  std::string device_id;

  RETURN_IF_ERROR(MakeStatus<TPM2Error>(
                      context_.GetTpmUtility().GetRsuDeviceId(&device_id)))
      .WithStatus<TPMError>("Failed to get the RSU device ID");

  return BlobFromString(device_id);
}

StatusOr<IFXFieldUpgradeInfo> VendorTpm2::GetIFXFieldUpgradeInfo() {
  return MakeStatus<TPMError>("Unsupported command", TPMRetryAction::kNoRetry);
}

Status VendorTpm2::DeclareTpmFirmwareStable() {
  if (fw_declared_stable_) {
    return OkStatus();
  }

  RETURN_IF_ERROR(MakeStatus<TPM2Error>(
                      context_.GetTpmUtility().DeclareTpmFirmwareStable()))
      .WithStatus<TPMError>("Failed to declare TPM firmware stable");

  fw_declared_stable_ = true;

  return OkStatus();
}

StatusOr<VendorTpm2::RwVersion> VendorTpm2::GetRwVersion() {
  // TODO(b/257335815): Add Ti50 case here after its tpm_version is separated
  // from Cr50.
  if (!context_.GetTpmUtility().IsGsc()) {
    return MakeStatus<TPMError>("Not supported on non-GSC devices",
                                TPMRetryAction::kNoRetry);
  }

  // GSC tool uses the FW upgrade command to retrieve the RO/RW versions. There
  // are two phases of FW upgrade: connection establishment and actual image
  // transfer. RO/RW versions are included in the response of the first PDU to
  // establish connection, in new enough cr50 protocol versions. We can use this
  // first PDU to retrieve the RW version info we want without side effects. It
  // has all-zero digest and address.
  constexpr std::array<uint8_t, 20> kExtensionFwUpgradeRequest{
      0x80, 0x01,              // tag: TPM_ST_NO_SESSIONS
      0x00, 0x00, 0x00, 0x14,  // length
      0xba, 0xcc, 0xd0, 0x0a,  // ordinal: CONFIG_EXTENSION_COMMAND
      0x00, 0x04,              // subcmd: EXTENSION_FW_UPGRADE
      0x00, 0x00, 0x00, 0x00,  // digest : UINT32
      0x00, 0x00, 0x00, 0x00,  // address : UINT32
  };

  constexpr int kResponsePduOffset = 12;
  constexpr int kExpectedResponseSize =
      kResponsePduOffset + sizeof(first_response_pdu);
  constexpr int kRwVersionIndex = 1;

  std::string req(kExtensionFwUpgradeRequest.begin(),
                  kExtensionFwUpgradeRequest.end());

  ASSIGN_OR_RETURN(
      const brillo::Blob resp,
      SendRawCommand(brillo::Blob(kExtensionFwUpgradeRequest.begin(),
                                  kExtensionFwUpgradeRequest.end())));

  if (resp.size() != kExpectedResponseSize) {
    return MakeStatus<TPMError>("Incorrect response size",
                                TPMRetryAction::kNoRetry);
  }

  first_response_pdu pdu;
  memcpy(&pdu, resp.data() + kResponsePduOffset, sizeof(first_response_pdu));
  return RwVersion{
      .epoch = base::NetToHost32(pdu.shv[kRwVersionIndex].epoch),
      .major = base::NetToHost32(pdu.shv[kRwVersionIndex].major),
      .minor = base::NetToHost32(pdu.shv[kRwVersionIndex].minor),
  };
}

StatusOr<brillo::Blob> VendorTpm2::SendRawCommand(const brillo::Blob& command) {
  std::string response = context_.GetCommandTransceiver().SendCommandAndWait(
      BlobToString(command));

  RETURN_IF_ERROR(GetResponseStatus(response));

  return BlobFromString(response);
}

}  // namespace hwsec
