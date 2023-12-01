// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/ro_data.h"

#include <bitset>
#include <cstdint>
#include <utility>

#include <libhwsec-foundation/status/status_chain_macros.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "libhwsec/error/tpm_manager_error.h"
#include "libhwsec/error/tpm_nvram_error.h"
#include "libhwsec/structures/no_default_init.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

constexpr uint32_t kG2fCertIndex = 0x3fff02;

using Attributes = std::bitset<tpm_manager::NvramSpaceAttribute_ARRAYSIZE>;

struct SpaceInfo {
  NoDefault<uint32_t> index;
  NoDefault<bool> read_with_owner_auth;
  Attributes require_attributes;
  Attributes deny_attributes;
};

// Note: These bitset initialization steps would not work if we have more than
// 64 kind of attributes.
constexpr Attributes kG2fCertRequiredAttributes =
    (1ULL << tpm_manager::NVRAM_PERSISTENT_WRITE_LOCK) |
    (1ULL << tpm_manager::NVRAM_READ_AUTHORIZATION);

bool CheckAttributes(const Attributes& require_attributes,
                     const Attributes& deny_attributes,
                     const Attributes& attributes) {
  if ((attributes & require_attributes) != require_attributes) {
    return false;
  }

  if ((attributes & deny_attributes).any()) {
    return false;
  }

  return true;
}

StatusOr<SpaceInfo> GetSpaceInfo(RoSpace space) {
  switch (space) {
    case RoSpace::kG2fCert:
      return SpaceInfo{
          .index = kG2fCertIndex,
          .read_with_owner_auth = false,
          .require_attributes = kG2fCertRequiredAttributes,
      };
    default:
      return MakeStatus<TPMError>("Unknown space", TPMRetryAction::kNoRetry);
  }
}

struct DetailSpaceInfo {
  uint32_t size = 0;
  Attributes attributes;
};

StatusOr<DetailSpaceInfo> GetDetailSpaceInfo(
    org::chromium::TpmNvramProxyInterface& tpm_nvram,
    const SpaceInfo& space_info) {
  DetailSpaceInfo result;

  tpm_manager::GetSpaceInfoRequest request;
  request.set_index(space_info.index);
  tpm_manager::GetSpaceInfoReply reply;

  if (brillo::ErrorPtr err; !tpm_nvram.GetSpaceInfo(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMNvramError>(reply.result()));

  result.size = reply.size();
  for (int i = 0; i < reply.attributes().size(); ++i) {
    result.attributes[reply.attributes(i)] = true;
  }

  return result;
}

}  // namespace

StatusOr<bool> RoDataTpm2::IsReady(RoSpace space) {
  ASSIGN_OR_RETURN(const SpaceInfo& space_info, GetSpaceInfo(space));

  StatusOr<DetailSpaceInfo> detail_info =
      GetDetailSpaceInfo(tpm_nvram_, space_info);

  if (!detail_info.ok() &&
      detail_info.err_status()->UnifiedErrorCode() ==
          TPMNvramError(
              tpm_manager::NvramResult::NVRAM_RESULT_SPACE_DOES_NOT_EXIST)
              .UnifiedErrorCode()) {
    return false;
  }
  if (!detail_info.ok()) {
    return MakeStatus<TPMError>("Failed to get detail space info")
        .Wrap(std::move(detail_info).err_status());
  }
  return CheckAttributes(space_info.require_attributes,
                         space_info.deny_attributes, detail_info->attributes);
}

StatusOr<brillo::Blob> RoDataTpm2::Read(RoSpace space) {
  ASSIGN_OR_RETURN(const SpaceInfo& space_info, GetSpaceInfo(space));

  tpm_manager::ReadSpaceRequest request;
  request.set_index(space_info.index);
  request.set_use_owner_authorization(space_info.read_with_owner_auth);
  tpm_manager::ReadSpaceReply reply;

  if (brillo::ErrorPtr err; !tpm_nvram_.ReadSpace(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMNvramError>(reply.result()));

  return brillo::BlobFromString(reply.data());
}

StatusOr<brillo::Blob> RoDataTpm2::Certify(RoSpace space, Key key) {
  return MakeStatus<TPMError>("Not implemented", TPMRetryAction::kNoRetry);
}

}  // namespace hwsec
