// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/storage.h"

#include <bitset>
#include <cstdint>
#include <optional>
#include <utility>

#include <absl/container/flat_hash_set.h>
#include <base/strings/stringprintf.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "libhwsec/error/tpm_manager_error.h"
#include "libhwsec/error/tpm_nvram_error.h"
#include "libhwsec/error/tpm_retry_action.h"
#include "libhwsec/structures/no_default_init.h"

namespace hwsec {

using hwsec_foundation::status::MakeStatus;
using BootModeSetting = DeviceConfigSettings::BootModeSetting;
using Mode = DeviceConfigSettings::BootModeSetting::Mode;

namespace {

constexpr uint32_t kFwmpIndex = 0x100a;
constexpr uint32_t kInstallAttributesIndex =
    USE_TPM_DYNAMIC ? 0x9da5b0 : 0x800004;
constexpr uint32_t kBootlockboxIndex = USE_TPM_DYNAMIC ? 0x9da5b2 : 0x800006;
constexpr uint32_t kEnterpriseRollbackIndex = 0x100e;

// 3-byte boot mode:
//  - byte 0: 1 if in developer mode, 0 otherwise,
//  - byte 1: 1 if in recovery mode, 0 otherwise,
//  - byte 2: 1 if verified firmware, 0 if developer firmware.
// Allowed modes for FWMP update:
//  - normal =   {0, 0, 1}
//  - dev =      {1, 0, 1}
//  - recovery = {0, 1, 0}
constexpr Mode kAllowedFWMPUpdateBootModes[] = {Mode{
                                                    .developer_mode = false,
                                                    .recovery_mode = false,
                                                    .verified_firmware = true,
                                                },
                                                Mode{
                                                    .developer_mode = true,
                                                    .recovery_mode = false,
                                                    .verified_firmware = true,
                                                },
                                                Mode{
                                                    .developer_mode = false,
                                                    .recovery_mode = true,
                                                    .verified_firmware = false,
                                                }};

using Attributes = std::bitset<tpm_manager::NvramSpaceAttribute_ARRAYSIZE>;

struct SpaceInfo {
  NoDefault<uint32_t> index;
  NoDefault<bool> write_with_owner_auth;
  NoDefault<bool> read_with_owner_auth;
  NoDefault<bool> lock_after_write;
  NoDefault<bool> preparable_if_not_writable;
  std::optional<Attributes> init_attributes;
  Attributes require_attributes;
  Attributes deny_attributes;
  std::optional<const char*> owner_dependency;
};

// Note: These bitset initialization steps would not work if we have more than
// 64 kind of attributes.
constexpr Attributes kFwmpInitAttributes =
    (1ULL << tpm_manager::NVRAM_PERSISTENT_WRITE_LOCK) |
    (1ULL << tpm_manager::NVRAM_PLATFORM_READ);

constexpr Attributes kFwmpRequireAttributes =
    (1ULL << tpm_manager::NVRAM_PERSISTENT_WRITE_LOCK) |
    (1ULL << tpm_manager::NVRAM_PLATFORM_READ);

constexpr Attributes kPlatformFwmpRequireAttributes =
    (1ULL << tpm_manager::NVRAM_PLATFORM_CREATE) |
    (1ULL << tpm_manager::NVRAM_OWNER_WRITE) |
    (1ULL << tpm_manager::NVRAM_READ_AUTHORIZATION) |
    (1ULL << tpm_manager::NVRAM_PLATFORM_READ);

constexpr Attributes kPlatformFwmpDenyAttributes =
    (1ULL << tpm_manager::NVRAM_WRITE_AUTHORIZATION);

constexpr Attributes kInstallAttributesRequireAttributes =
    (1ULL << tpm_manager::NVRAM_PERSISTENT_WRITE_LOCK);

constexpr Attributes kInstallAttributesInitAttributes =
    (1ULL << tpm_manager::NVRAM_PERSISTENT_WRITE_LOCK);

constexpr Attributes kBootlockboxInitAttributes =
    (1ULL << tpm_manager::NVRAM_READ_AUTHORIZATION) |
    (1ULL << tpm_manager::NVRAM_BOOT_WRITE_LOCK) |
    (1ULL << tpm_manager::NVRAM_WRITE_AUTHORIZATION);

constexpr Attributes kEnterpriseRollbackRequireAttributes =
    (1ULL << tpm_manager::NVRAM_PLATFORM_CREATE) |
    (1ULL << tpm_manager::NVRAM_READ_AUTHORIZATION) |
    (1ULL << tpm_manager::NVRAM_WRITE_AUTHORIZATION);

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

StatusOr<SpaceInfo> GetSpaceInfo(Space space) {
  switch (space) {
    case Space::kFirmwareManagementParameters:
      return SpaceInfo{
          .index = kFwmpIndex,
          .write_with_owner_auth = false,
          .read_with_owner_auth = false,
          .lock_after_write = true,
          .preparable_if_not_writable = true,
          .init_attributes = kFwmpInitAttributes,
          .require_attributes = kFwmpRequireAttributes,
      };
    case Space::kPlatformFirmwareManagementParameters:
      return SpaceInfo{
          .index = kFwmpIndex,
          .write_with_owner_auth = true,
          .read_with_owner_auth = false,
          .lock_after_write = false,
          .preparable_if_not_writable = false,
          .require_attributes = kPlatformFwmpRequireAttributes,
          .deny_attributes = kPlatformFwmpDenyAttributes,
      };
    case Space::kInstallAttributes:
      return SpaceInfo{
          .index = kInstallAttributesIndex,
          .write_with_owner_auth = false,
          .read_with_owner_auth = false,
          .lock_after_write = true,
          .preparable_if_not_writable = true,
          .init_attributes = kInstallAttributesInitAttributes,
          .require_attributes = kInstallAttributesRequireAttributes,
          .owner_dependency = tpm_manager::kTpmOwnerDependency_Nvram,
      };
    case Space::kBootlockbox:
      return SpaceInfo{
          .index = kBootlockboxIndex,
          .write_with_owner_auth = false,
          .read_with_owner_auth = false,
          .lock_after_write = false,
          .preparable_if_not_writable = false,
          .init_attributes = kBootlockboxInitAttributes,
          .owner_dependency = tpm_manager::kTpmOwnerDependency_Bootlockbox,
      };
    case Space::kEnterpriseRollback:
      return SpaceInfo{
          .index = kEnterpriseRollbackIndex,
          .write_with_owner_auth = false,
          .read_with_owner_auth = false,
          .lock_after_write = false,
          .preparable_if_not_writable = false,
          .require_attributes = kEnterpriseRollbackRequireAttributes,
      };
    default:
      return MakeStatus<TPMError>("Unknown space",
                                  TPMRetryAction::kSpaceNotFound);
  }
}

StatusOr<absl::flat_hash_set<uint32_t>> List(
    org::chromium::TpmNvramProxyInterface& tpm_nvram) {
  absl::flat_hash_set<uint32_t> result;

  tpm_manager::ListSpacesRequest request;
  tpm_manager::ListSpacesReply reply;

  if (brillo::ErrorPtr err; !tpm_nvram.ListSpaces(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMNvramError>(reply.result()));

  for (int i = 0; i < reply.index_list_size(); ++i) {
    result.insert(reply.index_list(i));
  }

  return result;
}

Status CheckAndRemoveDependency(
    org::chromium::TpmManagerProxyInterface& tpm_manager,
    const SpaceInfo& space_info) {
  if (space_info.owner_dependency.has_value()) {
    tpm_manager::RemoveOwnerDependencyRequest request;
    request.set_owner_dependency(space_info.owner_dependency.value());
    tpm_manager::RemoveOwnerDependencyReply reply;

    if (brillo::ErrorPtr err; !tpm_manager.RemoveOwnerDependency(
            request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
      return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
          .Wrap(std::move(err));
    }

    RETURN_IF_ERROR(MakeStatus<TPMManagerError>(reply.status()));
  }

  return OkStatus();
}

StatusOr<bool> HasOwnerPassword(
    org::chromium::TpmManagerProxyInterface& tpm_manager) {
  tpm_manager::GetTpmNonsensitiveStatusRequest status_request;
  tpm_manager::GetTpmNonsensitiveStatusReply status_reply;

  if (brillo::ErrorPtr err; !tpm_manager.GetTpmNonsensitiveStatus(
          status_request, &status_reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMManagerError>(status_reply.status()));

  if (!status_reply.is_owned()) {
    return MakeStatus<TPMError>("TPM is not owned", TPMRetryAction::kLater);
  }

  if (!status_reply.is_owner_password_present()) {
    return false;
  }

  return true;
}

struct DetailSpaceInfo {
  uint32_t size = 0;
  bool is_read_locked = false;
  bool is_write_locked = false;
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
  result.is_read_locked = reply.is_read_locked();
  result.is_write_locked = reply.is_write_locked();
  for (int i = 0; i < reply.attributes().size(); ++i) {
    result.attributes[reply.attributes(i)] = true;
  }

  return result;
}

bool IsFWMP(Space space) {
  return space == Space::kFirmwareManagementParameters ||
         space == Space::kPlatformFirmwareManagementParameters;
}

}  // namespace

StatusOr<StorageTpm2::ReadyState> StorageTpm2::IsReadyInternal(Space space) {
  ASSIGN_OR_RETURN(const absl::flat_hash_set<uint32_t>& space_list,
                   List(tpm_nvram_),
                   _.WithStatus<TPMError>("Failed to list space"));

  ASSIGN_OR_RETURN(const SpaceInfo& space_info, GetSpaceInfo(space));

  DetailSpaceInfo detail_info;
  bool ready = false;
  bool space_exists = space_list.count(space_info.index);
  if (space_exists) {
    ASSIGN_OR_RETURN(detail_info, GetDetailSpaceInfo(tpm_nvram_, space_info),
                     _.WithStatus<TPMError>("Failed to get detail space info"));

    ready = CheckAttributes(space_info.require_attributes,
                            space_info.deny_attributes, detail_info.attributes);
  }

  ASSIGN_OR_RETURN(
      bool has_owner_pass, HasOwnerPassword(tpm_manager_),
      _.WithStatus<TPMError>("Failed to get owner password status"));

  if (!ready) {
    if (!space_info.init_attributes.has_value()) {
      return MakeStatus<TPMError>("This space is not preparable",
                                  space_exists
                                      ? TPMRetryAction::kNoRetry
                                      : TPMRetryAction::kSpaceNotFound);
    }

    if (!has_owner_pass) {
      // Nothing we can do under this kind of case.
      return MakeStatus<TPMError>(
          "No owner password", space_exists ? TPMRetryAction::kNoRetry
                                            : TPMRetryAction::kSpaceNotFound);
    }

    return ReadyState{
        .preparable = true,
        .readable = false,
        .writable = false,
        .destroyable = true,
    };
  }

  bool preparable = false;
  bool readable = !detail_info.is_read_locked;
  bool writable = !detail_info.is_write_locked;
  bool destroyable = has_owner_pass;

  if (space_info.read_with_owner_auth && !has_owner_pass) {
    readable = false;
  }

  if (space_info.write_with_owner_auth && !has_owner_pass) {
    writable = false;
  }

  if (!writable && space_info.preparable_if_not_writable) {
    preparable = has_owner_pass;
  }

  // Note: For platform FWMP, the correct timing to remove the owner dependency
  // is after finishing the first write command.
  // But currently there is no owner dependency for FWMP.
  if (!preparable && has_owner_pass) {
    RETURN_IF_ERROR(CheckAndRemoveDependency(tpm_manager_, space_info))
        .WithStatus<TPMError>("Failed to check and remove dependency");
  }

  return ReadyState{
      .preparable = preparable,
      .readable = readable,
      .writable = writable,
      .destroyable = destroyable,
  };
}

StatusOr<StorageTpm2::ReadyState> StorageTpm2::IsReady(Space space) {
  auto cache_it = state_cache_.find(space);

  ReadyState state{
      .preparable = false,
      .readable = false,
      .writable = false,
      .destroyable = false,
  };

  if (cache_it != state_cache_.end()) {
    state = cache_it->second;
  } else {
    ASSIGN_OR_RETURN(state, IsReadyInternal(space));
  }

  if (IsFWMP(space) &&
      (state.preparable || state.writable || state.destroyable) &&
      !CanModifyFWMP().value_or(false)) {
    state.preparable = false;
    state.writable = false;
    state.destroyable = false;
  }

  state_cache_.insert_or_assign(space, state);

  return state;
}

Status StorageTpm2::Prepare(Space space, uint32_t size) {
  ASSIGN_OR_RETURN(ReadyState ready_state, IsReady(space),
                   _.WithStatus<TPMError>("Failed to get space ready state"));

  ASSIGN_OR_RETURN(const SpaceInfo& space_info, GetSpaceInfo(space));

  if (ready_state.readable && ready_state.writable) {
    return OkStatus();
  }

  if (!ready_state.preparable) {
    return MakeStatus<TPMError>("The space is not preparable",
                                TPMRetryAction::kReboot);
  }

  if (!ready_state.destroyable) {
    return MakeStatus<TPMError>(
        "The space is not preparable due to not destroyable",
        TPMRetryAction::kNoRetry);
  }

  RETURN_IF_ERROR(Destroy(space))
      .WithStatus<TPMError>("Failed to destroy space when prepare space");

  // The cache will be invalidated.
  state_cache_.erase(space);

  tpm_manager::DefineSpaceRequest define_request;
  define_request.set_index(space_info.index);
  define_request.set_size(size);
  const Attributes& attrs = space_info.init_attributes.value();
  for (int i = 0; i < attrs.size(); i++) {
    if (attrs[i]) {
      define_request.add_attributes(
          static_cast<tpm_manager::NvramSpaceAttribute>(i));
    }
  }

  tpm_manager::DefineSpaceReply define_reply;

  if (brillo::ErrorPtr err; !tpm_nvram_.DefineSpace(
          define_request, &define_reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMNvramError>(define_reply.result()));

  RETURN_IF_ERROR(CheckAndRemoveDependency(tpm_manager_, space_info))
      .WithStatus<TPMError>("Failed to check and remove dependency");

  return OkStatus();
}

StatusOr<brillo::Blob> StorageTpm2::Load(Space space) {
  ASSIGN_OR_RETURN(ReadyState ready_state, IsReady(space),
                   _.WithStatus<TPMError>("Failed to get space ready state"));

  if (!ready_state.readable) {
    return MakeStatus<TPMError>("The space is not readable",
                                TPMRetryAction::kNoRetry);
  }

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

Status StorageTpm2::Store(Space space, const brillo::Blob& blob) {
  ASSIGN_OR_RETURN(ReadyState ready_state, IsReady(space),
                   _.WithStatus<TPMError>("Failed to get space ready state"));

  if (!ready_state.writable) {
    return MakeStatus<TPMError>("The space is not writable",
                                TPMRetryAction::kReboot);
  }

  ASSIGN_OR_RETURN(const SpaceInfo& space_info, GetSpaceInfo(space));

  tpm_manager::WriteSpaceRequest request;
  request.set_index(space_info.index);
  request.set_data(brillo::BlobToString(blob));
  request.set_use_owner_authorization(space_info.write_with_owner_auth);
  tpm_manager::WriteSpaceReply reply;

  if (brillo::ErrorPtr err; !tpm_nvram_.WriteSpace(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMNvramError>(reply.result()));

  if (space_info.lock_after_write) {
    RETURN_IF_ERROR(Lock(space,
                         LockOptions{
                             .read_lock = false,
                             .write_lock = true,
                         }))
        .WithStatus<TPMError>("Failed to lock after write");
  }

  return OkStatus();
}

Status StorageTpm2::Lock(Space space, LockOptions options) {
  ASSIGN_OR_RETURN(const SpaceInfo& space_info, GetSpaceInfo(space));

  ASSIGN_OR_RETURN(const DetailSpaceInfo& detail_info,
                   GetDetailSpaceInfo(tpm_nvram_, space_info),
                   _.WithStatus<TPMError>("Failed to get detail space info"));
  // If the space is already read-locked we don't have to read-lock it again.
  if (detail_info.is_read_locked) {
    options.read_lock = false;
  }
  // If the space is already write-locked we don't have to write-lock it again.
  if (detail_info.is_write_locked) {
    options.write_lock = false;
  }
  // This case will result in a no-op lock command, returning early instead.
  if (!options.read_lock && !options.write_lock) {
    return OkStatus();
  }

  // The cache will be invalidated.
  state_cache_.erase(space);

  tpm_manager::LockSpaceRequest request;
  request.set_index(space_info.index);
  request.set_lock_write(options.write_lock);
  request.set_lock_read(options.read_lock);
  tpm_manager::LockSpaceReply reply;

  if (brillo::ErrorPtr err; !tpm_nvram_.LockSpace(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  return MakeStatus<TPMNvramError>(reply.result());
}

Status StorageTpm2::Destroy(Space space) {
  ASSIGN_OR_RETURN(ReadyState ready_state, IsReady(space),
                   _.WithStatus<TPMError>("Failed to get space ready state"));

  if (!ready_state.destroyable) {
    return MakeStatus<TPMError>("The space is not destroyable",
                                TPMRetryAction::kReboot);
  }

  ASSIGN_OR_RETURN(const SpaceInfo& space_info, GetSpaceInfo(space));

  ASSIGN_OR_RETURN(const absl::flat_hash_set<uint32_t>& space_list,
                   List(tpm_nvram_),
                   _.WithStatus<TPMError>("Failed to list space"));

  if (space_list.find(space_info.index) == space_list.end()) {
    return OkStatus();
  }

  // The cache will be invalidated.
  state_cache_.erase(space);

  tpm_manager::DestroySpaceRequest request;
  request.set_index(space_info.index);
  tpm_manager::DestroySpaceReply reply;

  if (brillo::ErrorPtr err; !tpm_nvram_.DestroySpace(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMNvramError>(reply.result()));

  return OkStatus();
}

StatusOr<bool> StorageTpm2::CanModifyFWMP() {
  using BootModeSetting = DeviceConfigSettings::BootModeSetting;
  using Mode = DeviceConfigSettings::BootModeSetting::Mode;

  ASSIGN_OR_RETURN(const ConfigTpm2::PcrMap&& current_pcr,
                   config_.ToSettingsPcrMap(
                       DeviceConfigSettings{.boot_mode =
                                                BootModeSetting{
                                                    // Current boot mode
                                                    .mode = std::nullopt,
                                                }}),
                   _.WithStatus<TPMError>("Failed to read current boot mode"));

  for (const Mode& allowed_mode : kAllowedFWMPUpdateBootModes) {
    ASSIGN_OR_RETURN(
        const ConfigTpm2::PcrMap& allowed_pcr,
        config_.ToSettingsPcrMap(DeviceConfigSettings{
            .boot_mode = BootModeSetting{.mode = allowed_mode}}),
        _.WithStatus<TPMError>("Failed to read current boot mode"));

    if (allowed_pcr == current_pcr) {
      return true;
    }
  }

  return false;
}

}  // namespace hwsec
