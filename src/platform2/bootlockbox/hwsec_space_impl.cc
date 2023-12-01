// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/bootlockbox/frontend.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "bootlockbox/hwsec_space.h"
#include "bootlockbox/hwsec_space_impl.h"
#include "libhwsec/error/tpm_error.h"

namespace bootlockbox {

SpaceState HwsecSpaceImpl::DefineSpace() {
  ASSIGN_OR_RETURN(hwsec::BootLockboxFrontend::StorageState state,
                   hwsec_->GetSpaceState(),
                   _.WithStatus<hwsec::TPMError>("Failed to get space state")
                       .LogError()
                       .As(SpaceState::kSpaceNeedPowerwash));

  if (state.writable) {
    return SpaceState::kSpaceUninitialized;
  }

  if (!state.preparable) {
    LOG(ERROR) << "Cannot prepare space with unprepareable state.";
    return SpaceState::kSpaceError;
  }

  RETURN_IF_ERROR(hwsec_->PrepareSpace(kSpaceSize))
      .WithStatus<hwsec::TPMError>("Failed to prepare space")
      .LogError()
      .As(SpaceState::kSpaceUndefined);

  return SpaceState::kSpaceUninitialized;
}

bool HwsecSpaceImpl::WriteSpace(const std::string& digest) {
  if (digest.size() != SHA256_DIGEST_LENGTH) {
    LOG(ERROR) << "Wrong digest size, expected: " << SHA256_DIGEST_LENGTH
               << " got: " << digest.size();
    return false;
  }

  BootLockboxSpace space;
  space.version = kSpaceVersion;
  space.flags = 0;
  memcpy(space.digest, digest.data(), SHA256_DIGEST_LENGTH);
  brillo::Blob nvram_data(kSpaceSize);
  memcpy(nvram_data.data(), &space, kSpaceSize);

  RETURN_IF_ERROR(hwsec_->StoreSpace(nvram_data))
      .WithStatus<hwsec::TPMError>("Failed to store space")
      .LogError()
      .As(false);

  return true;
}

SpaceState HwsecSpaceImpl::ReadSpace(std::string* digest) {
  ASSIGN_OR_RETURN(hwsec::BootLockboxFrontend::StorageState state,
                   hwsec_->GetSpaceState(),
                   _.WithStatus<hwsec::TPMError>("Failed to get space state")
                       .LogError()
                       .As(SpaceState::kSpaceNeedPowerwash));

  if (!state.readable && state.preparable) {
    return SpaceState::kSpaceUndefined;
  }

  ASSIGN_OR_RETURN(brillo::Blob nvram_data, hwsec_->LoadSpace(),
                   _.WithStatus<hwsec::TPMError>("Failed to read space")
                       .LogError()
                       .As(SpaceState::kSpaceError));

  if (nvram_data.size() != kSpaceSize) {
    LOG(ERROR) << "Error reading nvram space, invalid data length, expected:"
               << kSpaceSize << ", got " << nvram_data.size();
    return SpaceState::kSpaceError;
  }

  std::string nvram_data_str = brillo::BlobToString(nvram_data);
  if (nvram_data_str == std::string(kSpaceSize, '\0') ||
      nvram_data_str == std::string(kSpaceSize, 0xff)) {
    LOG(ERROR) << "Empty nvram data.";
    return SpaceState::kSpaceUninitialized;
  }

  BootLockboxSpace space;
  memcpy(&space, nvram_data.data(), kSpaceSize);
  if (space.version != kSpaceVersion) {
    LOG(ERROR) << "Error reading nvram space, invalid version";
    return SpaceState::kSpaceError;
  }
  digest->assign(reinterpret_cast<const char*>(space.digest),
                 SHA256_DIGEST_LENGTH);
  return SpaceState::kSpaceNormal;
}

bool HwsecSpaceImpl::LockSpace() {
  RETURN_IF_ERROR(hwsec_->LockSpace())
      .WithStatus<hwsec::TPMError>("Failed to lock space")
      .LogError()
      .As(false);

  return true;
}

void HwsecSpaceImpl::RegisterOwnershipTakenCallback(
    base::OnceClosure callback) {
  hwsec_->WaitUntilReady(base::IgnoreArgs<hwsec::Status>(std::move(callback)));
}

}  // namespace bootlockbox
