// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/pkcs11_slot_getter.h"

#include <utility>
#include <vector>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/single_thread_task_runner.h>
#include <chaps/isolate.h>

#include "base/time/time.h"
#include "shill/store/pkcs11_util.h"

namespace {

constexpr char kChapsSystemToken[] = "/var/lib/chaps";
constexpr char kChapsDaemonStore[] = "/run/daemon-store/chaps";

}  // namespace

namespace shill {

Pkcs11SlotGetter::Pkcs11SlotGetter(const std::string& user_hash,
                                   chaps::TokenManagerClient* test_chaps_client)
    : user_slot_id_(pkcs11::kInvalidSlot),
      system_slot_id_(pkcs11::kInvalidSlot),
      user_hash_(user_hash) {
  chaps_client_ =
      test_chaps_client ? test_chaps_client : &default_chaps_client_;
}

CK_SLOT_ID Pkcs11SlotGetter::GetPkcs11SlotId(pkcs11::Slot slot) {
  switch (slot) {
    case pkcs11::Slot::kUser: {
      if (user_slot_id_ == pkcs11::kInvalidSlot) {
        user_slot_id_ = GetSlotId(slot);
      }
      return user_slot_id_;
    }
    case pkcs11::Slot::kSystem: {
      if (system_slot_id_ == pkcs11::kInvalidSlot) {
        system_slot_id_ = GetSlotId(slot);
      }
      return system_slot_id_;
    }
    default:
      return pkcs11::kInvalidSlot;
  }
}

void Pkcs11SlotGetter::GetPkcs11SlotIdWithRetries(
    pkcs11::Slot slot,
    base::OnceCallback<void(CK_SLOT_ID)> callback,
    base::TimeDelta delay) {
  CK_SLOT_ID slot_id = GetPkcs11SlotId(slot);
  if (slot_id != pkcs11::kInvalidSlot || delay > kPkcs11TokenMaxRequestDelay) {
    std::move(callback).Run(slot_id);
    return;
  }
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Pkcs11SlotGetter::GetPkcs11SlotIdWithRetries,
                     weak_factory_.GetWeakPtr(), slot, std::move(callback),
                     delay * kPkcs11TokenDelayMultiplier),
      delay);
}

CK_SLOT_ID Pkcs11SlotGetter::GetPkcs11DefaultSlotId() {
  if (!user_hash_.empty()) {
    return GetPkcs11SlotId(pkcs11::Slot::kUser);
  }
  return GetPkcs11SlotId(pkcs11::Slot::kSystem);
}

pkcs11::Slot Pkcs11SlotGetter::GetSlotType(CK_SLOT_ID slot_id) {
  if (slot_id == GetPkcs11SlotId(pkcs11::Slot::kUser)) {
    return pkcs11::Slot::kUser;
  }
  if (slot_id == GetPkcs11SlotId(pkcs11::Slot::kSystem)) {
    return pkcs11::Slot::kSystem;
  }
  return pkcs11::Slot::kUnknown;
}

CK_SLOT_ID Pkcs11SlotGetter::GetSlotId(pkcs11::Slot slot) {
  base::FilePath token_path;
  switch (slot) {
    case pkcs11::Slot::kUser: {
      if (user_hash_.empty()) {
        return pkcs11::kInvalidSlot;
      }
      token_path = base::FilePath(kChapsDaemonStore).Append(user_hash_);
      break;
    }
    case pkcs11::Slot::kSystem: {
      token_path = base::FilePath(kChapsSystemToken);
      break;
    }
    default:
      return pkcs11::kInvalidSlot;
  }

  CK_RV rv;
  rv = C_Initialize(nullptr);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    LOG(WARNING) << "C_Initialize failed for " << token_path << ". rv: " << rv;
    return pkcs11::kInvalidSlot;
  }

  const CK_ULONG default_num_slots = 20;
  CK_ULONG num_slots = default_num_slots;
  std::vector<CK_SLOT_ID> slots;
  slots.resize(num_slots);
  rv = C_GetSlotList(CK_TRUE, slots.data(), &num_slots);
  if (rv == CKR_BUFFER_TOO_SMALL) {
    slots.resize(num_slots);
    rv = C_GetSlotList(CK_TRUE, slots.data(), &num_slots);
  }
  if (rv != CKR_OK) {
    LOG(WARNING) << "C_GetSlotList failed for " << token_path << ". rv: " << rv;
    return pkcs11::kInvalidSlot;
  }
  slots.resize(num_slots);

  // Look through all slots for |token_path|.
  for (CK_SLOT_ID curr_slot : slots) {
    base::FilePath slot_path;
    if (chaps_client_->GetTokenPath(
            chaps::IsolateCredentialManager::GetDefaultIsolateCredential(),
            curr_slot, &slot_path) &&
        (token_path == slot_path)) {
      return curr_slot;
    }
  }
  LOG(WARNING) << "Path " << token_path << "not found";
  return pkcs11::kInvalidSlot;
}

}  // namespace shill
