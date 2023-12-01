// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_PKCS11_SLOT_GETTER_H_
#define SHILL_STORE_PKCS11_SLOT_GETTER_H_

#include <chaps/pkcs11/cryptoki.h>

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <chaps/threading_mode.h>
#include <chaps/token_manager_client.h>
#include <gtest/gtest_prod.h>

#include <shill/store/pkcs11_util.h>

namespace shill {

// The initial, maximum, and multiplier for the delay of getting the TPM token
// slot ID. Timeout happens when the current delay exceeds the maximum delay
// |kPkcs11TokenMaxRequestDelay|.
constexpr base::TimeDelta kPkcs11TokenInitialRequestDelay =
    base::Milliseconds(100);
constexpr base::TimeDelta kPkcs11TokenMaxRequestDelay = base::Minutes(5);
constexpr int kPkcs11TokenDelayMultiplier = 2;

// This class handles getting the user or the system slot ID from chaps.
class Pkcs11SlotGetter {
 public:
  explicit Pkcs11SlotGetter(
      const std::string& user_hash = "",
      chaps::TokenManagerClient* test_chaps_client_ = nullptr);
  Pkcs11SlotGetter(const Pkcs11SlotGetter&) = delete;
  Pkcs11SlotGetter& operator=(const Pkcs11SlotGetter&) = delete;

  virtual ~Pkcs11SlotGetter() = default;

  // Get PKCS#11 slot ID value of |slot|. |slot| can either be user slot or
  // system slot. Upon failure, this will return pkcs11::kInvalidSlot. The slot
  // ID might not be ready when calling this method. Use this method only when
  // the synchronous call is necessary (e.g. when the TPM token is about to get
  // removed).
  virtual CK_SLOT_ID GetPkcs11SlotId(pkcs11::Slot slot);

  // The asynchronous version of GetPkcs11SlotId. Upon failure, this method
  // will retry to get the slot ID value. On timeout, this will return
  // pkcs11::kInvalidSlot. The retry is necessary as the TPM token might not
  // yet be ready.
  virtual void GetPkcs11SlotIdWithRetries(
      pkcs11::Slot slot,
      base::OnceCallback<void(CK_SLOT_ID)> callback,
      base::TimeDelta delay = kPkcs11TokenInitialRequestDelay);

  // Returns the user slot ID if |user_hash_| is valid, otherwise it returns the
  // system slot ID. Upon failure, pkcs11::kInvalidSlot is returned.
  virtual CK_SLOT_ID GetPkcs11DefaultSlotId();

  // Get the slot type (user or system) of |slot_id|.
  virtual pkcs11::Slot GetSlotType(CK_SLOT_ID slot_id);

 private:
  FRIEND_TEST(Pkcs11SlotGetterTest, GetInvalidUserSlot);
  FRIEND_TEST(Pkcs11SlotGetterTest, GetDefaultSlot_SystemSlot);

  // Get the slot ID value of slot type |slot|. |user_hash_| needs to be valid
  // in order to grab the user type slot.
  CK_SLOT_ID GetSlotId(pkcs11::Slot slot);

  // Cached user and system slot ID.
  CK_SLOT_ID user_slot_id_;
  CK_SLOT_ID system_slot_id_;

  // The hash of the currently active user.
  std::string user_hash_;

  // The default token manager client for accessing chapsd's Pkcs#11 interface
  chaps::TokenManagerClient default_chaps_client_{
      chaps::ThreadingMode::kCurrentThread};

  // The actual token manager client used by this class, usually set to
  // default_chaps_client_, but can be overridden for testing.
  chaps::TokenManagerClient* chaps_client_;

  base::WeakPtrFactory<Pkcs11SlotGetter> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_STORE_PKCS11_SLOT_GETTER_H_
