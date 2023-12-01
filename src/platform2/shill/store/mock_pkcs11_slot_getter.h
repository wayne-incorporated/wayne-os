// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_MOCK_PKCS11_SLOT_GETTER_H_
#define SHILL_STORE_MOCK_PKCS11_SLOT_GETTER_H_

#include <chaps/pkcs11/cryptoki.h>

#include <gmock/gmock.h>

#include <shill/store/pkcs11_slot_getter.h>

namespace shill {

class MockPkcs11SlotGetter : public Pkcs11SlotGetter {
 public:
  MockPkcs11SlotGetter();
  MockPkcs11SlotGetter(const MockPkcs11SlotGetter&) = delete;
  MockPkcs11SlotGetter& operator=(const MockPkcs11SlotGetter&) = delete;

  ~MockPkcs11SlotGetter() override;

  MOCK_METHOD(CK_SLOT_ID, GetPkcs11SlotId, (pkcs11::Slot), (override));
  MOCK_METHOD(void,
              GetPkcs11SlotIdWithRetries,
              (pkcs11::Slot,
               base::OnceCallback<void(CK_SLOT_ID)>,
               base::TimeDelta),
              (override));
  MOCK_METHOD(CK_SLOT_ID, GetPkcs11DefaultSlotId, (), (override));
};

}  // namespace shill

#endif  // SHILL_STORE_MOCK_PKCS11_SLOT_GETTER_H_
