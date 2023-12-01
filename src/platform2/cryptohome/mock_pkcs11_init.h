// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_PKCS11_INIT_H_
#define CRYPTOHOME_MOCK_PKCS11_INIT_H_

#include "cryptohome/pkcs11_init.h"

#include <gmock/gmock.h>

namespace cryptohome {

class MockPkcs11Init : public Pkcs11Init {
 public:
  MockPkcs11Init();
  virtual ~MockPkcs11Init();

  MOCK_METHOD(bool,
              GetTpmTokenSlotForPath,
              (const base::FilePath&, CK_SLOT_ID_PTR),
              (override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_PKCS11_INIT_H_
