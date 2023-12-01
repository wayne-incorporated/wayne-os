// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SLOT_MANAGER_MOCK_H_
#define CHAPS_SLOT_MANAGER_MOCK_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chaps/slot_manager.h"
#include "pkcs11/cryptoki.h"

namespace chaps {

class SlotManagerMock : public SlotManager {
 public:
  SlotManagerMock();
  SlotManagerMock(const SlotManagerMock&) = delete;
  SlotManagerMock& operator=(const SlotManagerMock&) = delete;

  ~SlotManagerMock() override;

  MOCK_METHOD0(GetSlotCount, int());
  MOCK_CONST_METHOD2(IsTokenPresent, bool(const brillo::SecureBlob&, int));
  MOCK_CONST_METHOD2(IsTokenAccessible, bool(const brillo::SecureBlob&, int));
  MOCK_CONST_METHOD3(GetSlotInfo,
                     void(const brillo::SecureBlob&, int, CK_SLOT_INFO*));
  MOCK_CONST_METHOD3(GetTokenInfo,
                     void(const brillo::SecureBlob&, int, CK_TOKEN_INFO*));
  MOCK_CONST_METHOD2(GetMechanismInfo,
                     MechanismMap*(const brillo::SecureBlob&, int));
  MOCK_METHOD3(OpenSession, int(const brillo::SecureBlob&, int, bool));
  MOCK_METHOD2(CloseSession, bool(const brillo::SecureBlob&, int));
  MOCK_METHOD2(CloseAllSessions, void(const brillo::SecureBlob&, int));
  MOCK_CONST_METHOD3(GetSession,
                     bool(const brillo::SecureBlob&, int, Session**));
};

}  // namespace chaps

#endif  // CHAPS_SLOT_MANAGER_MOCK_H_
