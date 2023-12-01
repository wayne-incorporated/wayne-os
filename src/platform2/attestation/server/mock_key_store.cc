// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/mock_key_store.h"

using ::testing::_;
using ::testing::Return;

namespace attestation {

MockKeyStore::MockKeyStore() {
  ON_CALL(*this, Read(_, _, _)).WillByDefault(Return(true));
  ON_CALL(*this, Write(_, _, _)).WillByDefault(Return(true));
  ON_CALL(*this, Delete(_, _)).WillByDefault(Return(true));
  ON_CALL(*this, DeleteByPrefix(_, _)).WillByDefault(Return(true));
  ON_CALL(*this, Register(_, _, _, _, _, _, _)).WillByDefault(Return(true));
  ON_CALL(*this, RegisterCertificate(_, _)).WillByDefault(Return(true));
}

MockKeyStore::~MockKeyStore() {}

}  // namespace attestation
