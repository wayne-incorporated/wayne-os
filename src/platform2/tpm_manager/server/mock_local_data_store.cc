// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/mock_local_data_store.h"

using testing::_;
using testing::ByRef;
using testing::DoAll;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;

namespace tpm_manager {

MockLocalDataStore::MockLocalDataStore() {
  ON_CALL(*this, Read(_))
      .WillByDefault(DoAll(SetArgPointee<0>(ByRef(fake_)), Return(true)));
  ON_CALL(*this, Write(_))
      .WillByDefault(DoAll(SaveArg<0>(&fake_), Return(true)));
}
MockLocalDataStore::~MockLocalDataStore() {}

}  // namespace tpm_manager
