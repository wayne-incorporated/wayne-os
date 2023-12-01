// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_FINGERPRINT_MANAGER_H_
#define CRYPTOHOME_MOCK_FINGERPRINT_MANAGER_H_

#include "cryptohome/fingerprint_manager.h"

#include <string>

namespace cryptohome {

class MockFingerprintManager : public FingerprintManager {
 public:
  MockFingerprintManager() {}
  virtual ~MockFingerprintManager() {}

  MOCK_METHOD(void,
              StartAuthSessionAsyncForUser,
              (const ObfuscatedUsername& user,
               StartSessionCallback auth_session_start_client_callback),
              (override));

  MOCK_METHOD(void,
              SetAuthScanDoneCallback,
              (ResultCallback auth_scan_done_callback),
              (override));

  MOCK_METHOD(void,
              SetSignalCallback,
              (SignalCallback signal_callback),
              (override));

  MOCK_METHOD(bool,
              HasAuthSessionForUser,
              (const ObfuscatedUsername& user),
              (override));

  MOCK_METHOD(void, EndAuthSession, (), (override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_FINGERPRINT_MANAGER_H_
