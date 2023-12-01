// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_VAULT_KEYSET_FACTORY_H_
#define CRYPTOHOME_MOCK_VAULT_KEYSET_FACTORY_H_

#include <gmock/gmock.h>

namespace cryptohome {
class VaultKeyset;
class Platform;
class Crypto;

class MockVaultKeysetFactory : public VaultKeysetFactory {
 public:
  MockVaultKeysetFactory() {}
  virtual ~MockVaultKeysetFactory() {}
  MOCK_METHOD(VaultKeyset*, New, (Platform*, Crypto*), (override));
  MOCK_METHOD(VaultKeyset*, NewBackup, (Platform*, Crypto*), (override));
};
}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_VAULT_KEYSET_FACTORY_H_
