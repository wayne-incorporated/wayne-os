// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/vault_keyset_factory.h"

#include "cryptohome/vault_keyset.h"

namespace cryptohome {

VaultKeysetFactory::VaultKeysetFactory() {}
VaultKeysetFactory::~VaultKeysetFactory() {}

VaultKeyset* VaultKeysetFactory::New(Platform* platform, Crypto* crypto) {
  VaultKeyset* v = new VaultKeyset();
  v->Initialize(platform, crypto);
  return v;
}

VaultKeyset* VaultKeysetFactory::NewBackup(Platform* platform, Crypto* crypto) {
  VaultKeyset* v = new VaultKeyset();
  v->InitializeAsBackup(platform, crypto);
  return v;
}

}  // namespace cryptohome
