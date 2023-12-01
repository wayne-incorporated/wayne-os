// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_FILE_SYSTEM_KEYSET_TEST_UTILS_H_
#define CRYPTOHOME_STORAGE_FILE_SYSTEM_KEYSET_TEST_UTILS_H_

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/file_system_keyset.h"

namespace cryptohome {

MATCHER_P(FileSystemKeysetEquals, keyset, "") {
  return arg.Key().fek == keyset.Key().fek &&
         arg.Key().fnek == keyset.Key().fnek &&
         arg.Key().fek_salt == keyset.Key().fek_salt &&
         arg.Key().fnek_salt == keyset.Key().fnek_salt &&
         arg.KeyReference().fek_sig == keyset.KeyReference().fek_sig &&
         arg.KeyReference().fnek_sig == keyset.KeyReference().fnek_sig &&
         arg.chaps_key() == keyset.chaps_key();
}

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_FILE_SYSTEM_KEYSET_TEST_UTILS_H_
