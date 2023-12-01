// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_KEYRING_UTILS_H_
#define CRYPTOHOME_STORAGE_KEYRING_UTILS_H_

#include <string>

#include <brillo/secure_blob.h>

#include "cryptohome/storage/encrypted_container/filesystem_key.h"

namespace cryptohome {

namespace ecryptfs {

// Creates an ecryptfs auth token and installs it in the kernel keyring.
bool AddEcryptfsAuthToken(const brillo::SecureBlob& key,
                          const std::string& key_sig,
                          const brillo::SecureBlob& salt);

// Creates an ecryptfs auth token and installs it in the kernel keyring.
bool RemoveEcryptfsAuthToken(const std::string& key_sig);

}  // namespace ecryptfs

namespace dmcrypt {
// Generate the keyring description.
FileSystemKeyReference GenerateKeyringDescription(
    const brillo::SecureBlob& key_reference);

// Generates the key descriptor to be used in the device mapper table if the
// kernel keyring is supported.
brillo::SecureBlob GenerateDmcryptKeyDescriptor(
    const brillo::SecureBlob key_reference, uint64_t key_size);

// For dm-crypt, we use the process keyring to ensure that the key is unlinked
// if the process exits/crashes before it is cleared.
bool AddLogonKey(const brillo::SecureBlob& key,
                 const brillo::SecureBlob& key_reference);

// Removes the key from the keyring.
bool UnlinkLogonKey(const brillo::SecureBlob& key_reference);

}  // namespace dmcrypt

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_KEYRING_UTILS_H_
