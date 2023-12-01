// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/keyring/utils.h"

#include <inttypes.h>
#include <keyutils.h>
#include <string>

#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>

#include "cryptohome/storage/encrypted_container/filesystem_key.h"

namespace cryptohome {

namespace ecryptfs {
extern "C" {
#include <ecryptfs.h>  // NOLINT(build/include_alpha)
}

bool AddEcryptfsAuthToken(  // NOLINT(runtime/int)
    const brillo::SecureBlob& key,
    const std::string& key_sig,
    const brillo::SecureBlob& salt) {
  DCHECK_EQ(static_cast<size_t>(ECRYPTFS_MAX_KEY_BYTES), key.size());
  DCHECK_EQ(static_cast<size_t>(ECRYPTFS_SIG_SIZE) * 2, key_sig.length());
  DCHECK_EQ(static_cast<size_t>(ECRYPTFS_SALT_SIZE), salt.size());

  struct ecryptfs_auth_tok auth_token;

  generate_payload(&auth_token, const_cast<char*>(key_sig.c_str()),
                   const_cast<char*>(salt.char_data()),
                   const_cast<char*>(key.char_data()));

  bool ret = ecryptfs_add_auth_tok_to_keyring(
                 &auth_token, const_cast<char*>(key_sig.c_str())) >= 0;
  brillo::SecureClearObject(auth_token);
  return ret;
}

bool RemoveEcryptfsAuthToken(const std::string& key_sig) {
  return ecryptfs_remove_auth_tok_from_keyring(
             const_cast<char*>(key_sig.c_str())) >= 0;
}

}  // namespace ecryptfs

namespace dircrypto {}  // namespace dircrypto

namespace dmcrypt {

constexpr char kKeyring[] = "logon";
constexpr char kDmcryptKeyDescriptor[] = "dmcrypt:";

// Generate the keyring description.
FileSystemKeyReference GenerateKeyringDescription(
    const brillo::SecureBlob& key_reference) {
  return {
      .fek_sig = brillo::SecureBlob::Combine(
          brillo::SecureBlob(kDmcryptKeyDescriptor),
          brillo::SecureBlob(base::ToLowerASCII(
              base::HexEncode(key_reference.data(), key_reference.size())))),
  };
}

// Generates the key descriptor to be used in the device mapper table if the
// kernel keyring is supported.
brillo::SecureBlob GenerateDmcryptKeyDescriptor(
    const brillo::SecureBlob key_reference, uint64_t key_size) {
  brillo::SecureBlob key_desc(
      base::StringPrintf(":%" PRIu64 ":%s:", key_size, kKeyring));
  return brillo::SecureBlob::Combine(key_desc, key_reference);
}

// For dm-crypt, we use the process keyring to ensure that the key is unlinked
// if the process exits/crashes before it is cleared.
bool AddLogonKey(const brillo::SecureBlob& key,
                 const brillo::SecureBlob& key_reference) {
  if (add_key(kKeyring, key_reference.char_data(), key.char_data(), key.size(),
              KEY_SPEC_SESSION_KEYRING) == -1) {
    PLOG(ERROR) << "add_key failed";
    return false;
  }

  return true;
}

bool UnlinkLogonKey(const brillo::SecureBlob& key_reference) {
  key_serial_t key = keyctl_search(KEY_SPEC_SESSION_KEYRING, kKeyring,
                                   key_reference.char_data(), 0);

  if (key == -1) {
    PLOG(ERROR) << "keyctl_search failed";
    return false;
  }

  if (keyctl_invalidate(key) != 0) {
    LOG(ERROR) << "Failed to invalidate key " << key;
    return false;
  }

  return true;
}

}  // namespace dmcrypt

}  // namespace cryptohome
