// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_DIRCRYPTO_UTIL_H_
#define CRYPTOHOME_DIRCRYPTO_UTIL_H_

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>
#include <brillo/secure_blob.h>

extern "C" {
#include <keyutils.h>
#include <linux/fscrypt.h>
}

namespace dircrypto {

// State of the directory's encryption key.
enum class KeyState {
  UNKNOWN,        // Cannot get the state.
  NOT_SUPPORTED,  // The directory doesn't support dircrypto.
  NO_KEY,         // No key is set.
  ENCRYPTED,      // Key is set.

  // Must be the last item.
  kMaxValue = ENCRYPTED
};

// KeyReference describes an in-use fscrypt key.
struct KeyReference {
  // Policy version: FSCRYPT_POLICY_V2 is only supported on kernels >= 5.4.
  int policy_version = FSCRYPT_POLICY_V1;
  // Key identifier/descriptor.
  brillo::SecureBlob reference;
};

// keyutils functions use -1 as the invalid key serial value.
inline constexpr key_serial_t kInvalidKeySerial = -1;

// Checks if the device supports fscrypt key add/remove ioctls.
bool CheckFscryptKeyIoctlSupport();

// Sets the directory key.
bool SetDirectoryKey(const base::FilePath& dir,
                     const KeyReference& key_reference);

// Adds the directory key.
BRILLO_EXPORT bool AddDirectoryKey(const brillo::SecureBlob& key,
                                   KeyReference* key_reference);

// Removes the directory key.
BRILLO_EXPORT bool RemoveDirectoryKey(const KeyReference& key_reference,
                                      const base::FilePath& dir);

// Returns the directory's key state, or returns UNKNOWN on errors.
BRILLO_EXPORT KeyState GetDirectoryKeyState(const base::FilePath& dir);

// Returns the directory's policy version or returns -1.
int GetDirectoryPolicyVersion(const base::FilePath& dir);

}  // namespace dircrypto

#endif  // CRYPTOHOME_DIRCRYPTO_UTIL_H_
