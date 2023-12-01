// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOUNT_ENCRYPTED_ENCRYPTION_KEY_H_
#define CRYPTOHOME_MOUNT_ENCRYPTED_ENCRYPTION_KEY_H_

#include <stdint.h>

#include <string>
#include <vector>

#include <base/files/file_path.h>

#include <brillo/secure_blob.h>

#include "cryptohome/mount_encrypted/mount_encrypted.h"

namespace mount_encrypted {

class SystemKeyLoader;

// EncryptionKey takes care of the lifecycle of the encryption key protecting
// the encrypted stateful file system. This includes generation of the key,
// wrapping it using a system key which is stored in TPM NVRAM, as well as
// storing and loading the key to/from disk.
class EncryptionKey {
 public:
  // Describes the status of the system key for metrics reporting purposes.
  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class SystemKeyStatus {
    kUnknown,              // No key loaded yet.
    kNVRAMLockbox,         // Using lockbox salt as system key.
    kNVRAMEncstateful,     // Key in dedicated encstateful NVRAM space.
    kFinalizationPending,  // TPM not ready, obfuscated key on on disk.
    kKernelCommandLine,    // Key from kernel command line.
    kProductUUID,          // Using product UUID as system key.
    kStaticFallback,       // Using hard-coded fallback key.
    kCount,                // Must be last (and may be re-assigned).
  };

  // Describes the status of the encryption key for metrics reporting purposes.
  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class EncryptionKeyStatus {
    kUnknown,            // Key not loaded yet.
    kKeyFile,            // Key loaded from encrypted.key file.
    kNeedsFinalization,  // Key loaded from needs-finalization file.
    kFresh,              // Freshly generated key.
    kCount,              // Must be last (and may be re-assigned).
  };

  EncryptionKey(SystemKeyLoader* loader, const base::FilePath& rootdir);

  // Loads the system key from TPM NVRAM via |loader_|.
  result_code SetTpmSystemKey();

  // Determines the system key to use in a production image on Chrome OS
  // hardware. Attempts to load the system key from TPM NVRAM via |loader_| or
  // generates a new system key. As a last resort, allows to continue without a
  // system key to cover systems where the NVRAM space is yet to be created by
  // cryptohomed.
  result_code LoadChromeOSSystemKey();

  // While ChromeOS devices can store the system key in the NVRAM area, all the
  // rest will fallback through various places (kernel command line, BIOS UUID,
  // and finally a static value) for a system key.
  result_code SetInsecureFallbackSystemKey();

  // Load the encryption key from disk using the previously loaded system key.
  result_code LoadEncryptionKey();

  // Get a key derived from |system_key_| by performing an HMAC256 operation on
  // it with |label| being the data to do the HMAC operation on.
  // If |system_key_| is empty, it returns an empty blob.
  brillo::SecureBlob GetDerivedSystemKey(const std::string& label) const;

  const brillo::SecureBlob& encryption_key() const { return encryption_key_; }
  bool is_fresh() const {
    return encryption_key_status_ == EncryptionKeyStatus::kFresh;
  }
  bool did_finalize() const { return did_finalize_; }

  base::FilePath key_path() const { return key_path_; }
  base::FilePath needs_finalization_path() const {
    return needs_finalization_path_;
  }
  base::FilePath preservation_request_path() const {
    return preservation_request_path_;
  }
  base::FilePath preserved_previous_key_path() const {
    return preserved_previous_key_path_;
  }
  SystemKeyStatus system_key_status() const { return system_key_status_; }
  EncryptionKeyStatus encryption_key_status() const {
    return encryption_key_status_;
  }

 private:
  // Encrypts the |encryption_key_| under |system_key_| and writes the result to
  // disk to the |key_path_| file.
  void Finalize();

  // Loads the previous system key and encryption key and rewraps the latter
  // under a fresh system key. This allows carrying over the encryption key (and
  // thus the encrypted) file system across a TPM clear.
  bool RewrapPreviousEncryptionKey();

  SystemKeyLoader* loader_ = nullptr;

  // Paths.
  base::FilePath key_path_;
  base::FilePath needs_finalization_path_;
  base::FilePath preservation_request_path_;
  base::FilePath preserved_previous_key_path_;

  // The system key is usually the key stored in TPM NVRAM that wraps the actual
  // encryption key. Empty if not available.
  brillo::SecureBlob system_key_;

  // The encryption key used for file system encryption.
  brillo::SecureBlob encryption_key_;

  // Whether finalization took place during Persist().
  bool did_finalize_ = false;

  // System key status. Only valid after one of the system key loading functions
  // has been called.
  SystemKeyStatus system_key_status_ = SystemKeyStatus::kUnknown;

  // Encryption key status. Only valid after calling LoadEncryptionKey().
  EncryptionKeyStatus encryption_key_status_ = EncryptionKeyStatus::kUnknown;
};

}  // namespace mount_encrypted

#endif  // CRYPTOHOME_MOUNT_ENCRYPTED_ENCRYPTION_KEY_H_
