// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTOHOME_COMMON_H_
#define CRYPTOHOME_CRYPTOHOME_COMMON_H_

#include <stdint.h>

namespace cryptohome {

// Constants used in both service.cc and userdataauth.cc
static constexpr char kPublicMountSaltFilePath[] = "/var/lib/public_mount_salt";

// The default symmetric key size for cryptohome is the ecryptfs default
#define CRYPTOHOME_DEFAULT_KEY_SIZE 64           // ECRYPTFS_MAX_KEY_BYTES
#define CRYPTOHOME_DEFAULT_KEY_SIGNATURE_SIZE 8  // ECRYPTFS_SIG_SIZE
#define CRYPTOHOME_DEFAULT_KEY_SALT_SIZE 8       // ECRYPTFS_SALT_SIZE
#define CRYPTOHOME_AES_KEY_BYTES 16              // ECRYPTFS_AES_KEY_BYTES
// The default salt length for the user salt
#define CRYPTOHOME_DEFAULT_SALT_LENGTH 16
#define CRYPTOHOME_PWNAME_BUF_LENGTH 1024
#define CRYPTOHOME_CHAPS_KEY_LENGTH 16  // AES block size
#define CRYPTOHOME_RESET_SEED_LENGTH 32
// Always 32 bytes per the firmware.
#define CRYPTOHOME_RESET_SECRET_LENGTH 32
// UserSecretStash file system encryption keys are 512 bits.
#define CRYPTOHOME_DEFAULT_512_BIT_KEY_SIZE 64

struct VaultKeysetKeys {
  unsigned char fek[CRYPTOHOME_DEFAULT_KEY_SIZE];
  unsigned char fek_sig[CRYPTOHOME_DEFAULT_KEY_SIGNATURE_SIZE];
  unsigned char fek_salt[CRYPTOHOME_DEFAULT_KEY_SALT_SIZE];
  unsigned char fnek[CRYPTOHOME_DEFAULT_KEY_SIZE];
  unsigned char fnek_sig[CRYPTOHOME_DEFAULT_KEY_SIGNATURE_SIZE];
  unsigned char fnek_salt[CRYPTOHOME_DEFAULT_KEY_SALT_SIZE];
} __attribute__((__packed__));
typedef struct VaultKeysetKeys VaultKeysetKeys;

}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTOHOME_COMMON_H_
