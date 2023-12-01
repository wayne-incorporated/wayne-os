// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_NSS_UTIL_H_
#define LOGIN_MANAGER_NSS_UTIL_H_

#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <crypto/scoped_nss_types.h>
#include <crypto/signature_verifier.h>

namespace crypto {
class RSAPrivateKey;
}

namespace login_manager {
// Forward declaration.
typedef struct PK11SlotInfoStr PK11SlotInfo;

struct PK11SlotDescriptor {
  crypto::ScopedPK11Slot slot;
  std::optional<base::FilePath> ns_mnt_path;
};

using OptionalFilePath = std::optional<base::FilePath>;

using ScopedPK11SlotDescriptor = std::unique_ptr<PK11SlotDescriptor>;

// An interface to wrap the usage of crypto/nss_util.h and allow for mocking.
class NssUtil {
 public:
  NssUtil();
  NssUtil(const NssUtil&) = delete;
  NssUtil& operator=(const NssUtil&) = delete;

  virtual ~NssUtil();

  // Creates an NssUtil. If there is no Factory (the default) this creates and
  // returns a new NssUtil.
  static std::unique_ptr<NssUtil> Create();

  // Returns empty ScopedPK11Slot in the event that the database cannot be
  // opened. Will attempt to enter the mount namespace at |ns_mnt_path|, if
  // present. The database is used to store the owner private key for consumer
  // users.
  virtual ScopedPK11SlotDescriptor OpenUserDB(
      const base::FilePath& user_homedir,
      const OptionalFilePath& ns_mnt_path) = 0;

  // Returns a read-only internal slot. Can be used to safely initialize NSS and
  // still perform operations on the slot even when session_manager doesn't need
  // to store the private key there.
  virtual ScopedPK11SlotDescriptor GetInternalSlot() = 0;

  // Will attempt to enter the mount namespace at |user_slot->ns_mnt_path|,
  // if present.
  virtual std::unique_ptr<crypto::RSAPrivateKey> GetPrivateKeyForUser(
      const std::vector<uint8_t>& public_key_der,
      PK11SlotDescriptor* user_slot) = 0;

  // Will attempt to enter the mount namespace at |user_slot->ns_mnt_path|,
  // if present.
  virtual std::unique_ptr<crypto::RSAPrivateKey> GenerateKeyPairForUser(
      PK11SlotDescriptor* user_slot) = 0;

  virtual base::FilePath GetOwnerKeyFilePath() = 0;

  // Returns subpath of the NSS DB; e.g. '.pki/nssdb'
  virtual base::FilePath GetNssdbSubpath() = 0;

  // Returns true if |blob| is a validly encoded NSS SubjectPublicKeyInfo.
  virtual bool CheckPublicKeyBlob(const std::vector<uint8_t>& blob) = 0;

  virtual bool Verify(
      const std::vector<uint8_t>& signature,
      const std::vector<uint8_t>& data,
      const std::vector<uint8_t>& public_key,
      const crypto::SignatureVerifier::SignatureAlgorithm algorithm) = 0;

  virtual bool Sign(const std::vector<uint8_t>& data,
                    crypto::RSAPrivateKey* key,
                    std::vector<uint8_t>* out_signature) = 0;
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_NSS_UTIL_H_
