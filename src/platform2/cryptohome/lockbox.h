// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Lockbox - class for storing tamper-evident data blobs.
#ifndef CRYPTOHOME_LOCKBOX_H_
#define CRYPTOHOME_LOCKBOX_H_

#include <memory>

#include <openssl/sha.h>

#include <base/strings/string_util.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/cryptohome/frontend.h>

#include "cryptohome/platform.h"

namespace cryptohome {

class LockboxContents;

enum class LockboxError {
  kNvramInvalid,
  kTpmUnavailable,
  kTpmError,  // Transient or unknown TPM error.
};

// Enable LockboxError to be used in LOG output.
std::ostream& operator<<(std::ostream& out, LockboxError error);

// Lockbox stores a blob of data in a tamper-evident manner.
//
// This class provides system integration for supporting tamper-evident
// storage using the TPM NVRAM locking and restricted TPM ownership to
// ensure that a data blob stored on disk has not been tampered with to
// the degree that can be cryptographically assured.
//
// Lockbox is not thread-safe and should not be accessed in parallel.
//
// A normal usage flow for Lockbox would be something as follows:
//
// Initializing new data against a lockbox (except with error checking :)
//   Lockbox lockbox(hwsec, hwsec::Space::kInstallAttributes);
//   LockboxError error;
//   lockbox->Create(&error);
//   lockbox->Store(mah_locked_data, &error);
//
// Verifying data is performed via class |LockboxContents|.
class Lockbox {
 public:
  // Populates the basic internal state of the Lockbox.
  //
  // Parameters
  // - hwsec: a required pointer to hwsec object.
  // - space: the space for lockbox.
  Lockbox(const hwsec::CryptohomeFrontend* hwsec, hwsec::Space space);

  Lockbox(const Lockbox&) = delete;
  Lockbox& operator=(const Lockbox&) = delete;

  virtual ~Lockbox();

  // Sets up the backend state needed for this lockbox.
  //
  // Instantiates a new TPM NVRAM index lockable bWriteDefine to store
  // the hash and blob size of the data to lock away.
  //
  // Parameters
  // - error: will contain the LockboxError if false.
  // Returns
  // - true if a new space was instantiated or an old one could be used.
  // - false if the space cannot be created or claimed.
  [[nodiscard]] virtual bool Reset(LockboxError* error);

  // Hashes, salts, sizes, and stores metadata required for verifying |data|
  // in TPM NVRAM for later verification.
  //
  // Parameters
  // - data: blob to store.
  // - error: LockboxError populated only on failure
  // Returns
  // - true if written to disk and NVRAM (if there is a tpm).
  // - false if the data could not be persisted.
  [[nodiscard]] virtual bool Store(const brillo::Blob& data,
                                   LockboxError* error);

 protected:
  // constructor for mock testing purpose.
  Lockbox() {}

 private:
  const hwsec::CryptohomeFrontend* hwsec_;
  hwsec::Space space_;
};

// Represents decoded lockbox NVRAM space contents and provides operations to
// encode/decode, as well as setting up and verifying integrity of a specific
// data blob.
class LockboxContents {
 public:
  enum class VerificationResult {
    kValid,
    kSizeMismatch,
    kHashMismatch,
  };

  static inline constexpr size_t kFixedPartSize =
      sizeof(uint32_t) + sizeof(uint8_t) + SHA256_DIGEST_LENGTH;
  static inline constexpr size_t kKeyMaterialSize = 32;
  static inline constexpr size_t kNvramSize = kKeyMaterialSize + kFixedPartSize;

  // Creates a LockboxContents instance that'll handle encoded lockbox contents
  // corresponding to an NVRAM space of size |nvram_size|. Returns nullptr in
  // case the passed |nvram_size| isn't supported.
  static std::unique_ptr<LockboxContents> New();

  size_t key_material_size() const { return key_material_.size(); }

  // Serialize to |nvram_data|.
  [[nodiscard]] bool Encode(brillo::SecureBlob* nvram_data);

  // Deserialize from |nvram_data|.
  [[nodiscard]] bool Decode(const brillo::SecureBlob& nvram_data);

  // Sets key material, which must be of key_material_size().
  [[nodiscard]] bool SetKeyMaterial(const brillo::SecureBlob& key_material);

  // Protect |blob|, i.e. compute the digest that will later make Verify() to
  // succeed if and only if a copy of |blob| is being passed.
  [[nodiscard]] bool Protect(const brillo::Blob& blob);

  // Verify |blob| against the lockbox contents.
  [[nodiscard]] VerificationResult Verify(const brillo::Blob& blob);

 private:
  LockboxContents() = default;

  uint32_t size_ = 0;
  uint8_t flags_ = 0;
  brillo::SecureBlob key_material_ = {0};
  uint8_t hash_[SHA256_DIGEST_LENGTH] = {0};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_LOCKBOX_H_
