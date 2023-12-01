// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mount_encrypted/encryption_key.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/file_utils.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>

#include "cryptohome/mount_encrypted/mount_encrypted.h"
#include "cryptohome/mount_encrypted/tpm.h"

namespace mount_encrypted {
namespace paths {
const char kStatefulMount[] = "mnt/stateful_partition";
const char kEncryptedKey[] = "encrypted.key";
const char kNeedsFinalization[] = "encrypted.needs-finalization";
const char kKernelCmdline[] = "/proc/cmdline";
const char kProductUUID[] = "/sys/class/dmi/id/product_uuid";
const char kStatefulPreservationRequest[] = "preservation_request";
const char kPreservedPreviousKey[] = "encrypted.key.preserved";
}  // namespace paths

namespace {

const char kKernelCmdlineOption[] = "encrypted-stateful-key=";
const char kStaticKeyDefault[] = "default unsafe static key";
const char kStaticKeyFinalizationNeeded[] = "needs finalization";

const size_t kMaxReadSize = 4 * 1024;

bool ReadKeyFile(const base::FilePath& path,
                 brillo::SecureBlob* plaintext,
                 const brillo::SecureBlob& encryption_key) {
  std::string ciphertext;
  if (!base::ReadFileToStringWithMaxSize(path, &ciphertext, kMaxReadSize)) {
    LOG(ERROR) << "Data read failed from " << path;
    return false;
  }

  if (!hwsec_foundation::AesDecryptSpecifyBlockMode(
          brillo::SecureBlob(ciphertext), 0, ciphertext.size(), encryption_key,
          brillo::SecureBlob(hwsec_foundation::kAesBlockSize),
          hwsec_foundation::PaddingScheme::kPaddingStandard,
          hwsec_foundation::BlockMode::kCbc, plaintext)) {
    LOG(ERROR) << "Decryption failed for data from " << path;
    return false;
  }

  // The decryption is succeed when the plaintext size is correct.
  if (plaintext->size() != DIGEST_LENGTH) {
    LOG(ERROR) << "Decryption result size mismatch for data from " << path
               << ", expected size:" << DIGEST_LENGTH
               << ", actual size:" << plaintext->size();
    return false;
  }
  return true;
}

bool WriteKeyFile(const base::FilePath& path,
                  const brillo::SecureBlob& plaintext,
                  const brillo::SecureBlob& encryption_key) {
  if (base::PathExists(path)) {
    LOG(ERROR) << path << " already exists.";
    return false;
  }

  // Note that we pass an all-zeros IV. In general, this is dangerous since
  // identical plaintext will lead to identical ciphertext, revealing the fact
  // that the same message has been encrypted. This can potentially be used in
  // chosen plaintext attacks to determine the plaintext for a given ciphertext.
  // In the case at hand, we only ever encrypt a single message using the system
  // key and don't allow attackers to inject plaintext, so we are good.
  //
  // Ideally, we'd generate a random IV and stored it to disk as well, but
  // switching over to the safer scheme would have to be done in a
  // backwards-compatible way, so for now it isn't worth it.
  brillo::SecureBlob ciphertext;
  if (!hwsec_foundation::AesEncryptSpecifyBlockMode(
          plaintext, 0, plaintext.size(), encryption_key,
          brillo::SecureBlob(hwsec_foundation::kAesBlockSize),
          hwsec_foundation::PaddingScheme::kPaddingStandard,
          hwsec_foundation::BlockMode::kCbc, &ciphertext)) {
    LOG(ERROR) << "Encryption failed for " << path;
    return false;
  }

  if (!brillo::WriteBlobToFileAtomic(path, ciphertext, 0600) ||
      !brillo::SyncFileOrDirectory(path.DirName(), true, false)) {
    PLOG(ERROR) << "Unable to write " << path;
    return false;
  }

  return true;
}

// ShredFile - Overwrite file contents. Useless on SSD. :(
// Currently, if the TPM is not ready, we encrypt the encryption key data
// with a static key and write it to disk. This function is a best-attempt to
// clear the contents of the key file.
// We'd ideally never write an insufficiently protected key to disk. This
// is already the case for TPM 2.0 devices as they can create system keys as
// needed, and we can improve the situation for TPM 1.2 devices as well by (1)
// using an NVRAM space that doesn't get lost on TPM clear and (2) allowing
// mount-encrypted to take ownership and create the NVRAM space if necessary.
void ShredFile(const base::FilePath& file) {
  uint8_t patterns[] = {0xA5, 0x5A, 0xFF, 0x00};
  FILE* target;
  struct stat info;
  uint8_t* pattern;
  int i;

  // Give up if we can't safely open or stat the target.
  base::ScopedFD fd(HANDLE_EINTR(
      open(file.value().c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << file;
    return;
  }
  if (fstat(fd.get(), &info)) {
    PLOG(ERROR) << file;
    return;
  }
  if (!(target = fdopen(fd.get(), "w"))) {
    PLOG(ERROR) << file;
    return;
  }

  // Ignore errors here, since there's nothing we can really do.
  pattern = static_cast<uint8_t*>(malloc(info.st_size));
  for (i = 0; i < sizeof(patterns); ++i) {
    memset(pattern, patterns[i], info.st_size);
    if (fseek(target, 0, SEEK_SET))
      PLOG(ERROR) << file;
    if (fwrite(pattern, info.st_size, 1, target) != 1)
      PLOG(ERROR) << file;
    if (fflush(target))
      PLOG(ERROR) << file;
    if (fdatasync(fd.get()))
      PLOG(ERROR) << file;
  }
}

brillo::SecureBlob Sha256(const std::string& str) {
  brillo::SecureBlob blob(str);
  return hwsec_foundation::Sha256(blob);
}

brillo::SecureBlob GetUselessKey() {
  return Sha256(kStaticKeyFinalizationNeeded);
}

// Extract the desired system key from the kernel's boot command line.
brillo::SecureBlob GetKeyFromKernelCmdline() {
  std::string cmdline;
  if (!base::ReadFileToStringWithMaxSize(base::FilePath(paths::kKernelCmdline),
                                         &cmdline, kMaxReadSize)) {
    PLOG(ERROR) << "Failed to read kernel command line";
    return brillo::SecureBlob();
  }

  // Find a string match either at start of string or following a space.
  size_t pos = cmdline.find(kKernelCmdlineOption);
  if (pos == std::string::npos || !(pos == 0 || cmdline[pos - 1] == ' ')) {
    return brillo::SecureBlob();
  }

  std::string value = cmdline.substr(pos + strlen(kKernelCmdlineOption));
  value = value.substr(0, value.find(' '));

  brillo::SecureBlob key = Sha256(value);
  return key;
}

}  // namespace

EncryptionKey::EncryptionKey(SystemKeyLoader* loader,
                             const base::FilePath& rootdir)
    : loader_(loader) {
  base::FilePath stateful_mount = rootdir.AppendASCII(paths::kStatefulMount);
  key_path_ = stateful_mount.AppendASCII(paths::kEncryptedKey);
  needs_finalization_path_ =
      stateful_mount.AppendASCII(paths::kNeedsFinalization);
  preservation_request_path_ =
      stateful_mount.AppendASCII(paths::kStatefulPreservationRequest);
  preserved_previous_key_path_ =
      stateful_mount.AppendASCII(paths::kPreservedPreviousKey);
}

result_code EncryptionKey::SetTpmSystemKey() {
  result_code rc = loader_->Load(&system_key_);
  if (rc == RESULT_SUCCESS) {
    LOG(INFO) << "Using NVRAM as system key; already populated.";
  } else {
    LOG(INFO) << "Using NVRAM as system key; finalization needed.";
  }

  return rc;
}

result_code EncryptionKey::SetInsecureFallbackSystemKey() {
  system_key_ = GetKeyFromKernelCmdline();
  if (!system_key_.empty()) {
    LOG(INFO) << "Using kernel command line argument as system key.";
    system_key_status_ = SystemKeyStatus::kKernelCommandLine;
    return RESULT_SUCCESS;
  }

  std::string product_uuid;
  if (base::ReadFileToStringWithMaxSize(base::FilePath(paths::kProductUUID),
                                        &product_uuid, kMaxReadSize)) {
    system_key_ = Sha256(base::ToUpperASCII(product_uuid));
    LOG(INFO) << "Using UUID as system key.";
    system_key_status_ = SystemKeyStatus::kProductUUID;
    return RESULT_SUCCESS;
  }

  LOG(INFO) << "Using default insecure system key.";
  system_key_ = Sha256(kStaticKeyDefault);
  system_key_status_ = SystemKeyStatus::kStaticFallback;
  return RESULT_SUCCESS;
}

result_code EncryptionKey::LoadChromeOSSystemKey() {
  SetTpmSystemKey();

  // Check and handle potential requests to preserve an already existing
  // encryption key in order to retain the existing stateful file system.
  if (system_key_.empty() && base::PathExists(preservation_request_path_)) {
    // Move the previous key file to a different path and clear the request
    // before changing TPM state. This makes sure that we're not putting the
    // system into a state where the old key might get picked up accidentally
    // (even by previous versions of mount-encrypted on rollback) if we reboot
    // while the preservation process is not completed yet (for example due to
    // power loss).
    if (!base::Move(key_path_, preserved_previous_key_path_)) {
      base::DeleteFile(key_path_);
    }
    base::DeleteFile(preservation_request_path_);
  }

  // Note that we must check for presence of a to-be-preserved key
  // unconditionally: If the preservation process doesn't complete on first
  // attempt (e.g. due to crash or power loss) but already took TPM ownership,
  // we might see a situation where there appears to be a valid system key but
  // we still must retry preservation to salvage the previous key.
  if (base::PathExists(preserved_previous_key_path_)) {
    RewrapPreviousEncryptionKey();

    // Preservation is done at this point even though it might have bailed or
    // failed. The code below will handle the potentially absent system key.
    base::DeleteFile(preserved_previous_key_path_);
  }

  // Attempt to generate a fresh system key if we haven't found one.
  if (system_key_.empty()) {
    LOG(INFO) << "Attempting to generate fresh NVRAM system key.";

    const auto key_material =
        hwsec_foundation::CreateSecureRandomBlob(DIGEST_LENGTH);
    result_code rc = loader_->Initialize(key_material, &system_key_);
    if (rc != RESULT_SUCCESS) {
      LOG(ERROR) << "Failed to initialize system key NV space contents.";
      return rc;
    }

    if (!system_key_.empty() && loader_->Persist() != RESULT_SUCCESS) {
      system_key_.clear();
    }
  }

  // Lock the system key to to prevent subsequent manipulation.
  loader_->Lock();

  // Determine and record the system key status.
  if (system_key_.empty()) {
    system_key_status_ = SystemKeyStatus::kFinalizationPending;
  } else if (loader_->UsingLockboxKey()) {
    system_key_status_ = SystemKeyStatus::kNVRAMLockbox;
  } else {
    system_key_status_ = SystemKeyStatus::kNVRAMEncstateful;
  }

  return RESULT_SUCCESS;
}

result_code EncryptionKey::LoadEncryptionKey() {
  if (!system_key_.empty()) {
    if (ReadKeyFile(key_path_, &encryption_key_, system_key_)) {
      encryption_key_status_ = EncryptionKeyStatus::kKeyFile;
      return RESULT_SUCCESS;
    }
    LOG(INFO) << "Failed to load encryption key from disk.";
  } else {
    LOG(INFO) << "No usable system key found.";
  }

  // Delete any stale encryption key files from disk. This is important because
  // presence of the key file determines whether finalization requests from
  // cryptohome do need to write a key file.
  base::DeleteFile(key_path_);
  encryption_key_.clear();

  // Check if there's a to-be-finalized key on disk.
  if (!ReadKeyFile(needs_finalization_path_, &encryption_key_,
                   GetUselessKey())) {
    // This is a brand new system with no keys, so generate a fresh one.
    LOG(INFO) << "Generating new encryption key.";
    encryption_key_ = hwsec_foundation::CreateSecureRandomBlob(DIGEST_LENGTH);
    encryption_key_status_ = EncryptionKeyStatus::kFresh;
  } else {
    encryption_key_status_ = EncryptionKeyStatus::kNeedsFinalization;
    LOG(ERROR) << "Finalization unfinished! Encryption key still on disk!";
  }

  // At this point, we have an encryption key but it has not been finalized yet
  // (i.e. encrypted under the system key and stored on disk in the key file).
  //
  // However, when we are creating the encrypted mount for the first time, the
  // TPM might not be in a state where we have a system key. In this case we
  // fall back to writing the obfuscated encryption key to disk (*sigh*).
  //
  // NB: We'd ideally never write an insufficiently protected key to disk. This
  // is already the case for TPM 2.0 devices as they can create system keys as
  // needed, and we can improve the situation for TPM 1.2 devices as well by (1)
  // using an NVRAM space that doesn't get lost on TPM clear and (2) allowing
  // mount-encrypted to take ownership and create the NVRAM space if necessary.
  if (system_key_.empty()) {
    if (is_fresh()) {
      LOG(INFO) << "Writing finalization intent " << needs_finalization_path_;
      if (!WriteKeyFile(needs_finalization_path_, encryption_key_,
                        GetUselessKey())) {
        LOG(ERROR) << "Failed to write " << needs_finalization_path_;
      }
    }
    return RESULT_SUCCESS;
  }

  // We have a system key, so finalize now.
  Finalize();

  return RESULT_SUCCESS;
}

brillo::SecureBlob EncryptionKey::GetDerivedSystemKey(
    const std::string& label) const {
  if (!system_key_.empty() &&
      system_key_status_ == EncryptionKey::SystemKeyStatus::kNVRAMEncstateful) {
    return hwsec_foundation::HmacSha256(system_key_, brillo::SecureBlob(label));
  }

  return brillo::SecureBlob();
}

void EncryptionKey::Finalize() {
  CHECK(!system_key_.empty());
  CHECK(!encryption_key_.empty());

  LOG(INFO) << "Writing keyfile " << key_path_;
  if (!WriteKeyFile(key_path_, encryption_key_, system_key_)) {
    LOG(ERROR) << "Failed to write " << key_path_;
    return;
  }

  // Finalization is complete at this point.
  did_finalize_ = true;

  // Make a best effort attempt to wipe the obfuscated key file from disk. This
  // is unreliable on many levels, in particular ext4 doesn't support secure
  // delete so the data may end up sticking around in the journal. Furthermore,
  // SSDs may remap flash blocks on write, so the data may physically remain in
  // the old block. See comment above regarding options to get rid of the
  // finalization intent file in the long run.
  if (base::PathExists(needs_finalization_path_)) {
    ShredFile(needs_finalization_path_);
    base::DeleteFile(needs_finalization_path_);
  }
}

bool EncryptionKey::RewrapPreviousEncryptionKey() {
  // Key preservation has been requested, but we haven't performed the process
  // of carrying over the encryption key yet, or we have started and didn't
  // finish the last attempt.
  LOG(INFO) << "Attempting to preserve previous encryption key.";

  // Load the previous system key and set up a fresh system key to re-wrap the
  // encryption key.
  brillo::SecureBlob fresh_system_key;
  brillo::SecureBlob previous_system_key;
  if (loader_->GenerateForPreservation(&previous_system_key,
                                       &fresh_system_key) != RESULT_SUCCESS) {
    return false;
  }

  brillo::SecureBlob previous_encryption_key;
  if (!ReadKeyFile(preserved_previous_key_path_, &previous_encryption_key,
                   previous_system_key)) {
    LOG(WARNING) << "Failed to decrypt preserved previous key, aborting.";
    return false;
  }

  // We have the previous encryption key at this point, so we're in business.
  // Re-wrap the encryption key under the new system key and store it to disk.
  base::DeleteFile(key_path_);
  if (!WriteKeyFile(key_path_, previous_encryption_key, fresh_system_key)) {
    return false;
  }

  // Persist the fresh system key. It's important that the fresh system key gets
  // written to the NVRAM space as the last step (in particular, only after the
  // encryption key has been re-wrapped). Otherwise, a crash would lead to a
  // situation where the new system key has already replaced the old one,
  // leaving us with no way to recover the preserved encryption key.
  if (loader_->Persist() != RESULT_SUCCESS) {
    return false;
  }

  // Success. Put the keys in place for later usage.
  system_key_ = std::move(fresh_system_key);

  LOG(INFO) << "Successfully preserved encryption key.";

  return true;
}

}  // namespace mount_encrypted
