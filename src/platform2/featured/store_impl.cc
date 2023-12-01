// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "featured/store_impl.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <brillo/secure_blob.h>
#include <brillo/files/file_util.h>
#include <brillo/secure_string.h>
#include <featured/proto_bindings/featured.pb.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <sys/stat.h>

namespace featured {

constexpr char kStorePath[] = "/var/lib/featured/store";
// No longer used; this constant is only here to clean up older usage of this
// file.
constexpr char kStoreHMACPath[] = "/var/lib/featured/store_hmac";

constexpr mode_t kSystemFeaturedFilesMode = 0760;

constexpr size_t kTpmSeedSize = 32;
// File where the TPM seed is stored, that we have to read from.
constexpr char kTpmSeedTmpFile[] = "/run/featured_seed/tpm_seed";

namespace {

// Walks the directory tree to make sure we avoid symlinks.
// Creates |path| if it does not exist.
//
// All parent parts must already exist else we return false.
bool ValidatePathAndOpen(const base::FilePath& path,
                         int* outfd,
                         int flags = 0) {
  std::vector<std::string> components = path.GetComponents();
  if (components.empty()) {
    LOG(ERROR) << "Cannot open an empty path";
    return false;
  }

  int parentfd = AT_FDCWD;
  for (auto it = components.begin(); it != components.end(); ++it) {
    std::string component = *it;
    int fd;
    if (it == components.end() - 1) {
      // Check that the last component is a valid file and open it for reading
      // and writing.
      fd = openat(parentfd, component.c_str(),
                  O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | flags,
                  kSystemFeaturedFilesMode);
    } else {
      // Check that all components except the last are a valid directory.
      fd = openat(parentfd, component.c_str(),
                  O_NOFOLLOW | O_CLOEXEC | O_PATH | O_DIRECTORY);
    }
    if (fd < 0) {
      PLOG(ERROR) << "Unable to access path: " << path.value() << " ("
                  << component << ")";
      if (parentfd != AT_FDCWD) {
        close(parentfd);
      }
      return false;
    }
    if (parentfd != AT_FDCWD) {
      close(parentfd);
    }
    parentfd = fd;
  }
  *outfd = parentfd;
  return true;
}

// Validates |file_path| according to |ValidatePathAndOpen| and reads the
// contents into |file_content|. Creates |file_path| if it does not exist.
//
// Returns false if validating, opening, or reading |file_path| fail.
//
// NOTE: While |file_path| could be recreated if reading fails, doing so is
// risky since deletion could have unintended consequences (eg. the file is a
// symlink).
bool ValidatePathAndRead(const base::FilePath& file_path,
                         std::string& file_content) {
  int fd;
  if (!ValidatePathAndOpen(file_path, &fd)) {
    LOG(ERROR) << "Failed to validate and open " << file_path;
    return false;
  } else {
    // Constructing with |fd| instead of |file_path| to avoid potential
    // TOCTOU (time-of-check/time-of-use) vulnerabilities between calling
    // |ValidatePathAndOpen| and constructing |file|.
    base::File file(fd);
    std::vector<uint8_t> buffer(file.GetLength());
    if (!file.ReadAndCheck(/*offset=*/0, base::make_span(buffer))) {
      LOG(ERROR) << "Failed to read file contents";
      return false;
    }
    file_content = std::string(buffer.begin(), buffer.end());
  }
  return true;
}

// Overwrite the file's contents before deleting, to ensure data is wiped.
void SafeDeleteFile(const base::FilePath& seed_path) {
  brillo::Blob all_zero(kTpmSeedSize);
  if (!base::WriteFile(seed_path, all_zero)) {
    PLOG(WARNING) << "Failed to write zeroes to the TPM seed file.";
  }
  if (!brillo::DeleteFile(seed_path)) {
    PLOG(WARNING) << "Failed to delete the TPM seed file.";
  }
}

std::optional<brillo::SecureBlob> GetTpmSeed(const base::FilePath& seed_path) {
  brillo::SecureBlob tpm_seed(kTpmSeedSize);
  int bytes_read = base::ReadFile(
      seed_path, reinterpret_cast<char*>(tpm_seed.data()), tpm_seed.size());
  SafeDeleteFile(seed_path);

  if (bytes_read != kTpmSeedSize) {
    LOG(ERROR) << "Failed to read TPM seed from tmpfile, size expected: "
               << kTpmSeedSize << ", size got: " << bytes_read << ".";
    return std::nullopt;
  }

  return tpm_seed;
}

}  // namespace

StoreImpl::StoreImpl(const Store& store,
                     const base::FilePath& store_path,
                     std::optional<brillo::SecureBlob>&& tpm_seed,
                     const OverridesSet& overrides)
    : store_(store),
      store_path_(store_path),
      tpm_seed_(tpm_seed),
      overrides_(overrides) {}

void StoreImpl::ComputeHMACAndUpdate() {
  if (!tpm_seed_.has_value()) {
    LOG(WARNING) << "Couldn't compute HMAC because there's no key; continuing.";
    return;
  }
  brillo::SecureBlob hash = hwsec_foundation::HmacSha256(
      tpm_seed_.value(), brillo::BlobFromString(store_.overrides()));
  store_.set_overrides_hmac(hash.to_string());
}

// Updates hmac, writes store and hmac to disk.
bool StoreImpl::WriteDisk() {
  ComputeHMACAndUpdate();

  std::string serialized_store;
  bool serialized = store_.SerializeToString(&serialized_store);
  if (!serialized) {
    LOG(ERROR) << "Could not serialize protobuf";
    return false;
  }

  int store_fd;
  if (!ValidatePathAndOpen(store_path_, &store_fd, O_TRUNC)) {
    PLOG(ERROR) << "Could not reopen " << store_path_;
    return false;
  }

  // Write store to disk.
  base::File store_file(store_fd);
  if (!store_file.WriteAtCurrentPosAndCheck(
          base::as_bytes(base::make_span(serialized_store)))) {
    PLOG(ERROR) << "Could not write new store to disk";
    return false;
  }
  return true;
}

std::unique_ptr<StoreInterface> StoreImpl::Create() {
  if (base::PathExists(base::FilePath(kStoreHMACPath))) {
    // Clean up after oureselves from prior implementation.
    if (!brillo::DeleteFile(base::FilePath(kStoreHMACPath))) {
      PLOG(ERROR) << "Failed to delete HMAC file";
    }
  }
  return Create(base::FilePath(kStorePath), base::FilePath(kTpmSeedTmpFile));
}

std::unique_ptr<StoreInterface> StoreImpl::Create(
    base::FilePath store_path, base::FilePath tpm_seed_path) {
  // Do this first so that we always clean up the seed.
  std::optional<brillo::SecureBlob> tpm_seed = GetTpmSeed(tpm_seed_path);
  if (!tpm_seed.has_value()) {
    LOG(ERROR) << "Failed to get TPM seed. Overrides updates will fail.";
  }

  // Read the store.
  // Open store file or create if it does not exist.
  std::string store_content;
  if (!ValidatePathAndRead(store_path, store_content)) {
    LOG(ERROR) << "Failed to validate and read from " << store_path;
    return nullptr;
  }

  // Deserialize the proto and store it in memory.
  Store store;
  bool deserialized_store = store.ParseFromString(store_content);
  bool write_back = false;
  if (!deserialized_store) {
    LOG(ERROR) << "Failed to deserialize store";
    store.Clear();
    // Write the cleared store back to disk.
    write_back = true;
  }

  // Verify the HMAC, falling back to no overrides if it fails to verify
  // (or is missing).
  brillo::SecureBlob hash;
  if (tpm_seed.has_value()) {
    // Only attempt to compute the hash if there is a seed. (The seed won't be
    // available if featured crashes and restarts -- see GetTmpSeed().)
    hash = hwsec_foundation::HmacSha256(
        tpm_seed.value(), brillo::BlobFromString(store.overrides()));
  }
  // Mark as verified only if:
  // 1) There is a tpm_seed
  // 2) The stored HMAC in the proto has the right length
  // 3) The HMAC match.
  bool verified =
      hash.size() == store.overrides_hmac().size() &&
      (brillo::SecureMemcmp(hash.data(), store.overrides_hmac().data(),
                            hash.size())) == 0;
  if (!verified) {
    if (!store.overrides().empty()) {
      // If the hash fails *and* there were overrides, reset them so that we
      // don't use them this run of featured.
      LOG(ERROR)
          << "HMAC verification failed; falling back to default overrides";
      store.clear_overrides();
      store.clear_overrides_hmac();
      if (tpm_seed.has_value()) {
        // Write cleared state back to disk to reset any corruption / reset any
        // attacker-modified state.
        // Even though we cleared overrides_hmac, WriteDisk will recompute it.
        // *ONLY* do this if there was a seed; otherwise it's most likely that
        // featured crashed and restarted, and we shouldn't make destructive
        // changes.
        // (featured deletes the seed immediately after reading it to prevent
        // malicious processes from reading it; see GetTpmSeed above.)
        write_back = true;
      }
    }
  }

  OverridesSet overrides;
  if (!overrides.ParseFromString(store.overrides())) {
    LOG(ERROR) << "Overrides deserialization failed; falling back to default "
                  "overrides";
    store.clear_overrides();
    store.clear_overrides_hmac();
    write_back = true;
  }

  auto store_impl = std::unique_ptr<StoreImpl>(
      new StoreImpl(store, store_path, std::move(tpm_seed), overrides));
  if (write_back) {
    if (!store_impl->WriteDisk()) {
      // Fail more quickly, since, if writing fails, the class won't be able to
      // provide any mutating functions.
      return nullptr;
    }
  }
  return store_impl;
}

uint32_t StoreImpl::GetBootAttemptsSinceLastUpdate() {
  return store_.boot_attempts_since_last_seed_update();
}

bool StoreImpl::IncrementBootAttemptsSinceLastUpdate() {
  uint32_t boot_attempts = GetBootAttemptsSinceLastUpdate();
  store_.set_boot_attempts_since_last_seed_update(boot_attempts + 1);

  if (!WriteDisk()) {
    LOG(ERROR) << "Failed to increment boot attempts to disk.";
    return false;
  }
  return true;
}

bool StoreImpl::ClearBootAttemptsSinceLastUpdate() {
  store_.set_boot_attempts_since_last_seed_update(0);

  if (!WriteDisk()) {
    LOG(ERROR) << "Failed to increment boot attempts to disk.";
    return false;
  }
  return true;
}

SeedDetails StoreImpl::GetLastGoodSeed() {
  return store_.last_good_seed();
}

bool StoreImpl::SetLastGoodSeed(const SeedDetails& seed) {
  *store_.mutable_last_good_seed() = seed;
  if (!WriteDisk()) {
    LOG(ERROR) << "Failed to increment boot attempts to disk.";
    return false;
  }
  return true;
}

// TODO(kendraketsui): implement.
std::vector<FeatureOverride> StoreImpl::GetOverrides() {
  return std::vector<FeatureOverride>();
}
// TODO(kendraketsui): implement.
void StoreImpl::AddOverride(const FeatureOverride& override) {}
// TODO(kendraketsui): implement.
void StoreImpl::RemoveOverrideFor(const std::string& name) {}
}  // namespace featured
