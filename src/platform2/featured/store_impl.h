// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEATURED_STORE_IMPL_H_
#define FEATURED_STORE_IMPL_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/files/safe_fd.h>
#include <brillo/secure_blob.h>
#include <featured/proto_bindings/featured.pb.h>

#include "featured/feature_export.h"
#include "featured/store_interface.h"

namespace featured {

class FEATURE_EXPORT StoreImpl : public StoreInterface {
 public:
  ~StoreImpl() = default;
  // Attempts to instantiate and initialize a new StoreImpl, with store
  // created in the default location.
  static std::unique_ptr<StoreInterface> Create();

  // Attempts to instantiate and initialize a new StoreImpl, with the given
  // overrides. Used for tests.
  static std::unique_ptr<StoreInterface> Create(base::FilePath store_path,
                                                base::FilePath tpm_seed_path);

  // Returns the number of device boot attempts.
  uint32_t GetBootAttemptsSinceLastUpdate() override;

  // Increments number of device boot attempts both in memory and on disk.
  // Returns true if the increment is successfully written to disk.
  bool IncrementBootAttemptsSinceLastUpdate() override;

  // Same as above but sets the number of boot attempts to zero instead of
  // incrementing it.
  bool ClearBootAttemptsSinceLastUpdate() override;

  // Returns metadata associated with the last successful seed.
  SeedDetails GetLastGoodSeed() override;

  // Sets the value of the last successful seed fetch to |seed| in both memory
  // and on disk. Returns true if the update is successfully written to disk.
  bool SetLastGoodSeed(const SeedDetails& seed) override;

  // Returns the chrome://flags overrides.
  std::vector<FeatureOverride> GetOverrides() override;

  // Adds a chrome://flags override.
  void AddOverride(const FeatureOverride& override) override;

  // Removes override for feature |name|.
  void RemoveOverrideFor(const std::string& name) override;

 private:
  StoreImpl(const Store& store,
            const base::FilePath& store_path,
            std::optional<brillo::SecureBlob>&& hmac_key,
            const OverridesSet& overrides);

  // Write the store back to disk, updating HMAC if necessary.
  // Return false if writing fails, but *not* if there is no |hmac_key_|.
  bool WriteDisk();

  // Compute the HMAC of the overrides field, and update the overrides_hmac
  // field accordingly.
  void ComputeHMACAndUpdate();

  Store store_;
  base::FilePath store_path_;
  std::optional<brillo::SecureBlob> tpm_seed_;
  OverridesSet overrides_;
};
}  // namespace featured

#endif  // FEATURED_STORE_IMPL_H_
