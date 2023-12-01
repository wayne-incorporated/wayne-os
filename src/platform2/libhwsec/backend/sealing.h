// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_SEALING_H_
#define LIBHWSEC_BACKEND_SEALING_H_

#include <optional>

#include <brillo/secure_blob.h>

#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

// Sealing provide the functions to sealing and unsealing with policy.
class Sealing {
 public:
  struct UnsealOptions {
    // The preload_data returned from |PreloadSealedData|.
    std::optional<Key> preload_data;
  };

  // Is the device supported sealing/unsealing or not.
  virtual StatusOr<bool> IsSupported() = 0;

  // Seals the |unsealed_data| with |policy|.
  virtual StatusOr<brillo::Blob> Seal(
      const OperationPolicySetting& policy,
      const brillo::SecureBlob& unsealed_data) = 0;

  // Preloads the |sealed_data| with |policy|.
  virtual StatusOr<std::optional<ScopedKey>> PreloadSealedData(
      const OperationPolicy& policy, const brillo::Blob& sealed_data) = 0;

  // Unseals the |sealed_data| with |policy| and optional |options|.
  virtual StatusOr<brillo::SecureBlob> Unseal(const OperationPolicy& policy,
                                              const brillo::Blob& sealed_data,
                                              UnsealOptions options) = 0;

 protected:
  Sealing() = default;
  ~Sealing() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_SEALING_H_
