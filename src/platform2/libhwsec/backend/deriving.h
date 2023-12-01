// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_DERIVING_H_
#define LIBHWSEC_BACKEND_DERIVING_H_

#include <cstdint>

#include <brillo/secure_blob.h>

#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

// Deriving provide the functions to derive blob.
class Deriving {
 public:
  // Derives the |blob| with |key|.
  // Note: The function may return same |blob| on some platform(e.g. TPM1.2)
  // for backward compatibility.
  virtual StatusOr<brillo::Blob> Derive(Key key, const brillo::Blob& blob) = 0;

  // Derives the secure |blob| with |key|.
  // Note: The function may return same |blob| on some platform(e.g. TPM1.2)
  // for backward compatibility.
  virtual StatusOr<brillo::SecureBlob> SecureDerive(
      Key key, const brillo::SecureBlob& blob) = 0;

 protected:
  Deriving() = default;
  ~Deriving() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_DERIVING_H_
