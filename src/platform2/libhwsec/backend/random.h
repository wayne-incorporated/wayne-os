// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_RANDOM_H_
#define LIBHWSEC_BACKEND_RANDOM_H_

#include <brillo/secure_blob.h>

#include "libhwsec/status.h"

namespace hwsec {

// Random provide the functions to generate random.
class Random {
 public:
  // Generates random blob with |size|.
  virtual StatusOr<brillo::Blob> RandomBlob(size_t size) = 0;

  // Generates random secure blob with |size|.
  virtual StatusOr<brillo::SecureBlob> RandomSecureBlob(size_t size) = 0;

 protected:
  Random() = default;
  ~Random() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_RANDOM_H_
