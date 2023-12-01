// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_RO_DATA_H_
#define LIBHWSEC_BACKEND_RO_DATA_H_

#include <brillo/secure_blob.h>

#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/space.h"

namespace hwsec {

// Storage provide the functions for read-only space.
class RoData {
 public:
  // Is the |space| ready to use (defined correctly) or not.
  virtual StatusOr<bool> IsReady(RoSpace space) = 0;

  // Reads the data from the |space|.
  virtual StatusOr<brillo::Blob> Read(RoSpace space) = 0;

  // Certifies data the |space| with a |key|.
  virtual StatusOr<brillo::Blob> Certify(RoSpace space, Key key) = 0;

 protected:
  RoData() = default;
  ~RoData() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_RO_DATA_H_
