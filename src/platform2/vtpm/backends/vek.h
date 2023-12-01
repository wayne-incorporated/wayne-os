// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_VEK_H_
#define VTPM_BACKENDS_VEK_H_

#include "vtpm/backends/blob.h"

#include <string>

#include <trunks/tpm_generated.h>

#include "vtpm/backends/virtual_endorsement.h"

namespace vtpm {

// `Vek` is a helper that gets the EK blob from a `VirtualEndorsement`.
class Vek : public Blob {
 public:
  explicit Vek(VirtualEndorsement* e);
  ~Vek() override = default;

  trunks::TPM_RC Get(std::string& blob) override;

 private:
  VirtualEndorsement* const endorsement_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_VEK_H_
