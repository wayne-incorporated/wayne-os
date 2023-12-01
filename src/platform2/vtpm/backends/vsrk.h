// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_VSRK_H_
#define VTPM_BACKENDS_VSRK_H_

#include "vtpm/backends/blob.h"

#include <string>

#include <trunks/tpm_generated.h>
#include <trunks/trunks_factory.h>

namespace vtpm {

// `Vsrk` is the implementation of creating a virtual SRK for a virtual TPM.
class Vsrk : public Blob {
 public:
  explicit Vsrk(trunks::TrunksFactory* factory);
  ~Vsrk() override = default;

  // Creates a virtual SRK under host SRK.
  trunks::TPM_RC Get(std::string& blob) override;

 private:
  trunks::TrunksFactory* const factory_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_VSRK_H_
