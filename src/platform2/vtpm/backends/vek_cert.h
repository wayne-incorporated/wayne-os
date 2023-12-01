// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_VEK_CERT_H_
#define VTPM_BACKENDS_VEK_CERT_H_

#include "vtpm/backends/blob.h"

#include <string>

#include <trunks/tpm_generated.h>

#include "vtpm/backends/virtual_endorsement.h"

namespace vtpm {

class VekCert : public Blob {
 public:
  explicit VekCert(VirtualEndorsement* e);
  ~VekCert() override = default;

  trunks::TPM_RC Get(std::string& blob) override;

 private:
  VirtualEndorsement* const endorsement_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_VEK_CERT_H_
