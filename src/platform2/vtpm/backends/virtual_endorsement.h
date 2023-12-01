// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_VIRTUAL_ENDORSEMENT_H_
#define VTPM_BACKENDS_VIRTUAL_ENDORSEMENT_H_

#include <string>

#include <trunks/tpm_generated.h>

namespace vtpm {

// An interface that provides the information about an virtual endorsement,
// including EK and EK certificate.
class VirtualEndorsement {
 public:
  virtual ~VirtualEndorsement() = default;

  // Creates a new virtual endorsement and memorize the data for future calls to
  // getters.
  virtual trunks::TPM_RC Create() = 0;

  // Returns the endorsement key blob. The format is implementation-defined.
  virtual std::string GetEndorsementKey() = 0;

  // Returns the endorsement key certificate. The format is
  // implementation-defined.
  virtual std::string GetEndorsementCertificate() = 0;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_VIRTUAL_ENDORSEMENT_H_
