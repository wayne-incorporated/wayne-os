// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_MOCK_VIRTUAL_ENDORSEMENT_H_
#define VTPM_BACKENDS_MOCK_VIRTUAL_ENDORSEMENT_H_

#include "vtpm/backends/virtual_endorsement.h"

#include <string>

#include <gmock/gmock.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

class MockVirtualEndorsement : public VirtualEndorsement {
 public:
  virtual ~MockVirtualEndorsement() = default;

  MOCK_METHOD(trunks::TPM_RC, Create, (), (override));

  MOCK_METHOD(std::string, GetEndorsementKey, (), (override));

  MOCK_METHOD(std::string, GetEndorsementCertificate, (), (override));
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_MOCK_VIRTUAL_ENDORSEMENT_H_
