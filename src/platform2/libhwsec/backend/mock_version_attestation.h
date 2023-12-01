// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_VERSION_ATTESTATION_H_
#define LIBHWSEC_BACKEND_MOCK_VERSION_ATTESTATION_H_

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/version_attestation.h"

namespace hwsec {

class MockVersionAttestation : public VersionAttestation {
 public:
  MockVersionAttestation() = default;
  explicit MockVersionAttestation(VersionAttestation* on_call)
      : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, AttestVersion)
        .WillByDefault(Invoke(default_, &VersionAttestation::AttestVersion));
  }

  MOCK_METHOD(StatusOr<arc_attestation::CrOSVersionAttestationBlob>,
              AttestVersion,
              (Key, const std::string& cert, const brillo::Blob&),
              (override));

 private:
  VersionAttestation* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_VERSION_ATTESTATION_H_
