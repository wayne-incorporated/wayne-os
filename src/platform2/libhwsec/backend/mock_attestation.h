// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_ATTESTATION_H_
#define LIBHWSEC_BACKEND_MOCK_ATTESTATION_H_

#include <string>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/attestation.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class MockAttestation : public Attestation {
 public:
  MockAttestation() = default;
  explicit MockAttestation(Attestation* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, Quote).WillByDefault(Invoke(default_, &Attestation::Quote));
    ON_CALL(*this, IsQuoted)
        .WillByDefault(Invoke(default_, &Attestation::IsQuoted));
  }

  MOCK_METHOD(StatusOr<attestation::Quote>,
              Quote,
              (DeviceConfigs device_configs, Key key),
              (override));
  MOCK_METHOD(StatusOr<bool>,
              IsQuoted,
              (DeviceConfigs device_configs, const attestation::Quote& quote),
              (override));

 private:
  Attestation* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_ATTESTATION_H_
