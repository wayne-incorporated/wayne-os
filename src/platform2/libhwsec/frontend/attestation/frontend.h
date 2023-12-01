// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_ATTESTATION_FRONTEND_H_
#define LIBHWSEC_FRONTEND_ATTESTATION_FRONTEND_H_

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <brillo/secure_blob.h>

#include "libhwsec/frontend/frontend.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class AttestationFrontend : public Frontend {
 public:
  ~AttestationFrontend() override = default;
  virtual StatusOr<brillo::SecureBlob> Unseal(
      const brillo::Blob& sealed_data) const = 0;
  virtual StatusOr<brillo::Blob> Seal(
      const brillo::SecureBlob& unsealed_data) const = 0;
  virtual StatusOr<attestation::Quote> Quote(
      DeviceConfig device_config, const brillo::Blob& key_blob) const = 0;
  virtual StatusOr<bool> IsQuoted(DeviceConfig device_config,
                                  const attestation::Quote& quote) const = 0;
  virtual StatusOr<DeviceConfigSettings::BootModeSetting::Mode>
  GetCurrentBootMode() const = 0;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_ATTESTATION_FRONTEND_H_
