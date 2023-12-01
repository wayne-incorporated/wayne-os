// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_ATTESTATION_H_
#define LIBHWSEC_BACKEND_TPM2_ATTESTATION_H_

#include <attestation/proto_bindings/attestation_ca.pb.h>

#include "libhwsec/backend/attestation.h"
#include "libhwsec/backend/tpm2/config.h"
#include "libhwsec/backend/tpm2/key_management.h"
#include "libhwsec/backend/tpm2/signing.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class AttestationTpm2 : public Attestation {
 public:
  AttestationTpm2(TrunksContext& context,
                  ConfigTpm2& config,
                  KeyManagementTpm2& key_management,
                  SigningTpm2& signing)
      : context_(context),
        config_(config),
        key_management_(key_management),
        signing_(signing) {}

  StatusOr<attestation::Quote> Quote(DeviceConfigs device_configs,
                                     Key key) override;
  StatusOr<bool> IsQuoted(DeviceConfigs device_configs,
                          const attestation::Quote& quote) override;

 private:
  TrunksContext& context_;
  ConfigTpm2& config_;
  KeyManagementTpm2& key_management_;
  SigningTpm2& signing_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_ATTESTATION_H_
