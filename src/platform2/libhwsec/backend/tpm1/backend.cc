// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/backend.h"

#include <memory>
#include <utility>

#include <libhwsec-foundation/status/status_chain_macros.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/error/tpm_manager_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

BackendTpm1::BackendTpm1(Proxy& proxy,
                         MiddlewareDerivative middleware_derivative)
    : proxy_(proxy),
      tpm_manager_(proxy_.GetTpmManager()),
      tpm_nvram_(proxy_.GetTpmNvram()),
      overalls_(proxy_.GetOveralls()),
      crossystem_(proxy_.GetCrossystem()),
      middleware_derivative_(middleware_derivative),
      tss_helper_(tpm_manager_, overalls_),
      state_(tpm_manager_),
      da_mitigation_(tpm_manager_),
      storage_(tpm_manager_, tpm_nvram_),
      config_(overalls_, tss_helper_, crossystem_),
      random_(overalls_, tss_helper_),
      key_management_(overalls_, tss_helper_, config_, middleware_derivative_),
      sealing_(
          overalls_, tss_helper_, config_, key_management_, da_mitigation_),
      deriving_(),
      signature_sealing_(
          overalls_, tss_helper_, config_, key_management_, sealing_, random_),
      encryption_(overalls_, tss_helper_, key_management_),
      signing_(overalls_, tss_helper_, key_management_),
      pinweaver_(),
      vendor_(overalls_, tss_helper_, proxy_.GetTpmManager(), key_management_),
      recovery_crypto_(overalls_, config_, key_management_, sealing_, signing_),
      u2f_(),
      attestation_(overalls_, tss_helper_, config_, key_management_),
      version_attestation_() {}

BackendTpm1::~BackendTpm1() = default;

}  // namespace hwsec
