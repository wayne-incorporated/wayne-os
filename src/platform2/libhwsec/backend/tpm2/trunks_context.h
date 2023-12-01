// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_TRUNKS_CONTEXT_H_
#define LIBHWSEC_BACKEND_TPM2_TRUNKS_CONTEXT_H_

#include <memory>

#include <base/check.h>
#include <trunks/command_transceiver.h>
#include <trunks/trunks_factory.h>

#ifndef BUILD_LIBHWSEC
#error "Don't include this file outside libhwsec!"
#endif

namespace hwsec {

// This structure holds all Trunks client objects.
class TrunksContext {
 public:
  TrunksContext(trunks::CommandTransceiver& command_transceiver,
                trunks::TrunksFactory& factory)
      : command_transceiver_(command_transceiver),
        factory_(factory),
        tpm_state_(factory_.GetTpmState()),
        tpm_utility_(factory_.GetTpmUtility()) {
    CHECK(tpm_state_);
    CHECK(tpm_utility_);
  }

  trunks::CommandTransceiver& GetCommandTransceiver() {
    return command_transceiver_;
  }
  trunks::TrunksFactory& GetTrunksFactory() { return factory_; }
  trunks::TpmState& GetTpmState() { return *tpm_state_; }
  trunks::TpmUtility& GetTpmUtility() { return *tpm_utility_; }

 private:
  trunks::CommandTransceiver& command_transceiver_;
  trunks::TrunksFactory& factory_;
  std::unique_ptr<trunks::TpmState> tpm_state_;
  std::unique_ptr<trunks::TpmUtility> tpm_utility_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_TRUNKS_CONTEXT_H_
