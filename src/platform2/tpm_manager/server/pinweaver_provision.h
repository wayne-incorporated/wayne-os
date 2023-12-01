// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_PINWEAVER_PROVISION_H_
#define TPM_MANAGER_SERVER_PINWEAVER_PROVISION_H_

#include <memory>

// Use forward declaration to avoid conditional include.
namespace trunks {
class TrunksFactory;
}  // namespace trunks

namespace tpm_manager {

// An interface for performing pinweaver provisioning. This interface is meant
// to bridge the counterpart defined in `trunks/csme/pinweaver_provision.h`,
// which is not always available for build (e.g., TPM1.2 boards).
class PinWeaverProvision {
 public:
  // Creates an object that calls `trunks::csme::PinWeaverProvision`.
  static std::unique_ptr<PinWeaverProvision> Create(
      const trunks::TrunksFactory& factory);
  // Creates an object that does nothing for all the operations.
  static std::unique_ptr<PinWeaverProvision> CreateNoop();

  PinWeaverProvision() = default;
  virtual ~PinWeaverProvision() = default;

  // The interfaces that is meant to wrap
  // `trunks::csme::PinWeaverProvision::Provision()`.
  virtual bool Provision() = 0;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_PINWEAVER_PROVISION_H_
