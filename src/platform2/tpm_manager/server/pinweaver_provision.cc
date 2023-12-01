// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/pinweaver_provision.h"

#if USE_TPM2
#include <trunks/csme/pinweaver_provision_impl.h>
#include <trunks/trunks_factory.h>
#endif

#include <memory>

#include <base/logging.h>

namespace tpm_manager {

namespace {

class PinWeaverProvisionNoop : public PinWeaverProvision {
 public:
  PinWeaverProvisionNoop() = default;
  ~PinWeaverProvisionNoop() override = default;
  bool Provision() override { return true; }
};

#if USE_TPM2
class PinWeaverProvisionImpl : public PinWeaverProvision {
 public:
  explicit PinWeaverProvisionImpl(const trunks::TrunksFactory& factory)
      : impl_(factory) {}
  ~PinWeaverProvisionImpl() override = default;
  bool Provision() override { return impl_.Provision(); }

 private:
  trunks::csme::PinWeaverProvisionImpl impl_;
};
#endif

}  // namespace

// static
std::unique_ptr<PinWeaverProvision> PinWeaverProvision::Create(
    const trunks::TrunksFactory& factory) {
#if USE_TPM2
  std::unique_ptr<PinWeaverProvision> result;
  result.reset(new PinWeaverProvisionImpl(factory));
  return result;
#else
  LOG(DFATAL)
      << __func__
      << ": Creating pinweaver provision object on an unsupported device.";
  return {};
#endif
}

// static
std::unique_ptr<PinWeaverProvision> PinWeaverProvision::CreateNoop() {
  std::unique_ptr<PinWeaverProvision> result;
  result.reset(new PinWeaverProvisionNoop());
  return result;
}

}  // namespace tpm_manager
