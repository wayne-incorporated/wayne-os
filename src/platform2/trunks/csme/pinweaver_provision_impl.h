// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_PINWEAVER_PROVISION_IMPL_H_
#define TRUNKS_CSME_PINWEAVER_PROVISION_IMPL_H_

#include "trunks/csme/pinweaver_provision.h"

#include <string>

#include "trunks/trunks_export.h"
#include "trunks/trunks_factory.h"

namespace trunks {
namespace csme {

// The implementation of `PinWeaverProvision`.
class TRUNKS_EXPORT PinWeaverProvisionImpl : public PinWeaverProvision {
 public:
  explicit PinWeaverProvisionImpl(const TrunksFactory& factory);
  ~PinWeaverProvisionImpl() override = default;
  bool Provision() override;
  bool InitOwner() override;

 private:
  bool GetProvisionKeyContent(std::string& key);
  bool ProvisionSaltingKeyHash(const std::string& public_key_hash);
  bool InitOwnerInternal();

  const TrunksFactory& factory_;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_PINWEAVER_PROVISION_IMPL_H_
