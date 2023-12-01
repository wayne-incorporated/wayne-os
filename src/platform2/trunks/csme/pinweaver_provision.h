// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_PINWEAVER_PROVISION_H_
#define TRUNKS_CSME_PINWEAVER_PROVISION_H_

#include <memory>

#include "trunks/trunks_export.h"

namespace trunks {
namespace csme {

// An interface for performing pinweaver provisioning.
class TRUNKS_EXPORT PinWeaverProvision {
 public:
  PinWeaverProvision() = default;
  virtual ~PinWeaverProvision() = default;
  // Sets and commits salting key for CMSE. Creates and persists the salting key
  // if not done yet. performs no-ops if the salting key is already provisioned
  // (i.e., committed to CSME). Returns `true` iff the salting key is (already)
  // committed.
  //
  // Note that the salting key creation requires empty owner password by design.
  virtual bool Provision() = 0;
  // Issues `InitOwner` CSME command. Returns `true` iff the operations
  // succeeds.
  //
  // Note that this operation requires empty owner password by design. Also, it
  // requires the salting key to be provisioned first.
  virtual bool InitOwner() = 0;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_PINWEAVER_PROVISION_H_
