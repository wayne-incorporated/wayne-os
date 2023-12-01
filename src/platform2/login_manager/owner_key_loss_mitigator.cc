// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/owner_key_loss_mitigator.h"

namespace login_manager {

const char OwnerKeyLossMitigator::kMitigateMsg[] =
    "Owner private key lost. "
    "Check for TPM issues or disk corruption.";

OwnerKeyLossMitigator::OwnerKeyLossMitigator() {}

OwnerKeyLossMitigator::~OwnerKeyLossMitigator() {}

}  // namespace login_manager
