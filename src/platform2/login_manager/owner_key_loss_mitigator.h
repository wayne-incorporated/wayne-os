// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_OWNER_KEY_LOSS_MITIGATOR_H_
#define LOGIN_MANAGER_OWNER_KEY_LOSS_MITIGATOR_H_

#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <base/optional.h>

namespace login_manager {

class PolicyKey;

// Sometimes, the user we believe to be the Owner will not be able to
// demonstrate possession of the Owner private key.  This class defines the
// interface for objects that can handle this situation.
class OwnerKeyLossMitigator {
 public:
  static const char kMitigateMsg[];

  virtual ~OwnerKeyLossMitigator();

  // Deal with loss of the owner's private key.
  // Optionally, the key will only exist in the mount namespace identified by
  // |ns_path|.
  //
  // Returning true means that we can recover without user interaction.
  // Returning false means that we can't.
  virtual bool Mitigate(const std::string& ownername,
                        const base::Optional<base::FilePath>& ns_path) = 0;

  virtual bool Mitigating() = 0;

 protected:
  OwnerKeyLossMitigator();
  OwnerKeyLossMitigator(const OwnerKeyLossMitigator&) = delete;
  OwnerKeyLossMitigator& operator=(const OwnerKeyLossMitigator&) = delete;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_OWNER_KEY_LOSS_MITIGATOR_H_
