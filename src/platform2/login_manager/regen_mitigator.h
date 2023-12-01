// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_REGEN_MITIGATOR_H_
#define LOGIN_MANAGER_REGEN_MITIGATOR_H_

#include <optional>
#include <string>

#include <base/files/file_path.h>

#include "login_manager/owner_key_loss_mitigator.h"

namespace login_manager {

class KeyGenerator;
class PolicyKey;

// This class mitigates owner key loss by triggering the generation of a new
// owner key and the re-signing of exisiting owner device policy.
class RegenMitigator : public OwnerKeyLossMitigator {
 public:
  explicit RegenMitigator(KeyGenerator* generator);
  RegenMitigator(const RegenMitigator&) = delete;
  RegenMitigator& operator=(const RegenMitigator&) = delete;

  ~RegenMitigator() override;

  // Deal with loss of the owner's private key.
  // Optionally, the key will only exist in the mount namespace identified by
  // |ns_path|.
  //
  // Returning true means that we can recover without user interaction.
  // Returning false means that we can't.
  bool Mitigate(const std::string& ownername,
                const std::optional<base::FilePath>& ns_path) override;

  bool Mitigating() override;

 private:
  KeyGenerator* generator_;
  bool mitigating_ = false;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_REGEN_MITIGATOR_H_
