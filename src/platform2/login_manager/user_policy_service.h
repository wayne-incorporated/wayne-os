// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_USER_POLICY_SERVICE_H_
#define LOGIN_MANAGER_USER_POLICY_SERVICE_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include <base/files/file_path.h>

#include "login_manager/policy_service.h"

namespace login_manager {

class PolicyKey;
class PolicyStore;
class SystemUtils;

// Policy service implementation for user policy.
class UserPolicyService : public PolicyService {
 public:
  UserPolicyService(const base::FilePath& policy_dir,
                    std::unique_ptr<PolicyKey> policy_key,
                    const base::FilePath& key_copy_path,
                    SystemUtils* system_utils);
  UserPolicyService(const UserPolicyService&) = delete;
  UserPolicyService& operator=(const UserPolicyService&) = delete;

  ~UserPolicyService() override;

  // Persists a copy of |scoped_policy_key_| at |key_copy_path_|, if both the
  // key and the copy path are present.
  void PersistKeyCopy();

  // Store a new policy. The only difference from the base PolicyService is that
  // this override allows storage of policy blobs that indiciate the user is
  // unmanaged even if they are unsigned. If a non-signed blob gets installed,
  // we also clear the signing key.
  bool Store(const PolicyNamespace& ns,
             const std::vector<uint8_t>& policy_blob,
             int key_flags,
             SignatureCheck signature_check,
             const Completion& completion) override;

  // Invoked after a new key has been persisted. This creates a copy of the key
  // at |key_copy_path_| that is readable by chronos, and notifies the delegate.
  void OnKeyPersisted(bool status) override;

 private:
  // UserPolicyService owns its PolicyKey, note that PolicyService just keeps a
  // plain pointer.
  std::unique_ptr<PolicyKey> scoped_policy_key_;

  // If non-empty then a copy of |scoped_policy_key_| will be stored at this
  // path, readable by chronos.
  base::FilePath key_copy_path_;

  // Owned by our owner.
  SystemUtils* system_utils_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_USER_POLICY_SERVICE_H_
