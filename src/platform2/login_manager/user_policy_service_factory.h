// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_USER_POLICY_SERVICE_FACTORY_H_
#define LOGIN_MANAGER_USER_POLICY_SERVICE_FACTORY_H_

#include <sys/types.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <base/memory/ref_counted.h>

namespace login_manager {
class NssUtil;
class PolicyService;
class SystemUtils;

// Factory for creating user policy service instances. User policies are stored
// in the root-owned part of the user's cryptohome.
class UserPolicyServiceFactory {
 public:
  UserPolicyServiceFactory(NssUtil* nss, SystemUtils* system_utils);
  UserPolicyServiceFactory(const UserPolicyServiceFactory&) = delete;
  UserPolicyServiceFactory& operator=(const UserPolicyServiceFactory&) = delete;

  virtual ~UserPolicyServiceFactory();

  // Creates a new user policy service instance.
  virtual std::unique_ptr<PolicyService> Create(const std::string& username);

  // Creates a new user policy service instance operating in a hidden user
  // home directory.
  virtual std::unique_ptr<PolicyService> CreateForHiddenUserHome(
      const std::string& username);

 private:
  // Creates a new user policy service instance operating in |policy_dir| and
  // persisting key copies in a directory keyed by sanitized |username|.
  std::unique_ptr<PolicyService> CreateInternal(
      const std::string& username, const base::FilePath& policy_dir);

  NssUtil* nss_;
  SystemUtils* system_utils_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_USER_POLICY_SERVICE_FACTORY_H_
