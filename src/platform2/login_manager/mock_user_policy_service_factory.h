// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_USER_POLICY_SERVICE_FACTORY_H_
#define LOGIN_MANAGER_MOCK_USER_POLICY_SERVICE_FACTORY_H_

#include "login_manager/user_policy_service_factory.h"

#include <memory>
#include <string>

#include <base/files/file_path.h>

namespace login_manager {

class MockUserPolicyServiceFactory : public UserPolicyServiceFactory {
 public:
  MockUserPolicyServiceFactory();
  ~MockUserPolicyServiceFactory() override;
  MOCK_METHOD(std::unique_ptr<PolicyService>,
              Create,
              (const std::string&),
              (override));
  MOCK_METHOD(std::unique_ptr<PolicyService>,
              CreateForHiddenUserHome,
              (const std::string&),
              (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_USER_POLICY_SERVICE_FACTORY_H_
