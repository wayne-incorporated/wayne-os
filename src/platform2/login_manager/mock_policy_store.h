// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_POLICY_STORE_H_
#define LOGIN_MANAGER_MOCK_POLICY_STORE_H_

#include "login_manager/policy_store.h"

namespace login_manager {
class MockPolicyStore : public PolicyStore {
 public:
  MockPolicyStore();
  ~MockPolicyStore() override;
  MOCK_METHOD(bool, DefunctPrefsFilePresent, (), (override));
  MOCK_METHOD(bool, EnsureLoadedOrCreated, (), (override));
  MOCK_METHOD(const enterprise_management::PolicyFetchResponse&,
              Get,
              (),
              (const, override));
  MOCK_METHOD(bool, Persist, (), (override));
  MOCK_METHOD(void,
              Set,
              (const enterprise_management::PolicyFetchResponse&),
              (override));
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_POLICY_STORE_H_
