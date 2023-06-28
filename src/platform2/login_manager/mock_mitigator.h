// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_MITIGATOR_H_
#define LOGIN_MANAGER_MOCK_MITIGATOR_H_

#include <string>

#include <base/macros.h>
#include <gmock/gmock.h>

#include "login_manager/owner_key_loss_mitigator.h"

namespace login_manager {
class PolicyKey;

class MockMitigator : public OwnerKeyLossMitigator {
 public:
  MockMitigator();
  MockMitigator(const MockMitigator&) = delete;
  MockMitigator& operator=(const MockMitigator&) = delete;

  ~MockMitigator() override;

  MOCK_METHOD(bool,
              Mitigate,
              (const std::string&, const base::Optional<base::FilePath>&),
              (override));
  MOCK_METHOD(bool, Mitigating, (), (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_MITIGATOR_H_
