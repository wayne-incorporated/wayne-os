// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_VPD_PROCESS_H_
#define LOGIN_MANAGER_MOCK_VPD_PROCESS_H_

#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>

#include "login_manager/vpd_process.h"
#include "login_manager/vpd_process_impl.h"

namespace login_manager {

class SystemUtils;

class MockVpdProcess : public VpdProcess {
 public:
  MockVpdProcess() : VpdProcess() {}
  MOCK_METHOD(bool,
              RunInBackground,
              (const KeyValuePairs&, bool, const CompletionCallback&),
              (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_VPD_PROCESS_H_
