// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_ARC_SIDELOAD_STATUS_H_
#define LOGIN_MANAGER_MOCK_ARC_SIDELOAD_STATUS_H_

#include "login_manager/arc_sideload_status_interface.h"

#include <memory>

namespace login_manager {

class MockArcSideloadStatus : public ArcSideloadStatusInterface {
 public:
  MockArcSideloadStatus() {}
  ~MockArcSideloadStatus() override {}

  MOCK_METHOD(void, Initialize, (), (override));
  MOCK_METHOD(bool, IsAdbSideloadAllowed, (), (override));
  MOCK_METHOD(void, EnableAdbSideload, (EnableAdbSideloadCallback), (override));
  MOCK_METHOD(void, QueryAdbSideload, (QueryAdbSideloadCallback), (override));
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_ARC_SIDELOAD_STATUS_H_
