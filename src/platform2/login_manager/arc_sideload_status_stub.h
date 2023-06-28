// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_ARC_SIDELOAD_STATUS_STUB_H_
#define LOGIN_MANAGER_ARC_SIDELOAD_STATUS_STUB_H_

#include "login_manager/arc_sideload_status_interface.h"

namespace login_manager {

class ArcSideloadStatusStub : public ArcSideloadStatusInterface {
 public:
  ArcSideloadStatusStub() = default;
  virtual ~ArcSideloadStatusStub() = default;

  // Overridden from ArcSideloadStatusInterface
  void Initialize() override;
  bool IsAdbSideloadAllowed() override;
  void EnableAdbSideload(EnableAdbSideloadCallback callback) override;
  void QueryAdbSideload(QueryAdbSideloadCallback callback) override;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_ARC_SIDELOAD_STATUS_STUB_H_
