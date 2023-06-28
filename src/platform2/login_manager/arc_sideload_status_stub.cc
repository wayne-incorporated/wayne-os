// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/arc_sideload_status_stub.h"

namespace login_manager {

void ArcSideloadStatusStub::Initialize() {}

bool ArcSideloadStatusStub::IsAdbSideloadAllowed() {
  return false;
}

void ArcSideloadStatusStub::EnableAdbSideload(
    EnableAdbSideloadCallback callback) {
  callback.Run(ArcSideloadStatusInterface::Status::DISABLED,
               "ARC is not supported");
}

void ArcSideloadStatusStub::QueryAdbSideload(
    QueryAdbSideloadCallback callback) {
  callback.Run(ArcSideloadStatusInterface::Status::DISABLED);
}

}  // namespace login_manager
