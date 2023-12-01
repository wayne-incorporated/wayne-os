// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/executor/mock_executor.h"

namespace printscanmgr {

MockExecutor::MockExecutor() = default;
MockExecutor::~MockExecutor() = default;

mojo::PendingRemote<mojom::Executor> MockExecutor::pending_remote() {
  return receiver_.BindNewPipeAndPassRemote();
}

}  // namespace printscanmgr
