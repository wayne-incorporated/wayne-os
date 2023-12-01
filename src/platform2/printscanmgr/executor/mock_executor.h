// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_EXECUTOR_MOCK_EXECUTOR_H_
#define PRINTSCANMGR_EXECUTOR_MOCK_EXECUTOR_H_

#include <gmock/gmock.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "printscanmgr/mojom/executor.mojom.h"

namespace printscanmgr {

// Implementation of the mojom::Executor Mojo interface for use in unit tests.
class MockExecutor : public mojom::Executor {
 public:
  MockExecutor();
  MockExecutor(const MockExecutor&) = delete;
  MockExecutor& operator=(const MockExecutor&) = delete;
  ~MockExecutor();

  mojo::PendingRemote<mojom::Executor> pending_remote();

  // mojom::Executor overrides:
  MOCK_METHOD(void,
              StopUpstartJob,
              (mojom::UpstartJob, StopUpstartJobCallback),
              (override));
  MOCK_METHOD(void,
              RestartUpstartJob,
              (mojom::UpstartJob, RestartUpstartJobCallback),
              (override));

 private:
  // Provides a Mojo endpoint that printscanmgr can call to access the
  // executor's Mojo methods.
  mojo::Receiver<mojom::Executor> receiver_{/*impl=*/this};
};

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_EXECUTOR_MOCK_EXECUTOR_H_
