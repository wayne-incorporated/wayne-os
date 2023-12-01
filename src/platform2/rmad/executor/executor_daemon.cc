// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/executor/executor_daemon.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/task/single_thread_task_runner.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/system/invitation.h>
#include <mojo/public/cpp/system/message_pipe.h>

#include "rmad/constants.h"
#include "rmad/executor/mojom/executor.mojom.h"

namespace rmad {

ExecutorDaemon::ExecutorDaemon(mojo::PlatformChannelEndpoint endpoint) {
  DCHECK(endpoint.is_valid());

  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

  // Accept invitation from rmad.
  mojo::IncomingInvitation invitation =
      mojo::IncomingInvitation::Accept(std::move(endpoint));
  mojo::ScopedMessagePipeHandle pipe =
      invitation.ExtractMessagePipe(kRmadInternalMojoPipeName);

  mojo_service_ = std::make_unique<Executor>(
      mojo::PendingReceiver<::chromeos::rmad::mojom::Executor>(
          std::move(pipe)));
}

}  // namespace rmad
