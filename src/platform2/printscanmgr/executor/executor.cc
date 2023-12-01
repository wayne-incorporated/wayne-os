// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/executor/executor.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <mojo/public/cpp/system/invitation.h>
#include <mojo/public/cpp/system/message_pipe.h>

#include "printscanmgr/mojom/executor.mojom.h"

namespace printscanmgr {

Executor::Executor(mojo::PlatformChannelEndpoint endpoint)
    : mojo_task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()) {
  DCHECK(endpoint.is_valid());

  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      mojo_task_runner_, mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

  mojo::IncomingInvitation invitation =
      mojo::IncomingInvitation::Accept(std::move(endpoint));
  // Always use 0 as the default pipe name.
  mojo::ScopedMessagePipeHandle pipe = invitation.ExtractMessagePipe(0);

  mojo_adaptor_ = std::make_unique<MojoAdaptor>(
      mojo_task_runner_,
      mojo::PendingReceiver<mojom::Executor>(std::move(pipe)),
      base::BindOnce(&Executor::Quit, base::Unretained(this)));
}

Executor::~Executor() = default;

}  // namespace printscanmgr
