// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/executor/mojo_adaptor.h"

#include <string>
#include <utility>

namespace printscanmgr {

MojoAdaptor::MojoAdaptor(
    const scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner,
    mojo::PendingReceiver<mojom::Executor> receiver,
    base::OnceClosure on_disconnect)
    : mojo_task_runner_(mojo_task_runner),
      receiver_{/*impl=*/this, std::move(receiver)} {
  receiver_.set_disconnect_handler(std::move(on_disconnect));
}

MojoAdaptor::~MojoAdaptor() = default;

void MojoAdaptor::StopUpstartJob(mojom::UpstartJob job,
                                 StopUpstartJobCallback callback) {
  std::string error;
  bool success = upstart_tools_->StopJob(job, &error);
  std::move(callback).Run(success, error);
}

void MojoAdaptor::RestartUpstartJob(mojom::UpstartJob job,
                                    RestartUpstartJobCallback callback) {
  std::string error;
  bool success = upstart_tools_->RestartJob(job, &error);
  std::move(callback).Run(success, error);
}

}  // namespace printscanmgr
