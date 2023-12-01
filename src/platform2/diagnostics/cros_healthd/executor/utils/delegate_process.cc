// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/executor/utils/delegate_process.h"

#include <string>
#include <utility>
#include <vector>

#include <base/task/sequenced_task_runner.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/message_pipe.h>

#include "diagnostics/cros_healthd/delegate/constants.h"
#include "diagnostics/cros_healthd/mojom/delegate.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kDelegateBinary[] = "/usr/libexec/diagnostics/executor-delegate";

}  // namespace

DelegateProcess::DelegateProcess() = default;

DelegateProcess::~DelegateProcess() = default;

DelegateProcess::DelegateProcess(const std::string& seccomp_filename,
                                 const SandboxedProcess::Options& options)
    : SandboxedProcess({kDelegateBinary}, seccomp_filename, options) {
  mojo::ScopedMessagePipeHandle pipe = invitation_.AttachMessagePipe(0);
  remote_.Bind(mojo::PendingRemote<mojom::Delegate>(std::move(pipe), 0));
}

void DelegateProcess::StartAsync() {
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&DelegateProcess::StartAndIgnoreResult,
                                weak_factory_.GetWeakPtr()));
}

void DelegateProcess::StartAndIgnoreResult() {
  Start();
}

bool DelegateProcess::Start() {
  mojo::PlatformChannel channel;
  mojo::OutgoingInvitation::Send(std::move(invitation_),
                                 base::kNullProcessHandle,
                                 channel.TakeLocalEndpoint());
  base::LaunchOptions options;
  std::string value;
  channel.PrepareToPassRemoteEndpoint(&options.fds_to_remap, &value);

  AddArg(std::string("--") + kDelegateMojoChannelHandle + "=" + value);

  for (const auto& pii : options.fds_to_remap) {
    BindFd(pii.first, pii.second);
  }

  bool res = SandboxedProcess::Start();
  channel.RemoteProcessLaunchAttempted();
  return res;
}

}  // namespace diagnostics
