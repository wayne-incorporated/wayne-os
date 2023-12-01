// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/daemon/daemon.h"

#include <utility>

#include <base/task/single_thread_task_runner.h>
#include <dbus/printscanmgr/dbus-constants.h>
#include <mojo/public/cpp/system/invitation.h>

namespace printscanmgr {

Daemon::Daemon(mojo::PlatformChannelEndpoint endpoint)
    : DBusServiceDaemon(kPrintscanmgrServiceName),
      ipc_support_(base::SingleThreadTaskRunner::GetCurrentDefault(),
                   mojo::core::ScopedIPCSupport::ShutdownPolicy::
                       CLEAN /* blocking shutdown */) {
  mojo::OutgoingInvitation invitation;
  // Always use 0 as the default pipe name.
  mojo::ScopedMessagePipeHandle pipe = invitation.AttachMessagePipe(0);
  mojo::OutgoingInvitation::Send(std::move(invitation),
                                 base::kNullProcessHandle, std::move(endpoint));
  dbus_adaptor_ = std::make_unique<DbusAdaptor>(
      mojo::PendingRemote<mojom::Executor>(std::move(pipe),
                                           /*version=*/0));
}

Daemon::~Daemon() = default;

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  dbus_adaptor_->RegisterAsync(
      bus_, sequencer->GetHandler("RegisterAsync() failed.", true));
}

}  // namespace printscanmgr
