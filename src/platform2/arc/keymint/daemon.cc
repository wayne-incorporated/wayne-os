// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymint/daemon.h"

#include <sysexits.h>

#include <cstdint>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/bindings/self_owned_receiver.h>
#include <mojo/public/cpp/system/invitation.h>

#include "arc/keymint/cert_store_instance.h"
#include "arc/keymint/keymint_server.h"

namespace arc::keymint {

Daemon::Daemon() : weak_factory_(this) {}
Daemon::~Daemon() = default;

int Daemon::OnInit() {
  int exit_code = brillo::DBusDaemon::OnInit();
  if (exit_code != EX_OK)
    return exit_code;

  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);
  LOG(INFO) << "Mojo init succeeded.";

  InitDBus();
  return EX_OK;
}

void Daemon::InitDBus() {
  dbus::ExportedObject* exported_object =
      bus_->GetExportedObject(dbus::ObjectPath(kArcKeyMintServicePath));

  CHECK(exported_object);
  CHECK(exported_object->ExportMethodAndBlock(
      kArcKeyMintInterfaceName, kBootstrapMojoConnectionMethod,
      base::BindRepeating(&Daemon::BootstrapMojoConnection,
                          weak_factory_.GetWeakPtr())));
  CHECK(bus_->RequestOwnershipAndBlock(kArcKeyMintServiceName,
                                       dbus::Bus::REQUIRE_PRIMARY));
  LOG(INFO) << "D-Bus registration succeeded";
}

void Daemon::BootstrapMojoConnection(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  LOG(INFO) << "Receiving bootstrap mojo call from D-Bus client.";

  if (is_bound_) {
    LOG(WARNING) << "Trying to instantiate multiple Mojo proxies.";
    return;
  }

  base::ScopedFD file_handle;
  dbus::MessageReader reader(method_call);

  if (!reader.PopFileDescriptor(&file_handle)) {
    LOG(ERROR) << "Couldn't extract Mojo IPC handle.";
    return;
  }

  if (!file_handle.is_valid()) {
    LOG(ERROR) << "Couldn't get file handle sent over D-Bus.";
    return;
  }

  if (!base::SetCloseOnExec(file_handle.get())) {
    PLOG(ERROR) << "Failed setting FD_CLOEXEC on fd.";
    return;
  }

  AcceptProxyConnection(std::move(file_handle));
  LOG(INFO) << "Mojo connection established.";
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void Daemon::AcceptProxyConnection(base::ScopedFD fd) {
  mojo::IncomingInvitation invitation = mojo::IncomingInvitation::Accept(
      mojo::PlatformChannelEndpoint(mojo::PlatformHandle(std::move(fd))));

  auto keymint_server = std::make_unique<KeyMintServer>();
  auto cert_store_instance =
      std::make_unique<CertStoreInstance>(keymint_server->GetWeakPtr());

  {
    mojo::ScopedMessagePipeHandle child_pipe;
    if (mojo::core::IsMojoIpczEnabled()) {
      constexpr uint64_t kKeyMintPipeAttachment = 0;
      child_pipe = invitation.ExtractMessagePipe(kKeyMintPipeAttachment);
    } else {
      child_pipe = invitation.ExtractMessagePipe("arc-keymint-pipe");
    }
    if (!child_pipe.is_valid()) {
      LOG(ERROR) << "Could not extract KeyMintServer pipe.";
      return;
    }
    mojo::MakeSelfOwnedReceiver(
        std::move(keymint_server),
        mojo::PendingReceiver<arc::mojom::keymint::KeyMintServer>(
            std::move(child_pipe)));
  }
  {
    mojo::ScopedMessagePipeHandle child_pipe;
    if (mojo::core::IsMojoIpczEnabled()) {
      constexpr uint64_t kCertStorePipeAttachment = 1;
      child_pipe = invitation.ExtractMessagePipe(kCertStorePipeAttachment);
    } else {
      child_pipe = invitation.ExtractMessagePipe("arc-cert-store-keymint-pipe");
    }

    if (!child_pipe.is_valid()) {
      LOG(ERROR) << "Could not extract CertStoreInstance pipe.";
      return;
    }
    mojo::MakeSelfOwnedReceiver(
        std::move(cert_store_instance),
        mojo::PendingReceiver<arc::keymint::mojom::CertStoreInstance>(
            std::move(child_pipe)));
  }
  is_bound_ = true;
}

}  // namespace arc::keymint
