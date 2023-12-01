// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mojom/mojo_service_provider.h"

#include <cstdint>
#include <memory>

#include <base/functional/bind.h>
#include <base/task/single_thread_task_runner.h>
#include <chromeos/mojo/service_constants.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/enum_utils.h>
#include <mojo_service_manager/lib/mojom/service_manager.mojom.h>

#include "shill/manager.h"
#include "shill/mojom/mojo_passpoint_service.h"
#include "shill/wifi/wifi_provider.h"

namespace shill {

// The delay of reconnecting when disconnected from the service.
constexpr base::TimeDelta kReconnectDelay = base::Seconds(1);

MojoServiceProvider::MojoServiceProvider(Manager* manager)
    : ipc_thread_("Mojo IPC"), passpoint_service_(manager), manager_(manager) {}

MojoServiceProvider::~MojoServiceProvider() = default;

void MojoServiceProvider::Start() {
  WiFiProvider* provider = manager_->wifi_provider();
  CHECK(provider);
  provider->AddPasspointCredentialsObserver(&passpoint_service_);

  // TODO(b/266150324): investigate if we really need a separate IO thread.
  ipc_thread_.StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0));
  // Note: this must be called only once per process and after
  // mojo::core::Init(). It works because Start() is called only once by
  // DaemonTask on Shill startup.
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      ipc_thread_.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

  // Register the service providers
  ConnectAndRegister();
}

void MojoServiceProvider::Stop() {
  WiFiProvider* provider = manager_->wifi_provider();
  CHECK(provider);
  provider->RemovePasspointCredentialsObserver(&passpoint_service_);

  if (ipc_thread_.IsRunning()) {
    ipc_support_.reset();
    ipc_thread_.Stop();
  }
}

void MojoServiceProvider::ConnectAndRegister() {
  // Connect to the service manager and watch errors.
  auto pending_remote =
      chromeos::mojo_service_manager::ConnectToMojoServiceManager();
  if (!pending_remote.is_valid()) {
    LOG(ERROR) << "Mojo service manager is not available.";
    return;
  }
  service_manager_.Bind(std::move(pending_remote));
  service_manager_.set_disconnect_with_reason_handler(
      base::BindOnce(&MojoServiceProvider::OnManagerDisconnected,
                     weak_ptr_factory_.GetWeakPtr()));

  // Register Passpoint Mojo service.
  service_manager_->Register(chromeos::mojo_services::kCrosPasspointService,
                             receiver_.BindNewPipeAndPassRemote());
}

void MojoServiceProvider::OnManagerDisconnected(uint32_t error,
                                                const std::string& message) {
  if (error == 0) {
    LOG(WARNING)
        << "Disconnected from service manager, scheduling reconnection";
    // The remote service probably restarted, try to reconnect.
    // TODO(b/266150324): implement a backoff or a max reconnection logic.
    service_manager_.reset();
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&MojoServiceProvider::ConnectAndRegister,
                       weak_ptr_factory_.GetWeakPtr()),
        kReconnectDelay);
    return;
  }
  const auto error_enum = mojo::ConvertIntToMojoEnum<
      chromeos::mojo_service_manager::mojom::ErrorCode>(
      static_cast<int32_t>(error));
  if (error_enum) {
    LOG(ERROR) << "Service manager disconnected with error "
               << error_enum.value() << ", message: " << message;
  } else {
    LOG(ERROR) << "Service manager disconnected with error " << error
               << ", message: " << message;
  }
}

void MojoServiceProvider::Request(
    chromeos::mojo_service_manager::mojom::ProcessIdentityPtr identity,
    mojo::ScopedMessagePipeHandle receiver) {
  // The dispatch logic will be implemented here when there will be multiple
  // services.
  service_receiver_set_.Add(
      &passpoint_service_,
      mojo::PendingReceiver<chromeos::connectivity::mojom::PasspointService>(
          std::move(receiver)));
}

}  // namespace shill
