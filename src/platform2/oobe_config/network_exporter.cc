// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/network_exporter.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/message_loops/base_message_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <dbus/object_path.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>
#include <mojo/public/cpp/platform/platform_handle.h>
#include <mojo/public/cpp/system/invitation.h>

#include "mojom/rollback_network_config.mojom.h"

namespace oobe_config {

namespace {

using ::ash::rollback_network_config::mojom::RollbackNetworkConfig;

std::unique_ptr<brillo::BaseMessageLoop> InitMessageLoop() {
  DCHECK(!brillo::MessageLoop::ThreadHasCurrent());
  auto message_loop = std::make_unique<brillo::BaseMessageLoop>();
  message_loop->SetAsCurrent();
  return message_loop;
}

scoped_refptr<dbus::Bus> InitDBus(brillo::DBusConnection* dbus_connection) {
  return dbus_connection->Connect();
}

std::unique_ptr<mojo::core::ScopedIPCSupport> InitMojo() {
  mojo::core::Init();
  return std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);
}

mojo::Remote<RollbackNetworkConfig> BootstrapMojoConnection(dbus::Bus* bus) {
  dbus::ObjectProxy* proxy = bus->GetObjectProxy(
      ::mojo_connection_service::kMojoConnectionServiceServiceName,
      dbus::ObjectPath(
          ::mojo_connection_service::kMojoConnectionServiceServicePath));

  dbus::MethodCall bootstrap_method_call(
      ::mojo_connection_service::kMojoConnectionServiceInterface,
      ::mojo_connection_service::
          kBootstrapMojoConnectionForRollbackNetworkConfigMethod);
  dbus::MessageWriter writer(&bootstrap_method_call);

  std::unique_ptr<dbus::Response> bootstrap_response =
      proxy->CallMethodAndBlock(&bootstrap_method_call, /*timeout_ms=*/25000);

  if (!bootstrap_response) {
    LOG(ERROR) << "Failed to establish dbus connection to Chrome. No response.";
    return mojo::Remote<RollbackNetworkConfig>();
  }

  base::ScopedFD file_handle;
  dbus::MessageReader reader(bootstrap_response.get());

  if (!reader.PopFileDescriptor(&file_handle) || !file_handle.is_valid()) {
    LOG(ERROR) << "Failed to set up mojo connection. Chrome did not return a "
                  "valid file descriptor.";
    return mojo::Remote<RollbackNetworkConfig>();
  }

  if (!base::SetCloseOnExec(file_handle.get())) {
    LOG(ERROR) << "Failed to set close on exec for file descriptor. Not "
                  "establishing mojo connection.";
    return mojo::Remote<RollbackNetworkConfig>();
  }

  mojo::IncomingInvitation invitation =
      mojo::IncomingInvitation::Accept(mojo::PlatformChannelEndpoint(
          mojo::PlatformHandle(std::move(file_handle))));

  return mojo::Remote<RollbackNetworkConfig>(
      mojo::PendingRemote<RollbackNetworkConfig>(
          invitation.ExtractMessagePipe(0), 0u));
}

void SaveNetworkConfig(brillo::BaseMessageLoop* message_loop,
                       std::string* config_out,
                       const std::string& onc_network_config) {
  *config_out = onc_network_config;
  message_loop->BreakLoop();
}

std::string FetchNetworkConfigs(
    const mojo::Remote<RollbackNetworkConfig>& network_config_remote,
    brillo::BaseMessageLoop* message_loop) {
  std::string config;
  network_config_remote.get()->RollbackConfigExport(
      base::BindOnce(&SaveNetworkConfig, message_loop, &config));

  // Schedule timeout after 90s.
  message_loop->PostDelayedTask(
      FROM_HERE, base::BindOnce([]() {
        LOG(ERROR) << "Fetching network configuration timed out";
        DCHECK(brillo::MessageLoop::current());
        brillo::MessageLoop::current()->BreakLoop();
      }),
      base::Seconds(90));

  // Wait until the configuration was fetched.
  message_loop->Run();
  return config;
}

}  // namespace

std::optional<std::string> ExportNetworkConfig() {
  brillo::DBusConnection dbus_connection;
  auto bus = InitDBus(&dbus_connection);
  // Initializing mojo requires that the current thread has an associated
  // message loop.
  std::unique_ptr<brillo::BaseMessageLoop> message_loop = InitMessageLoop();
  auto ipc_support = InitMojo();
  mojo::Remote<RollbackNetworkConfig> network_config_remote =
      BootstrapMojoConnection(bus.get());

  if (network_config_remote.is_bound()) {
    return FetchNetworkConfigs(network_config_remote, message_loop.get());
  }
  return std::nullopt;
}

}  // namespace oobe_config
