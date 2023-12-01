// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/daemons/daemon.h>
#include <brillo/syslog_logging.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/platform/platform_channel.h>
#include <mojo/public/cpp/system/invitation.h>

#include "diagnostics/bindings/connectivity/context.h"
#include "diagnostics/bindings/connectivity/local_state.h"
#include "diagnostics/bindings/connectivity/remote_state.h"
#include "diagnostics/mojom/public/cros_healthd.mojom-connectivity.h"

namespace diagnostics {

namespace {

namespace connectivity = ::ash::cros_healthd::connectivity;
namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kCrosHealthdServiceFactoryName[] = "CrosHealthdServiceFactory";

class ConnectivityTestProvider
    : public connectivity::mojom::ConnectivityTestProvider {
 public:
  ConnectivityTestProvider() = default;
  ConnectivityTestProvider(const ConnectivityTestProvider&) = delete;
  ConnectivityTestProvider& operator=(const ConnectivityTestProvider&) = delete;
  ~ConnectivityTestProvider() = default;

  // connectivity::mojom::ConnectivityTestProvider override.
  void BindContext(
      mojo::PendingRemote<connectivity::mojom::State> remote,
      mojo::PendingReceiver<connectivity::mojom::State> receiver) override {
    context_ = connectivity::Context::Create(
        connectivity::LocalState::Create(std::move(receiver)),
        connectivity::RemoteState::Create(std::move(remote)));
  }

  // connectivity::mojom::ConnectivityTestProvider override.
  void BindTestProvider(const std::string& interface_name,
                        mojo::ScopedMessagePipeHandle receiver) override {
    if (interface_name != kCrosHealthdServiceFactoryName) {
      LOG(ERROR) << interface_name << " is not supported.";
      return;
    }
    test_provider_ =
        mojom::CrosHealthdServiceFactoryTestProvider::Create(context_.get());
    test_provider_->Bind(
        mojo::PendingReceiver<mojom::CrosHealthdServiceFactory>(
            std::move(receiver)));
  }

 private:
  std::unique_ptr<connectivity::Context> context_;

  std::unique_ptr<mojom::CrosHealthdServiceFactoryTestProvider> test_provider_;
};

}  // namespace

class ConnectivityTestDaemon : public brillo::Daemon {
 public:
  explicit ConnectivityTestDaemon(mojo::PlatformChannelEndpoint endpoint)
      : scoped_ipc_support_(base::SingleThreadTaskRunner::
                                GetCurrentDefault() /* io_thread_task_runner */,
                            mojo::core::ScopedIPCSupport::ShutdownPolicy::
                                CLEAN /* blocking shutdown */) {
    mojo::IncomingInvitation invitation =
        mojo::IncomingInvitation::Accept(std::move(endpoint));
    mojo::ScopedMessagePipeHandle pipe = invitation.ExtractMessagePipe(0);
    receiver_.Bind(
        mojo::PendingReceiver<connectivity::mojom::ConnectivityTestProvider>(
            std::move(pipe)));
    receiver_.set_disconnect_handler(
        base::BindOnce(&ConnectivityTestDaemon::Quit, base::Unretained(this)));
  }
  ConnectivityTestDaemon(const ConnectivityTestDaemon&) = delete;
  ConnectivityTestDaemon& operator=(const ConnectivityTestDaemon&) = delete;
  ~ConnectivityTestDaemon() = default;

 private:
  mojo::core::ScopedIPCSupport scoped_ipc_support_;

  ConnectivityTestProvider provider_;

  mojo::Receiver<connectivity::mojom::ConnectivityTestProvider> receiver_{
      &provider_};
};

}  // namespace diagnostics

int main(int argc, char** argv) {
  brillo::InitLog(brillo::kLogToStderr);
  base::CommandLine::Init(argc, argv);
  mojo::core::Init();

  diagnostics::ConnectivityTestDaemon daemon(
      mojo::PlatformChannel::RecoverPassedEndpointFromCommandLine(
          *base::CommandLine::ForCurrentProcess()));
  return daemon.Run();
}
