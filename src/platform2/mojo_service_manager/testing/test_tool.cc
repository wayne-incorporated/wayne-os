// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/c/system/buffer.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/handle.h>

#include "mojo_service_manager/lib/connect.h"
#include "mojo_service_manager/lib/mojom/service_manager.mojom.h"
#include "mojo_service_manager/testing/test.mojom.h"

namespace chromeos {
namespace mojo_service_manager {
namespace {

// The actions supported by test tool.
constexpr char kActionCreateTestService[] = "create-test-service";
constexpr char kActionPingTestService[] = "ping-test-service";
constexpr char kActionTestSharedBuffer[] = "test-shared-buffer";

// The service name to register and request test service from service manager.
constexpr char kTestServiceName[] = "MojoServiceManagerTest";

// The buffer size to test the shared buffer creation.
constexpr uint64_t kTestSharedBufferSize = 1024;

class TestService : public mojom::Foo, public mojom::ServiceProvider {
 public:
  TestService();
  TestService(const TestService&) = delete;
  TestService& operator=(const TestService&) = delete;
  ~TestService();

  void Register(mojom::ServiceManager* service_manager) {
    service_manager->Register(kTestServiceName,
                              provider_.BindNewPipeAndPassRemote());
  }

 private:
  // mojom::Foo overrides.
  void Ping(PingCallback callback) override { std::move(callback).Run(); }

  // mojom::ServiceProvider overrides.
  void Request(mojom::ProcessIdentityPtr client_identity,
               mojo::ScopedMessagePipeHandle receiver) override {
    receiver_set_.Add(this,
                      mojo::PendingReceiver<mojom::Foo>(std::move(receiver)));
  }

 private:
  mojo::Receiver<mojom::ServiceProvider> provider_{this};
  mojo::ReceiverSet<mojom::Foo> receiver_set_;
};

TestService::TestService() = default;
TestService ::~TestService() = default;

int CreateTestService(brillo::Daemon& daemon,
                      mojom::ServiceManager* service_manager) {
  TestService test_service;
  test_service.Register(service_manager);
  LOG(INFO) << "Registered test service.";

  return daemon.Run();
}

int PingTestService(brillo::Daemon& daemon,
                    mojom::ServiceManager* service_manager) {
  mojo::Remote<mojom::Foo> foo;
  service_manager->Request(kTestServiceName, std::nullopt,
                           foo.BindNewPipeAndPassReceiver().PassPipe());
  foo.set_disconnect_with_reason_handler(
      base::BindOnce([](uint32_t error, const std::string& message) {
        LOG(FATAL) << "Foo service disconnected: " << error << ", " << message;
      }));
  foo->Ping(base::BindOnce(&brillo::Daemon::Quit, base::Unretained(&daemon)));
  daemon.Run();
  LOG(INFO) << "Ping test service successfully.";
  return 0;
}

int TestSharedBuffer() {
  MojoCreateSharedBufferOptions options = {sizeof(options),
                                           MOJO_CREATE_SHARED_BUFFER_FLAG_NONE};
  mojo::Handle handle;
  CHECK_EQ(MojoCreateSharedBuffer(kTestSharedBufferSize, &options,
                                  handle.mutable_value()),
           MOJO_RESULT_OK)
      << "Failed to allocate shared buffer.";
  CHECK(handle.is_valid()) << "Invalid shared buffer handle.";

  LOG(INFO) << "Create shared buffer successfully.";
  return 0;
}

}  // namespace

int TestToolMain(int argc, char* argv[]) {
  DEFINE_int32(log_level, 0,
               "Logging level - 0: LOG(INFO), 1: LOG(WARNING), 2: LOG(ERROR), "
               "-1: VLOG(1), -2: VLOG(2), ...");
  DEFINE_string(action, "",
                "Indicates whether the service manager daemon is in the "
                "permissive mode. In permissive mode, the requests with wrong "
                "identity won't be rejected.");

  brillo::InitLog(brillo::kLogToStderr);
  brillo::FlagHelper::Init(argc, argv, "Mojo service manager test tool");
  logging::SetMinLogLevel(FLAGS_log_level);

  mojo::core::Init();
  brillo::Daemon daemon;
  mojo::core::ScopedIPCSupport ipc_support(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::
          CLEAN /* blocking shutdown */);
  mojo::Remote<mojom::ServiceManager> service_manager{
      ConnectToMojoServiceManager()};
  service_manager.set_disconnect_with_reason_handler(
      base::BindOnce([](uint32_t error, const std::string& message) {
        LOG(FATAL) << "Service manager disconnected: " << error << ", "
                   << message;
      }));

  if (FLAGS_action == kActionCreateTestService)
    return CreateTestService(daemon, service_manager.get());
  if (FLAGS_action == kActionPingTestService)
    return PingTestService(daemon, service_manager.get());
  if (FLAGS_action == kActionTestSharedBuffer)
    return TestSharedBuffer();

  LOG(ERROR) << "Unknown action " << FLAGS_action << ", could be "
             << kActionCreateTestService << ", " << kActionPingTestService
             << ", " << kActionTestSharedBuffer;
  return 1;
}

}  // namespace mojo_service_manager
}  // namespace chromeos

int main(int argc, char* argv[]) {
  return chromeos::mojo_service_manager::TestToolMain(argc, argv);
}
