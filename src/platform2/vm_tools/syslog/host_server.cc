// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <linux/vm_sockets.h>

#include <memory>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/run_loop.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/file_utils.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>

#include "vm_tools/syslog/forwarder.h"
#include "vm_tools/syslog/log_pipe.h"

namespace {
constexpr unsigned int kPort = 9999;
// Default syslogd path. When |FLAGS_log_destination| is |kDevLog| we forward
// all logs using a unix domain socket.
constexpr char kDevLog[] = "/dev/log";
}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  DEFINE_string(
      log_destination, "",
      "Path to unix domain datagram socket to which logs will be forwarded");
  brillo::FlagHelper::Init(argc, argv, "VM log forwarding tool");

  bool only_log_to_syslog = FLAGS_log_destination == kDevLog;

  base::ScopedFD dest(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (!dest.is_valid()) {
    PLOG(ERROR) << "Failed to create unix domain datagram socket";
    return EXIT_FAILURE;
  }

  struct sockaddr_un un = {
      .sun_family = AF_UNIX,
  };

  DCHECK(sizeof(kDevLog) <= sizeof(un.sun_path));

  // sun_path is zero-initialized above so we just need to copy the path.
  memcpy(un.sun_path, kDevLog, sizeof(kDevLog));

  if (connect(dest.get(), reinterpret_cast<struct sockaddr*>(&un),
              sizeof(un)) != 0) {
    PLOG(ERROR) << "Failed to connect to " << kDevLog;
    return EXIT_FAILURE;
  }

  base::RunLoop run_loop;
  vm_tools::syslog::LogPipeManager log_pipe_manager(run_loop.QuitClosure());
  CHECK(log_pipe_manager.Init(std::move(dest), only_log_to_syslog));

  grpc::ServerBuilder builder;
  builder.AddListeningPort(
      base::StringPrintf("vsock:%u:%u", VMADDR_CID_ANY, kPort),
      grpc::InsecureServerCredentials());
  builder.RegisterService(&log_pipe_manager);

  std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
  CHECK(server);

  LOG(INFO) << "VM log forwarder listening on port " << kPort;

  run_loop.Run();
  server->Shutdown();

  return EXIT_SUCCESS;
}
