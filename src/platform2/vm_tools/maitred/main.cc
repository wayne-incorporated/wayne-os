// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <memory>
#include <string>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/threading/thread.h>
#include <google/protobuf/message.h>
#include <google/protobuf/text_format.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>
#include <chromeos/constants/vm_tools.h>

#include "vm_tools/maitred/init.h"
#include "vm_tools/maitred/service_impl.h"

using std::string;

namespace {

// Path to logging file.
constexpr char kDevKmsg[] = "/dev/kmsg";

// Prefix inserted before every log message.
constexpr char kLogPrefix[] = "maitred: ";

// Path to kernel cmdline file.
constexpr char kKernelCmdFile[] = "/proc/cmdline";

// Path to folder of .textproto files to start on init.
constexpr char kMaitredInitPath[] = "/etc/maitred/";

// Kernel Command line parameter
constexpr char kMaitredPortParam[] = "maitred.listen_port=";
constexpr char kMaitredPortParamFmt[] = "maitred.listen_port=%d";
constexpr char kMaitredStartProcessesParam[] = "maitred.no_startup_processes";

// File descriptor for log messages. Defaults to stderr.
// Needs to be a global variable because logging::LogMessageHandlerFunction is
// just a function pointer so we can't bind any variables to it via
// base::Bind*.
int g_log_fd = STDERR_FILENO;
// Prefix for log messages. Default is empty.
const char* g_log_prefix = "";

bool LogHandler(logging::LogSeverity severity,
                const char* file,
                int line,
                size_t message_start,
                const string& message) {
  const char* priority = nullptr;
  switch (severity) {
    case logging::LOGGING_VERBOSE:
      priority = "<7>";
      break;
    case logging::LOGGING_INFO:
      priority = "<6>";
      break;
    case logging::LOGGING_WARNING:
      priority = "<4>";
      break;
    case logging::LOGGING_ERROR:
      priority = "<3>";
      break;
    case logging::LOGGING_FATAL:
      priority = "<2>";
      break;
    default:
      priority = "<5>";
      break;
  }

  const struct iovec iovs[] = {
      {
          .iov_base = static_cast<void*>(const_cast<char*>(priority)),
          .iov_len = strlen(priority),
      },
      {
          .iov_base = static_cast<void*>(const_cast<char*>(g_log_prefix)),
          .iov_len = strlen(g_log_prefix),
      },
      {
          .iov_base = static_cast<void*>(
              const_cast<char*>(message.c_str() + message_start)),
          .iov_len = message.length() - message_start,
      },
  };

  ssize_t count = 0;
  for (const struct iovec& iov : iovs) {
    count += iov.iov_len;
  }

  ssize_t ret =
      HANDLE_EINTR(writev(g_log_fd, iovs, sizeof(iovs) / sizeof(struct iovec)));

  // Even if the write wasn't successful, we can't log anything here because
  // this _is_ the logging function.  Just return whether the write succeeded.
  return ret == count;
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  logging::InitLogging(logging::LoggingSettings());

  // Make sure that stdio is set up correctly.
  for (int fd = 0; fd < 3; ++fd) {
    if (fcntl(fd, F_GETFD) >= 0) {
      continue;
    }

    CHECK_EQ(errno, EBADF);

    int newfd = open("/dev/null", O_RDWR);
    CHECK_EQ(fd, newfd);
  }

  // Get PID of maitred to decide at runtime how maitred ran as PID 1 or
  // non-PID 1. If maitred is non-PID 1, maitred will not have to run init
  // functionality that systemd already does
  bool maitred_is_pid1 = getpid() == 1;
  LOG(INFO) << "maitred running as PID1 " << maitred_is_pid1;

  // Set up logging to /dev/kmsg if maitred is PID 1.
  if (maitred_is_pid1) {
    g_log_fd = open(kDevKmsg, O_WRONLY | O_CLOEXEC);
    CHECK_GE(g_log_fd, 0);
    g_log_prefix = kLogPrefix;
  }
  logging::SetLogMessageHandler(LogHandler);

  std::unique_ptr<vm_tools::maitred::Init> init;
  init = vm_tools::maitred::Init::Create(maitred_is_pid1);
  CHECK(init);

  // Check for kernel parameter to set startup listener port.
  int startup_port = vm_tools::kDefaultStartupListenerPort;
  // Check for kernel parameter to disable startup processes.
  bool run_startup_processes = true;

  // Parse kernel command line
  std::string kernel_parameters;
  if (base::ReadFileToString(base::FilePath(kKernelCmdFile),
                             &kernel_parameters)) {
    std::vector<base::StringPiece> params = base::SplitStringPiece(
        kernel_parameters, " ", base::WhitespaceHandling::TRIM_WHITESPACE,
        base::SplitResult::SPLIT_WANT_NONEMPTY);

    for (auto& p : params) {
      if (base::StartsWith(p, kMaitredPortParam,
                           base::CompareCase::SENSITIVE)) {
        int read_port;
        if (sscanf(std::string(p).c_str(), kMaitredPortParamFmt, &read_port) !=
            1) {
          continue;
        }
        startup_port = read_port;
      } else if (p == kMaitredStartProcessesParam) {
        run_startup_processes = false;
      }
    }
  }

  if (run_startup_processes) {
    // Check for startup applications in the maitred init folder.
    base::FileEnumerator file_enum(base::FilePath(kMaitredInitPath), true,
                                   base::FileEnumerator::FILES);
    std::vector<base::FilePath> files;
    for (base::FilePath file = file_enum.Next(); !file.empty();
         file = file_enum.Next()) {
      files.push_back(file);
    }

    // Sort the files so that they are started in alphabetical order.
    // See docs/init.md for more details.
    std::sort(files.begin(), files.end());

    for (const auto& file : files) {
      std::string contents;
      if (!base::ReadFileToString(file, &contents)) {
        LOG(ERROR) << "Unable to read file " << file.value();
        continue;
      }

      vm_tools::LaunchProcessRequest req;
      if (!google::protobuf::TextFormat::ParseFromString(contents, &req)) {
        LOG(ERROR) << "Unable to parse proto file: " << file.value();
        continue;
      }

      if (req.argv_size() <= 0) {
        LOG(ERROR) << "No argv in proto file " << file.value();
        continue;
      }

      std::vector<std::string> argv(req.argv().begin(), req.argv().end());
      std::map<string, string> env;
      for (const auto& pair : req.env()) {
        env[pair.first] = pair.second;
      }

      vm_tools::maitred::Init::ProcessLaunchInfo launch_info;
      if (!init->Spawn(std::move(argv), std::move(env), req.respawn(),
                       req.use_console(), req.wait_for_exit(), &launch_info)) {
        LOG(ERROR) << "Unable to spawn job: " << file.BaseName().value();
        continue;
      }

      switch (launch_info.status) {
        case vm_tools::maitred::Init::ProcessStatus::LAUNCHED:
          LOG(INFO) << "Successfully launched job: " << file.BaseName().value();
          break;
        case vm_tools::maitred::Init::ProcessStatus::EXITED:
          LOG(INFO) << "Job " << file.BaseName().value()
                    << " exited with status " << launch_info.code;
          break;
        case vm_tools::maitred::Init::ProcessStatus::SIGNALED:
          LOG(INFO) << "Job " << file.BaseName().value() << " killed by signal "
                    << launch_info.code;
          break;
        case vm_tools::maitred::Init::ProcessStatus::FAILED:
          LOG(ERROR) << "Failed to launch job: " << file.BaseName().value();
          break;
        case vm_tools::maitred::Init::ProcessStatus::UNKNOWN:
          LOG(WARNING) << "Unknown job status: " << file.BaseName().value();
          break;
      }
    }
  }

  base::Thread dbus_thread{"D-Bus Thread"};
  if (!dbus_thread.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed starting the D-Bus thread";
    return -1;
  }

  // Build the server.
  grpc::ServerBuilder builder;
  builder.AddListeningPort(
      base::StringPrintf("vsock:%u:%u", VMADDR_CID_ANY, vm_tools::kMaitredPort),
      grpc::InsecureServerCredentials());

  vm_tools::maitred::ServiceImpl maitred_service(std::move(init),
                                                 maitred_is_pid1);
  if (!maitred_service.Init(dbus_thread.task_runner())) {
    LOG(FATAL) << "Failed to initialize maitred service";
  }
  builder.RegisterService(&maitred_service);

  std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
  CHECK(server);

  // Due to restrictions in the gRPC API, there is no way to stop a server from
  // the same thread on which it is running.  It has to be stopped from a
  // different thread.  So we spawn a new thread here that sits around doing
  // nothing and give the maitre'd service a callback, which it will run when it
  // receives a Shutdown rpc.  This callback will post a task to the idle thread
  // to stop the gRPC server.  Once the server is stopped, it will return from
  // the Wait() call below and we can shut down the whole system by issuing a
  // reboot().
  base::Thread shutdown_thread("shutdown thread");
  CHECK(shutdown_thread.Start());

  // The following line is very confusing but is equivalent to this code:
  //
  // maitred_service.set_shutdown_cb(base::BindOnce(
  //     [](scoped_refptr<base::SingleThreadTaskRunner> runner,
  //        grpc::Server* server) {
  //       runner->PostTask(
  //           FROM_HERE,
  //           base::BindOnce([](grpc::Server* s) { s->Shutdown(); }, server));
  //     },
  //     shutdown_thread.task_runner(), server.get()));
  //
  // Admittedly, that's not much better but the only other option is to move
  // the code into a separate function, which would break up the flow of logic
  // and be arguably less readable than this code + comment.
  //
  // Once base::BindOnce in chrome os has been updated to handle lambdas, we
  // should consider replacing this with the above code instead.
  maitred_service.set_shutdown_cb(base::BindOnce(
      &base::TaskRunner::PostTask, shutdown_thread.task_runner(), FROM_HERE,
      base::BindOnce(
          static_cast<void (grpc::Server::*)(void)>(&grpc::Server::Shutdown),
          base::Unretained(server.get()))));

  LOG(INFO) << "Server listening on port " << vm_tools::kMaitredPort;
  LOG(INFO) << "Using startup listener port: " << startup_port;

  // Notify the host system that we are ready.
  vm_tools::StartupListener::Stub stub(grpc::CreateChannel(
      base::StringPrintf("vsock:%u:%u", VMADDR_CID_HOST, startup_port),
      grpc::InsecureChannelCredentials()));

  grpc::ClientContext ctx;
  vm_tools::EmptyMessage empty;
  grpc::Status status = stub.VmReady(&ctx, empty, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to notify host system that VM is ready: "
                 << status.error_message();
  }

  // The following call will return once the server has been stopped.
  server->Wait();

  if (maitred_is_pid1) {
    LOG(INFO) << "Shutting down system NOW";
    reboot(RB_AUTOBOOT);
  }

  return 0;
}
