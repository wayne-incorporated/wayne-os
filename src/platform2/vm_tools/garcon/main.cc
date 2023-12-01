// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <limits.h>
#include <signal.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h
#include <vm_protos/proto_bindings/container_host.pb.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_split.h>

// syslog.h and base/logging.h both try to #define LOG_INFO and LOG_WARNING.
// We need to #undef at least these two before including base/logging.h.  The
// others are included to be consistent.
namespace {
const int kSyslogDebug = LOG_DEBUG;
const int kSyslogInfo = LOG_INFO;
const int kSyslogWarning = LOG_WARNING;
const int kSyslogError = LOG_ERR;
const int kSyslogCritical = LOG_CRIT;

#undef LOG_INFO
#undef LOG_WARNING
#undef LOG_ERR
#undef LOG_CRIT
}  // namespace

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/synchronization/waitable_event.h>
#include <base/system/sys_info.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/task_runner.h>
#include <base/threading/thread.h>
#include <vm_protos/proto_bindings/container_guest.grpc.pb.h>
#include <chromeos/constants/vm_tools.h>
#include <base/files/scoped_file.h>

#include "google/protobuf/util/json_util.h"
#include "vm_tools/common/paths.h"
#include "vm_tools/common/spawn_util.h"
#include "vm_tools/garcon/file_chooser_dbus_service.h"
#include "vm_tools/garcon/host_notifier.h"
#include "vm_tools/garcon/package_kit_proxy.h"
#include "vm_tools/garcon/screensaver_dbus_service.h"
#include "vm_tools/garcon/service_impl.h"

namespace {

constexpr char kLogPrefix[] = "garcon: ";
constexpr char kAllowAnyUserSwitch[] = "allow_any_user";
constexpr char kServerSwitch[] = "server";
constexpr char kClientSwitch[] = "client";
constexpr char kUrlSwitch[] = "url";
constexpr char kTerminalSwitch[] = "terminal";
constexpr char kSelectFileSwitch[] = "selectfile";
constexpr char kSelectFileTypeSwitch[] = "type";
constexpr char kSelectFileTitleSwitch[] = "title";
constexpr char kSelectFilePathSwitch[] = "path";
constexpr char kSelectFileExtensionsSwitch[] = "extensions";
constexpr char kDiskSwitch[] = "disk";
constexpr char kShaderSwitch[] = "borealis-shader-cache";
constexpr char kShaderAppIDSwitch[] = "app-id";
constexpr char kShaderInstallSwitch[] = "install";
constexpr char kShaderUninstallSwitch[] = "uninstall";
constexpr char kShaderMountSwitch[] = "mount";
constexpr char kShaderUnmountSwitch[] = "unmount";
constexpr char kShaderWaitSwitch[] = "wait";
constexpr char kGetDiskInfoArg[] = "get_disk_info";
constexpr char kRequestSpaceArg[] = "request_space";
constexpr char kReleaseSpaceArg[] = "release_space";
constexpr char kSftpServer[] = "/usr/lib/openssh/sftp-server";
constexpr char kMetricsSwitch[] = "metrics";
constexpr uint32_t kVsockPortStart = 10000;
constexpr uint32_t kVsockPortEnd = 20000;
constexpr int kSecurityTokenLength = 36;

constexpr uid_t kCrostiniDefaultUid = 1000;

bool LogToSyslog(logging::LogSeverity severity,
                 const char* /* file */,
                 int /* line */,
                 size_t message_start,
                 const std::string& message) {
  switch (severity) {
    case logging::LOGGING_INFO:
      severity = kSyslogInfo;
      break;
    case logging::LOGGING_WARNING:
      severity = kSyslogWarning;
      break;
    case logging::LOGGING_ERROR:
      severity = kSyslogError;
      break;
    case logging::LOGGING_FATAL:
      severity = kSyslogCritical;
      break;
    default:
      severity = kSyslogDebug;
      break;
  }
  syslog(severity, "%s", message.c_str() + message_start);

  return true;
}

void BlockSigterm() {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  PCHECK(sigprocmask(SIG_BLOCK, &mask, nullptr) == 0);
}

// Picks a vsock port, listens on it, and launches sftp-server when the
// other side connects.
void RunSftpHandler(uint32_t* sftp_port, base::WaitableEvent* event) {
  BlockSigterm();
  base::ScopedFD vsock(socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0));
  PCHECK(vsock.is_valid());
  {
    const sockaddr_vm addr{
        .svm_family = AF_VSOCK,
        .svm_port = VMADDR_PORT_ANY,
        .svm_cid = VMADDR_CID_ANY,
    };
    PCHECK(bind(vsock.get(), reinterpret_cast<const struct sockaddr*>(&addr),
                sizeof(addr)) == 0);
  }
  PCHECK(listen(vsock.get(), 1) == 0);
  {
    sockaddr_vm addr;
    socklen_t len = sizeof(addr);
    PCHECK(getsockname(vsock.get(), reinterpret_cast<struct sockaddr*>(&addr),
                       &len) == 0);
    *sftp_port = addr.svm_port;
  }
  LOG(INFO) << "sftp listening on vsock port " << *sftp_port;
  event->Signal();

  // TODO(b/231500896): Does this loop need to exit? Maybe check
  // base::Thread::IsRunning?
  while (1) {
    LOG(INFO) << "sftp: accept waiting";
    sockaddr_vm addr;
    socklen_t len = sizeof(addr);
    base::ScopedFD fd(accept4(vsock.get(),
                              reinterpret_cast<struct sockaddr*>(&addr), &len,
                              SOCK_CLOEXEC));
    PCHECK(fd.is_valid());
    LOG(INFO) << "sftp: accepted connection from vsock:" << addr.svm_cid << ":"
              << addr.svm_port;

    std::vector<std::string> argv = {kSftpServer};
    std::map<std::string, std::string> env;
    const std::string working_dir;
    int stdio_fd[3] = {fd.get(), fd.get(), STDERR_FILENO};
    if (vm_tools::Spawn(argv, env, working_dir, stdio_fd)) {
      fd.reset();
      LOG(INFO) << "sftp: forked child process";
    } else {
      PLOG(ERROR) << "sftp: failed to spawn child process";
    }
  }
}

void RunGarconService(vm_tools::garcon::PackageKitProxy* pk_proxy,
                      base::WaitableEvent* event,
                      std::shared_ptr<grpc::Server>* server_copy,
                      int* vsock_listen_port,
                      scoped_refptr<base::TaskRunner> task_runner,
                      vm_tools::garcon::HostNotifier* host_notifier) {
  // We don't want to receive SIGTERM on this thread.
  BlockSigterm();

  // See crbug.com/922694 for more reference.
  // There's a bug in our patched version of gRPC where it uses signed integers
  // for ports. VSOCK uses unsigned integers for ports. So if we let the kernel
  // choose the port for us, then it can end up choosing one that has the high
  // bit set and cause gRPC to assert on the negative port number. This was a
  // much easier solution than patching gRPC or updating the kernel to keep the
  // VSOCK ports in the signed integer range.
  // The end on this for loop only exists to prevent running forever in case
  // something else goes wrong.
  for (*vsock_listen_port = kVsockPortStart; *vsock_listen_port < kVsockPortEnd;
       ++(*vsock_listen_port)) {
    // Build the server.
    grpc::ServerBuilder builder;
    builder.AddListeningPort(
        base::StringPrintf("vsock:%u:%d", VMADDR_CID_ANY, *vsock_listen_port),
        grpc::InsecureServerCredentials(), nullptr);

    vm_tools::garcon::ServiceImpl garcon_service(pk_proxy, task_runner.get(),
                                                 host_notifier);
    builder.RegisterService(&garcon_service);

    std::shared_ptr<grpc::Server> server(builder.BuildAndStart().release());
    if (!server) {
      LOG(WARNING) << "garcon failed binding requested vsock port "
                   << *vsock_listen_port << ", trying again with a new port";
      continue;
    }

    *server_copy = server;
    event->Signal();

    LOG(INFO) << "garcon listening on vsock port " << *vsock_listen_port;
    // The following call will return once we invoke Shutdown on the gRPC
    // server when the main RunLoop exits.
    server->Wait();
    break;
  }
}

void CreatePackageKitProxy(
    base::WaitableEvent* event,
    vm_tools::garcon::HostNotifier* host_notifier,
    std::unique_ptr<vm_tools::garcon::PackageKitProxy>* proxy_ptr) {
  // We don't want to receive SIGTERM on this thread.
  BlockSigterm();

  *proxy_ptr = vm_tools::garcon::PackageKitProxy::Create(host_notifier);
  event->Signal();
}

void CreateDBusServices(
    base::WaitableEvent* event,
    vm_tools::garcon::HostNotifier* host_notifier,
    std::unique_ptr<vm_tools::garcon::ScreenSaverDBusService>*
        screensaver_proxy_ptr,
    std::unique_ptr<vm_tools::garcon::FileChooserDBusService>*
        file_chooser_proxy_ptr) {
  // We don't want to receive SIGTERM on this thread.
  BlockSigterm();

  *screensaver_proxy_ptr =
      vm_tools::garcon::ScreenSaverDBusService::Create(host_notifier);
  *file_chooser_proxy_ptr =
      vm_tools::garcon::FileChooserDBusService::Create(host_notifier);
  event->Signal();
}

void PrintUsage() {
  LOG(INFO) << "Garcon: VM container bridge for Chrome OS\n\n"
            << "Mode Switches (must use one):\n"
            << "Mode Switch:\n"
            << "  --server: run in background as daemon\n"
            << "  --client: run as client and send message to host\n"
            << "Client Switches (only with --client):\n"
            << "  --url: opens all arguments as URLs in host browser\n"
            << "  --terminal: opens terminal\n"
            << "  --selectfile: open file dialog and return file: URL list\n"
            << "  --disk: handles requests relating to disk management\n"
            << "  --metrics: reports metrics to the host\n"
            << "  --borealis-shader-cache: (un)install shader cache\n"
            << "Borealis Shader Cache Switches "
            << "(only with --client --borealis-shader-cache):\n"
            << "  --app-id: Steam app ID\n"
            << "  --install: (optional) Install shader cache DLC\n"
            << "  --uninstall: (optional) Unmount and uninstall shader cache\n"
            << "               DLC\n"
            << "  --unmount: (optional) Unmount shader cache for this VM\n"
            << "  --mount: (optional, use with --install) Upon shader cache\n"
            << "           DLC installation, mount the DLC contents to VM's\n"
            << "           GPU cache\n"
            << "  --wait: (optional, use with --install or --unmount) Wait\n"
            << "          for all the operations to complete, including DLC\n"
            << "          download for --install\n"
            << "Select File Switches (only with --client --selectfile):\n"
            << "  --type: "
               "open-file|open-multi-file|saveas-file|folder|upload-folder\n"
            << "  --title: title for dialog\n"
            << "  --path: default path (file: URL or path)\n"
            << "  --extensions: comma-separated list of allowed extensions\n"
            << "Disk args (use with --client --disk):\n"
            << "  get_disk_info: returns information about the disk\n"
            << "  request_space <bytes>: tries to expand the disk by <bytes>\n"
            << "  release_space <bytes>: tries to shrink the disk by <bytes>\n"
            << "Metrics args (use with --client --metrics):\n"
            << "  <metric_name>=<metric_value>,[...]\n"
            << "Server Switches (only with --server):\n"
            << "  --allow_any_user: allow running as non-default uid\n";
}

std::string GetSecurityToken() {
  char token[kSecurityTokenLength + 1];
  base::FilePath security_token_path(vm_tools::kGarconContainerTokenFile);
  int num_read = base::ReadFile(security_token_path, token, sizeof(token) - 1);
  if (num_read <= 0) {
    return "";
  }
  token[num_read] = '\0';
  return std::string(token);
}

int HandleDiskArgs(std::vector<std::string> args,
                   vm_tools::garcon::HostNotifier* host_notifier) {
  std::string output;
  if (args.empty()) {
    LOG(ERROR) << "Missing arguments in --disk mode";
    PrintUsage();
    return -1;
  }
  google::protobuf::util::JsonOptions options;
  options.always_print_primitive_fields = true;
  if (args.at(0) == kGetDiskInfoArg) {
    vm_tools::container::GetDiskInfoResponse response;
    host_notifier->GetDiskInfo(&response);
    // Error code 4 is for invalid requests; those that have incomplete meta
    // data, don't originate from Borealis or are made when Chrome infra isn't
    // set up. To support unorthodox workflows, we return basic information,
    // rather than an error.
    if (response.error() == 4) {
      response.set_error(0);
      int free_space =
          base::SysInfo::AmountOfFreeDiskSpace(base::FilePath("/mnt/stateful"));
      response.set_available_space(free_space);
      // TODO(b/223308797): Potentially revert this to being empty.
      response.set_expandable_space(free_space);
    }
    google::protobuf::util::MessageToJsonString(response, &output, options);
    std::cout << output << std::endl;
    if (response.error() == 0)
      return 0;
    LOG(WARNING) << "Something went wrong when requesting disk info";
    return -1;
  }
  if (args.size() < 2) {
    LOG(ERROR) << "Missing additional argument for request/release space";
    PrintUsage();
    return -1;
  }
  uint64_t space_arg;
  bool arg_conversion = base::StringToUint64(args.at(1), &space_arg);
  if (args.at(0) == kRequestSpaceArg) {
    vm_tools::container::RequestSpaceResponse response;
    if (arg_conversion) {
      host_notifier->RequestSpace(space_arg, &response);
    } else {
      LOG(WARNING) << "Couldn't parse requested_bytes (expected Uint64)";
      PrintUsage();
      response.set_error(1);
    }
    google::protobuf::util::MessageToJsonString(response, &output, options);
    std::cout << output << std::endl;
    if (response.error() == 0)
      return 0;
    LOG(WARNING) << "Something went wrong when requesting for more space";
    return -1;
  }
  if (args.at(0) == kReleaseSpaceArg) {
    vm_tools::container::ReleaseSpaceResponse response;
    if (arg_conversion) {
      host_notifier->ReleaseSpace(space_arg, &response);
    } else {
      LOG(WARNING) << "Couldn't parse bytes_to_release (expected Uint64)";
      PrintUsage();
      response.set_error(1);
    }
    google::protobuf::util::MessageToJsonString(response, &output, options);
    std::cout << output << std::endl;
    if (response.error() == 0)
      return 0;
    LOG(WARNING) << "Something went wrong when releasing disk space";
    return -1;
  }
  LOG(ERROR) << "Invalid disk request";
  PrintUsage();
  return -1;
}

int HandleMetricsArgs(std::vector<std::string> args,
                      vm_tools::garcon::HostNotifier* host_notifier) {
  vm_tools::container::ReportMetricsRequest request;
  if (args.empty()) {
    LOG(ERROR) << "Missing arguments in --metrics mode";
    PrintUsage();
    return -1;
  }

  // Expected argument: swap_bytes_written=1234567890,bytes_written=99999999,...
  base::StringPairs key_value_pairs;
  if (!base::SplitStringIntoKeyValuePairs(args.at(0), '=', ',',
                                          &key_value_pairs)) {
    LOG(ERROR) << "Invalid argument to --metrics";
    PrintUsage();
    return -1;
  }

  for (const auto& [metric_name, metric_value] : key_value_pairs) {
    auto metric = request.add_metric();
    metric->set_name(metric_name);
    uint64_t metric_arg;
    bool arg_conversion = base::StringToUint64(metric_value, &metric_arg);
    if (!arg_conversion) {
      LOG(ERROR) << "Couldn't parse metric value (expected Uint64)";
      PrintUsage();
      return -1;
    }
    metric->set_value(metric_arg);
  }

  vm_tools::container::ReportMetricsResponse response;
  if (!host_notifier->ReportMetrics(std::move(request), &response)) {
    LOG(ERROR) << "ReportMetrics RPC to host failed";
    // Distinguish this error from other errors as it's reasonable
    // to retry the request if this error happens.
    return 1;
  }

  if (response.error() != 0) {
    LOG(ERROR) << "ReportMetrics RPC to host returned error "
               << response.error();
    return -1;
  }

  return 0;
}

int HandleShaderCacheArgs(base::CommandLine* cl,
                          vm_tools::garcon::HostNotifier* host_notifier) {
  uint64_t app_id = 0;
  std::string app_id_string = cl->GetSwitchValueNative(kShaderAppIDSwitch);
  if (app_id_string.empty()) {
    LOG(ERROR) << "Missing --" << kShaderAppIDSwitch << "=<Steam appid>";
    return -1;
  }
  base::StringToUint64(app_id_string, &app_id);
  if (app_id == 0) {
    LOG(ERROR) << "Invalid app ID";
    return -1;
  }

  auto flag_set = {kShaderInstallSwitch, kShaderUninstallSwitch,
                   kShaderUnmountSwitch};
  int flag_count = 0;
  std::ostringstream flags_combined;
  for (auto flag : flag_set) {
    flag_count += cl->HasSwitch(flag);
    flags_combined << flag << " ";
  }
  if (flag_count > 1) {
    LOG(ERROR) << "Only one of the following flags is allowed: "
               << flags_combined.str();
    return -1;
  } else if (flag_count == 0) {
    LOG(ERROR) << "One of the following flags must be specified: "
               << flags_combined.str();
    return -1;
  }

  bool success = false;
  if (cl->HasSwitch(kShaderInstallSwitch)) {
    LOG(INFO) << "Installing shader cache for " << app_id_string;
    if (cl->HasSwitch(kShaderMountSwitch)) {
      LOG(INFO) << "Upon successful installation, shader cache will be mounted";
    }
    if (cl->HasSwitch(kShaderWaitSwitch)) {
      LOG(INFO) << "Waiting for all operations to complete";
    }
    success = host_notifier->InstallShaderCache(
        app_id, cl->HasSwitch(kShaderMountSwitch),
        cl->HasSwitch(kShaderWaitSwitch));

  } else if (cl->HasSwitch(kShaderUnmountSwitch)) {
    LOG(INFO) << "Queuing unmount command for " << app_id_string
              << " in the background. Shader cache will be unmounted once mesa"
              << " stops using them.";
    if (cl->HasSwitch(kShaderWaitSwitch)) {
      LOG(INFO) << "Waiting for all operations to complete";
    }
    success = host_notifier->UnmountShaderCache(
        app_id, cl->HasSwitch(kShaderWaitSwitch));

  } else if (cl->HasSwitch(kShaderUninstallSwitch)) {
    if (cl->HasSwitch(kShaderMountSwitch)) {
      LOG(WARNING) << "Shader cache being uninstalled, ignoring --"
                   << kShaderMountSwitch;
    }
    if (cl->HasSwitch(kShaderWaitSwitch)) {
      LOG(WARNING) << "Shader cache uninstall always waits, --"
                   << kShaderWaitSwitch << " flag is redundant";
    }
    if (cl->HasSwitch(kShaderUnmountSwitch)) {
      LOG(WARNING) << "Shader cache uninstall always unmounts, --"
                   << kShaderWaitSwitch << " flag is redundant";
    }
    LOG(INFO) << "Unmounting and uninstalling shader cache for "
              << app_id_string;
    success = host_notifier->UninstallShaderCache(app_id);
  } else {
    LOG(ERROR) << "No command specified, specify one of --"
               << kShaderInstallSwitch << ", --" << kShaderUnmountSwitch
               << ", --" << kShaderUninstallSwitch;
  }

  return success ? 0 : -1;
}
}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  logging::InitLogging(logging::LoggingSettings());

  bool serverMode = cl->HasSwitch(kServerSwitch);
  bool clientMode = cl->HasSwitch(kClientSwitch);
  // The standard says that bool to int conversion is implicit and that
  // false => 0 and true => 1.
  // clang-format off
  if (serverMode + clientMode != 1) {
    // clang-format on
    LOG(ERROR) << "Exactly one of --server or --client must be used.";
    PrintUsage();
    return -1;
  }

  std::string token = GetSecurityToken();
  if (token.empty()) {
    if (clientMode) {
      LOG(ERROR) << "Failed to read the security token.";
      return -1;
    } else {
      LOG(WARNING) << "Failed to read the security token, retrying.";
      base::TimeTicks start = base::TimeTicks::Now();
      while (token.empty()) {
        if (base::TimeTicks::Now() - start > base::Minutes(1)) {
          LOG(ERROR) << "Timed out waiting for security token.";
          return -1;
        }
        base::PlatformThread::Sleep(base::Milliseconds(100));
        token = GetSecurityToken();
      }
    }
  }

  std::unique_ptr<vm_tools::garcon::HostNotifier> host_notifier =
      vm_tools::garcon::HostNotifier::Create(token);
  if (!host_notifier) {
    LOG(ERROR) << "Failure setting up the HostNotifier";
    return -1;
  }

  if (clientMode) {
    if (cl->HasSwitch(kUrlSwitch)) {
      std::vector<std::string> args = cl->GetArgs();
      if (args.empty()) {
        LOG(ERROR) << "Missing URL arguments in --url mode";
        PrintUsage();
        return -1;
      }
      // All arguments are URLs, send them to the host to be opened. The host
      // will do its own verification for validity of the URLs.
      for (const auto& arg : args) {
        if (!host_notifier->OpenUrlInHost(arg)) {
          return -1;
        }
      }
      return 0;
    } else if (cl->HasSwitch(kTerminalSwitch)) {
      std::vector<std::string> args = cl->GetArgs();
      if (host_notifier->OpenTerminal(std::move(args)))
        return 0;
      else
        return -1;
    } else if (cl->HasSwitch(kSelectFileSwitch)) {
      std::string type = cl->GetSwitchValueNative(kSelectFileTypeSwitch);
      std::string title = cl->GetSwitchValueNative(kSelectFileTitleSwitch);
      std::string path = cl->GetSwitchValueNative(kSelectFilePathSwitch);
      std::string extensions =
          cl->GetSwitchValueNative(kSelectFileExtensionsSwitch);
      std::vector<std::string> files;
      if (host_notifier->SelectFile(type, title, path, extensions, &files)) {
        for (const auto& file : files) {
          std::cout << file << std::endl;
        }
        return 0;
      } else {
        return -1;
      }
    } else if (cl->HasSwitch(kDiskSwitch)) {
      return HandleDiskArgs(cl->GetArgs(), host_notifier.get());
    } else if (cl->HasSwitch(kMetricsSwitch)) {
      return HandleMetricsArgs(cl->GetArgs(), host_notifier.get());
    } else if (cl->HasSwitch(kShaderSwitch)) {
      return HandleShaderCacheArgs(cl, host_notifier.get());
    }
    LOG(ERROR) << "Missing client switch for client mode.";
    PrintUsage();
    return -1;
  }

  // Set up logging to syslog for server mode.
  openlog(kLogPrefix, LOG_PID, LOG_DAEMON);
  logging::SetLogMessageHandler(LogToSyslog);

  // Exit if not running as the container default user.
  if (getuid() != kCrostiniDefaultUid && !cl->HasSwitch(kAllowAnyUserSwitch)) {
    LOG(ERROR) << "garcon normally runs only as uid(" << kCrostiniDefaultUid
               << "). Use --allow_any_user to override";
    return -1;
  }

  // Note on the threading model: There are 5 threads used in garcon:
  //
  // - incoming gRPC requests
  // - handling connections to the sftp-server over vsock
  // - D-Bus communication with the PackageKit
  // - the main thread which is for gRPC requests to the host as well as for
  // monitoring filesystem changes (which result in a
  // gRPC call to the host under certain conditions). The main thing to be
  // careful of is that the gRPC thread for incoming requests is never blocking
  // on the gRPC thread for outgoing requests (since they are both talking to
  // cicerone, and both of those operations in cicerone are likely going to use
  // the same D-Bus thread for communication within cicerone).
  // - running tasks initiated by garcon service.

  // Thread that the gRPC server is running on.
  base::Thread grpc_thread{"gRPC Server Thread"};
  if (!grpc_thread.Start()) {
    LOG(ERROR) << "Failed starting the gRPC thread";
    return -1;
  }

  // Thread that the sftp-server handler is running on.
  base::Thread sftp_thread{"sftp-server Thread"};
  if (!sftp_thread.Start()) {
    LOG(ERROR) << "Failed starting the sftp-server thread";
    return -1;
  }

  // Thread that D-Bus communication runs on.
  base::Thread dbus_thread{"D-Bus Thread"};
  if (!dbus_thread.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed starting the D-Bus thread";
    return -1;
  }

  // Thread that tasks started from garcon service run on.
  // Specifically, Ansible playbook application runs on
  // |garcon_service_tasks_thread|.
  base::Thread garcon_service_tasks_thread{"Garcon Service Tasks Thread"};
  if (!garcon_service_tasks_thread.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed starting the garcon service tasks thread";
    return -1;
  }

  // Setup the HostNotifier on the run loop for the main thread. It needs to
  // have its own run loop separate from the gRPC server & D-Bus server since it
  // will be using base::FilePathWatcher to identify installed application and
  // mime type changes.
  base::RunLoop run_loop;

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);

  // This needs to be created on the D-Bus thread.
  std::unique_ptr<vm_tools::garcon::PackageKitProxy> pk_proxy;
  bool ret = dbus_thread.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&CreatePackageKitProxy, &event,
                                host_notifier.get(), &pk_proxy));
  if (!ret) {
    LOG(ERROR) << "Failed to post PackageKit proxy creation to D-Bus thread";
    return -1;
  }
  // Wait for the creation to complete.
  event.Wait();
  if (!pk_proxy) {
    LOG(ERROR) << "Failed in creating the PackageKit proxy";
    return -1;
  }
  event.Reset();

  // These need to be created on the D-Bus thread.
  std::unique_ptr<vm_tools::garcon::ScreenSaverDBusService> screensaver;
  std::unique_ptr<vm_tools::garcon::FileChooserDBusService> file_chooser;
  ret = dbus_thread.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CreateDBusServices, &event, host_notifier.get(),
                     &screensaver, &file_chooser));
  if (!ret) {
    LOG(ERROR) << "Failed to post D-Bus server creation to D-Bus thread";
    return -1;
  }
  // Wait for the creation to complete.
  event.Wait();
  if (!screensaver || !file_chooser) {
    // Not returning -1 on failure as it is not essential for the VM to start.
    LOG(ERROR) << "Failed in creating the D-Bus servers";
  }
  event.Reset();

  // Launch the gRPC server on the gRPC thread.
  std::shared_ptr<grpc::Server> server_copy;
  int vsock_listen_port = 0;
  ret = grpc_thread.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&RunGarconService, pk_proxy.get(), &event,
                                &server_copy, &vsock_listen_port,
                                garcon_service_tasks_thread.task_runner(),
                                host_notifier.get()));
  if (!ret) {
    LOG(ERROR) << "Failed to post server startup task to grpc thread";
    return -1;
  }

  // Wait for the gRPC server to start.
  event.Wait();
  if (!server_copy) {
    LOG(ERROR) << "gRPC server failed to start";
    return -1;
  }
  event.Reset();

  // Launch a thread that listens for incoming connections and runs sftp-server
  // to handle them.
  uint32_t sftp_port = 0;
  ret = sftp_thread.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&RunSftpHandler, &sftp_port, &event));
  if (!ret) {
    LOG(ERROR) << "Failed to post server startup task to sftp thread";
    return -1;
  }

  // Wait for the sftp server to start.
  event.Wait();
  if (sftp_port == 0) {
    LOG(ERROR) << "sftp server failed to start";
    return -1;
  }
  event.Reset();

  if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
    PLOG(ERROR) << "Unable to explicitly ignore SIGCHILD";
    return -1;
  }

  if (!host_notifier->InitServer(run_loop.QuitClosure(),
                                 static_cast<uint32_t>(vsock_listen_port),
                                 sftp_port, pk_proxy.get())) {
    LOG(ERROR) << "Failed to set up host notifier";
    return -1;
  }

  // Start the main run loop now for the HostNotifier.
  run_loop.Run();

  // We get here after a SIGTERM gets posted and the main run loop has exited.
  // We then shutdown the gRPC server (which will terminate that thread) and
  // then stop the D-Bus thread. We will be the only remaining thread at that
  // point so everything can be safely destructed and we remove the need for
  // any weak pointers.
  server_copy->Shutdown();
  dbus_thread.Stop();
  garcon_service_tasks_thread.Stop();
  sftp_thread.Stop();
  return 0;
}
