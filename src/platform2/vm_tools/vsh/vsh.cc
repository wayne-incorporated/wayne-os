// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <unistd.h>

#include <sys/socket.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <memory>
#include <string>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/process/process.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <brillo/flag_helper.h>
#include <brillo/message_loops/base_message_loop.h>
#include <brillo/syslog_logging.h>
#include <chromeos/constants/vm_tools.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#include <vm_cicerone/cicerone_service.pb.h>
#include <vm_concierge/concierge_service.pb.h>

#include "vm_tools/vsh/scoped_termios.h"
#include "vm_tools/vsh/utils.h"
#include "vm_tools/vsh/vsh_client.h"

using std::string;
using vm_tools::vsh::ScopedTermios;
using vm_tools::vsh::VshClient;

namespace {

constexpr int kDefaultTimeoutMs = 30 * 1000;

constexpr char kVshUsage[] =
    "vsh client\n"
    "Usage: vsh [flags] -- ENV1=VALUE1 ENV2=VALUE2 command arg1 arg2...";

// Connect to the supplied |bus| and return a dbus::ObjectProxy for
// the given |service_name| and |service_path|.
dbus::ObjectProxy* GetServiceProxy(const scoped_refptr<dbus::Bus>& bus,
                                   const string& service_name,
                                   const string& service_path) {
  if (!bus->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
    return nullptr;
  }

  dbus::ObjectProxy* proxy =
      bus->GetObjectProxy(service_name, dbus::ObjectPath(service_path));
  if (!proxy) {
    LOG(ERROR) << "Unable to get dbus proxy for " << service_name;
    return nullptr;
  }

  return proxy;
}

// Parse list of container features like "1,3". Number should correspond to the
// enum values of vm_tools.cicerone.ContainerFeature, but no validation is done.
std::vector<int> ParseContainerFeatures(const std::string& container_features) {
  std::vector<int> result;
  for (const auto& piece :
       base::SplitStringPiece(container_features, ",", base::KEEP_WHITESPACE,
                              base::SPLIT_WANT_NONEMPTY)) {
    int value;
    if (base::StringToInt(piece, &value)) {
      result.push_back(value);
    }
  }
  return result;
}

bool GetCid(dbus::ObjectProxy* concierge_proxy,
            const std::string& owner_id,
            const std::string& vm_name,
            unsigned int* cid) {
  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kGetVmInfoMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::GetVmInfoRequest request;
  request.set_owner_id(owner_id);
  request.set_name(vm_name);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode GetVmInfo protobuf";
    return false;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      concierge_proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return false;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::GetVmInfoResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return false;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to get VM info for " << vm_name;
    return false;
  }

  *cid = response.vm_info().cid();
  return true;
}

bool LaunchVshd(dbus::ObjectProxy* cicerone_proxy,
                const std::string& owner_id,
                const std::string& vm_name,
                const std::string& container_name,
                const std::vector<int>& container_features,
                unsigned int port,
                uint32_t* cid) {
  DCHECK(cid);
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kLaunchVshdMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::LaunchVshdRequest request;
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_port(port);
  request.set_owner_id(owner_id);
  for (int feature : container_features) {
    request.add_container_features(
        static_cast<vm_tools::cicerone::ContainerFeature>(feature));
  }

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode LaunchVshdRequest protobuf";
    return false;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      cicerone_proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return false;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::LaunchVshdResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return false;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to launch vshd for " << vm_name << ":"
               << container_name << ": " << response.failure_reason();
    return false;
  }

  *cid = response.cid();

  return true;
}

bool ListenForVshd(dbus::ObjectProxy* cicerone_proxy,
                   unsigned int port,
                   base::ScopedFD* peer_sock_fd,
                   const std::string& owner_id,
                   const std::string& vm_name,
                   const std::string& container_name,
                   const std::vector<int>& container_features) {
  DCHECK(peer_sock_fd);

  // Create a socket to listen for incoming vsh connections.
  base::ScopedFD listen_fd(
      socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  if (!listen_fd.is_valid()) {
    PLOG(ERROR) << "Failed to create socket";
    return false;
  }

  struct sockaddr_vm addr;
  memset(&addr, 0, sizeof(addr));
  addr.svm_family = AF_VSOCK;
  addr.svm_port = port;
  addr.svm_cid = VMADDR_CID_ANY;

  if (bind(listen_fd.get(), reinterpret_cast<const struct sockaddr*>(&addr),
           sizeof(addr)) < 0) {
    PLOG(ERROR) << "Failed to bind vsh port";
    return false;
  }

  socklen_t addr_len = sizeof(addr);
  if (getsockname(listen_fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                  &addr_len) < 0) {
    PLOG(ERROR) << "Failed to get bound vsh port";
    return false;
  }

  if (listen(listen_fd.get(), 1) < 0) {
    PLOG(ERROR) << "Failed to listen";
    return false;
  }

  // The socket is listening. Request that cicerone start vshd.
  uint32_t expected_cid;
  if (!LaunchVshd(cicerone_proxy, owner_id, vm_name, container_name,
                  container_features, addr.svm_port, &expected_cid))
    return false;

  struct pollfd pollfds[] = {
      {listen_fd.get(), POLLIN, 0},
  };
  const int num_pollfds = std::size(pollfds);

  // Keep polling until we get a POLLIN. Previously we would timeout after 5
  // seconds and treat it as a success.
  if (HANDLE_EINTR(poll(pollfds, num_pollfds, 5000)) <= 0) {
    if (!(pollfds[0].revents & POLLIN)) {
      LOG(ERROR) << "Poll timed out after waiting 5 seconds.";
    } else {
      PLOG(ERROR) << "Failed to poll";
    }
    return false;
  }

  struct sockaddr_vm peer_addr;
  socklen_t addr_size = sizeof(peer_addr);
  peer_sock_fd->reset(HANDLE_EINTR(
      accept4(listen_fd.get(), reinterpret_cast<struct sockaddr*>(&peer_addr),
              &addr_size, SOCK_CLOEXEC)));
  if (!peer_sock_fd->is_valid()) {
    PLOG(ERROR) << "Failed to accept connection from daemon";
    return false;
  }

  if (peer_addr.svm_cid != expected_cid) {
    LOG(ERROR) << "Received connection from VM " << peer_addr.svm_cid
               << " but expected " << expected_cid;
    return false;
  }

  return true;
}

void RegisterVshSession(dbus::ObjectProxy* cicerone_proxy,
                        const std::string& owner_id,
                        const std::string& vm_name,
                        const std::string& container_name,
                        int32_t host_vsh_pid,
                        int32_t container_shell_pid) {
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kRegisterVshSessionMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::RegisterVshSessionRequest request;
  request.set_owner_id(owner_id);
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_host_vsh_pid(host_vsh_pid);
  request.set_container_shell_pid(container_shell_pid);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode RegisterVshSessionRequest protobuf";
    return;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      cicerone_proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::RegisterVshSessionResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to register vsh session for " << owner_id << ": "
               << vm_name << ":" << container_name << ": "
               << response.failure_reason();
  }
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  brillo::InitLog(brillo::kLogToStderr);

  DEFINE_uint64(listen_port, VMADDR_PORT_ANY, "Port to listen on");
  DEFINE_uint64(cid, 0, "Cid of VM");
  DEFINE_string(owner_id, "", "Owner of the VM. Usually user cryptohome_id");
  DEFINE_string(vm_name, "", "Target VM name");
  DEFINE_string(user, "", "Target user in the VM");
  DEFINE_string(target_container, "", "Target container");
  DEFINE_string(cwd, "", "Current working directory");
  DEFINE_string(container_features, "",
                "Features to enable in the container as a comma-separated list "
                "of enum ids (integers).");

  brillo::FlagHelper::Init(argc, argv, kVshUsage);

  brillo::BaseMessageLoop message_loop;
  message_loop.SetAsCurrent();
  std::unique_ptr<VshClient> client;

  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(std::move(opts)));

  bool interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);

  int32_t pid = base::Process::Current().Pid();
  dbus::ObjectProxy* cicerone_proxy = nullptr;

  base::ScopedFD stdout_fd;
  base::ScopedFD stderr_fd;
  if (interactive) {
    // Duplicate the stdout and stderr fds. Otherwise, VshClient will close
    // them and prevent logging after connection shutdown.
    stdout_fd.reset(dup(STDOUT_FILENO));
    if (!stdout_fd.is_valid()) {
      PLOG(ERROR) << "Failed to dup stdout file descriptor";
      return EXIT_FAILURE;
    }
    stderr_fd.reset(dup(STDERR_FILENO));
    if (!stderr_fd.is_valid()) {
      PLOG(ERROR) << "Failed to dup stderr file descriptor";
      return EXIT_FAILURE;
    }
  } else {
    // Take ownership of stdout and stderr, which are likely pipes. These will
    // be closed during the connection shutdown process.
    stdout_fd = base::ScopedFD(STDOUT_FILENO);
    stderr_fd = base::ScopedFD(STDERR_FILENO);
  }

  if (FLAGS_listen_port != VMADDR_PORT_ANY || !FLAGS_target_container.empty()) {
    unsigned int port = 0;
    if (FLAGS_listen_port != 0) {
      port = static_cast<unsigned int>(FLAGS_listen_port);
      if (FLAGS_listen_port < 0 ||
          static_cast<uint64_t>(port) != FLAGS_listen_port) {
        LOG(ERROR) << "Port " << FLAGS_listen_port << " is not a valid port";
        return EXIT_FAILURE;
      }
    }

    cicerone_proxy =
        GetServiceProxy(bus, vm_tools::cicerone::kVmCiceroneServiceName,
                        vm_tools::cicerone::kVmCiceroneServicePath);
    if (!cicerone_proxy)
      return EXIT_FAILURE;

    std::vector<int> container_features =
        ParseContainerFeatures(FLAGS_container_features);
    base::ScopedFD sock_fd;
    if (!ListenForVshd(cicerone_proxy, port, &sock_fd, FLAGS_owner_id,
                       FLAGS_vm_name, FLAGS_target_container,
                       container_features)) {
      return EXIT_FAILURE;
    }

    client = VshClient::Create(std::move(sock_fd), std::move(stdout_fd),
                               std::move(stderr_fd), FLAGS_user,
                               FLAGS_target_container, FLAGS_cwd, interactive);

    if (!client) {
      return EXIT_FAILURE;
    }

    RegisterVshSession(cicerone_proxy, FLAGS_owner_id, FLAGS_vm_name,
                       FLAGS_target_container, pid,
                       client->container_shell_pid());

  } else {
    if ((FLAGS_cid != 0 && !FLAGS_vm_name.empty()) ||
        (FLAGS_cid == 0 && FLAGS_vm_name.empty())) {
      LOG(ERROR) << "Exactly one of --cid or --vm_name is required";
      return EXIT_FAILURE;
    }
    if (!FLAGS_vm_name.empty() && FLAGS_owner_id.empty()) {
      LOG(ERROR) << "If using --vm_name, you must also specify --owner_id";
      return EXIT_FAILURE;
    }
    unsigned int cid;
    if (FLAGS_cid != 0) {
      cid = FLAGS_cid;
      if (static_cast<uint64_t>(cid) != FLAGS_cid) {
        LOG(ERROR) << "Cid value (" << FLAGS_cid << ") is too large.  Largest "
                   << "valid value is "
                   << std::numeric_limits<unsigned int>::max();
        return EXIT_FAILURE;
      }
    } else {
      dbus::ObjectProxy* proxy =
          GetServiceProxy(bus, vm_tools::concierge::kVmConciergeServiceName,
                          vm_tools::concierge::kVmConciergeServicePath);
      if (!proxy)
        return EXIT_FAILURE;
      if (!GetCid(proxy, FLAGS_owner_id, FLAGS_vm_name, &cid))
        return EXIT_FAILURE;
    }

    base::ScopedFD sock_fd(socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!sock_fd.is_valid()) {
      PLOG(ERROR) << "Failed to open vsock socket";
      return EXIT_FAILURE;
    }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_port = vm_tools::kVshPort;
    addr.svm_cid = cid;

    if (HANDLE_EINTR(connect(sock_fd.get(),
                             reinterpret_cast<struct sockaddr*>(&addr),
                             sizeof(addr))) < 0) {
      PLOG(ERROR) << "Failed to connect to vshd";
      return EXIT_FAILURE;
    }

    string user =
        FLAGS_user.empty() ? string("chronos") : std::move(FLAGS_user);
    client = VshClient::Create(std::move(sock_fd), std::move(stdout_fd),
                               std::move(stderr_fd), user,
                               FLAGS_target_container, FLAGS_cwd, interactive);
  }

  if (!client) {
    return EXIT_FAILURE;
  }

  base::ScopedFD ttyfd(
      HANDLE_EINTR(open(vm_tools::vsh::kDevTtyPath,
                        O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NONBLOCK)));

  // Set terminal to raw mode. Note that the client /must/ cleanly exit
  // the message loop below to restore termios settings.
  ScopedTermios termios(std::move(ttyfd));
  if (interactive && !termios.SetTermiosMode(ScopedTermios::TermiosMode::RAW)) {
    return EXIT_FAILURE;
  }

  message_loop.Run();

  // Clear session by setting container_shell_pid to 0.
  if (cicerone_proxy) {
    RegisterVshSession(cicerone_proxy, FLAGS_owner_id, FLAGS_vm_name,
                       FLAGS_target_container, pid, 0);
  }

  return client->exit_code();
}
