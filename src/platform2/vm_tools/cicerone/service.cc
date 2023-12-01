// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/cicerone/service.h"

#include <arpa/inet.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_path_watcher.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/no_destructor.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/synchronization/waitable_event.h>
#include <base/system/sys_info.h>
#include <base/task/single_thread_task_runner.h>
#include <base/uuid.h>
#include <brillo/timezone/tzif_parser.h>
#include <chromeos/constants/vm_tools.h>
#include <chromeos/dbus/service_constants.h>
#include <chunneld/proto_bindings/chunneld_service.pb.h>
#include <dbus/object_proxy.h>
#include <dbus/shadercached/dbus-constants.h>
#include <vm_protos/proto_bindings/container_host.pb.h>
#include <vm_tools/cicerone/shadercached_helper.h>

using std::string;

namespace vm_tools {
namespace cicerone {

namespace {

// Default name for a virtual machine.
constexpr char kDefaultVmName[] = "termina";

// Default name to use for a container.
constexpr char kDefaultContainerName[] = "penguin";

// Hostname for the default VM/container.
constexpr char kDefaultContainerHostname[] = "penguin.linux.test";

// file scheme.
constexpr char kUrlFileScheme[] = "file://";

// Delimiter for the end of a URL scheme.
constexpr char kUrlSchemeDelimiter[] = "://";

// Hostnames we replace with the container IP if they are sent over in URLs to
// be opened by the host.
const char* const kLocalhostReplaceNames[] = {"localhost", "127.0.0.1"};

// Path of system timezone file.
constexpr char kLocaltimePath[] = "/etc/localtime";

// TCP4 ports restricted from tunneling to the container.
const uint16_t kRestrictedPorts[] = {
    2222,  // cros-sftp service
    5355,  // Link-Local Multicast Name Resolution
};

// Path to the unix domain socket Concierge listens on for connections
// from Plugin VMs.
constexpr char kHostDomainSocket[] = "/run/vm_cicerone/client/host.sock";

// These rate limits ensure metrics can't be reported too frequently.
constexpr base::TimeDelta kMetricRateWindow = base::Seconds(60);
constexpr uint32_t kMetricRateLimit = 6;

// Passes |method_call| to |handler| and passes the response to
// |response_sender|. If |handler| returns NULL, an empty response is created
// and sent.
void HandleSynchronousDBusMethodCall(
    base::RepeatingCallback<std::unique_ptr<dbus::Response>(dbus::MethodCall*)>
        handler,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  std::unique_ptr<dbus::Response> response = handler.Run(method_call);
  if (!response)
    response = dbus::Response::FromMethodCall(method_call);
  std::move(response_sender).Run(std::move(response));
}

// Posted to a grpc thread to startup a listener service. Puts a copy of
// the pointer to the grpc server in |server_copy| and then signals |event|.
// It will listen on the address specified in |listener_address|.
void RunListenerService(grpc::Service* listener,
                        const std::vector<std::string>& listener_addresses,
                        base::WaitableEvent* event,
                        std::shared_ptr<grpc::Server>* server_copy) {
  // We are not interested in getting SIGCHLD or SIGTERM on this thread.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGTERM);
  sigprocmask(SIG_BLOCK, &mask, nullptr);

  // Build the grpc server.
  grpc::ServerBuilder builder;
  for (auto& addr : listener_addresses)
    builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
  builder.RegisterService(listener);

  std::shared_ptr<grpc::Server> server(builder.BuildAndStart().release());
  LOG(INFO) << "Server listening on "
            << base::JoinString(listener_addresses, ", ");

  *server_copy = server;
  event->Signal();

  if (server) {
    server->Wait();
  }
}

// Sets up a gRPC listener service by starting the |grpc_thread| and posting the
// main task to run for the thread. |listener_address| should be the address the
// gRPC server is listening on. A copy of the pointer to the server is put in
// |server_copy|. Returns true if setup & started successfully, false otherwise.
bool SetupListenerService(base::Thread* grpc_thread,
                          grpc::Service* listener_impl,
                          const std::vector<std::string>& listener_addresses,
                          std::shared_ptr<grpc::Server>* server_copy) {
  // Start the grpc thread.
  if (!grpc_thread->Start()) {
    LOG(ERROR) << "Failed to start grpc thread";
    return false;
  }

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool ret = grpc_thread->task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&RunListenerService, listener_impl,
                                listener_addresses, &event, server_copy));
  if (!ret) {
    LOG(ERROR) << "Failed to post server startup task to grpc thread";
    return false;
  }

  // Wait for the VM grpc server to start.
  event.Wait();

  if (!server_copy) {
    LOG(ERROR) << "grpc server failed to start";
    return false;
  }

  return true;
}

// Converts an IPv4 address to a string. The result will be stored in |str|
// on success.
bool IPv4AddressToString(const uint32_t address, std::string* str) {
  CHECK(str);

  char result[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, result, sizeof(result)) != result) {
    return false;
  }
  *str = std::string(result);
  return true;
}

// Translates the URL to be the equivalent value in the CrOS Host.
// * Replaces either localhost or 127.0.0.1 in the hostname part of a URL with
// the IP address of the container itself.
// * Replaces known file:// URLs such as file://$HOME =>
// file:///media/fuse/crostini_<owner_id>_<vm_name>_<container_name>.
std::string TranslateUrlForHost(const std::string& url,
                                const std::string& alt_host,
                                const std::string& owner_id,
                                const std::string& vm_name,
                                const Container& container) {
  // We don't have any URL parsing libraries at our disposal here without
  // integrating something new, so just do some basic URL parsing ourselves.
  // First find where the scheme ends, which'll be after the first :// string.
  // Then search for the next / char, which will start the path for the URL, the
  // hostname will be in the string between those two.
  // Also check for an @ symbol, which may have a user/pass before the hostname
  // and then check for a : at the end for an optional port.
  // scheme://[user:pass@]hostname[:port]/path
  auto front = url.find(kUrlSchemeDelimiter);
  if (front == std::string::npos) {
    return url;
  }
  front += sizeof(kUrlSchemeDelimiter) - 1;
  auto back = url.find('/', front);
  if (back == std::string::npos) {
    // This isn't invalid, such as http://google.com.
    back = url.length();
  }
  auto at_check = url.find('@', front);
  if (at_check != std::string::npos && at_check < back) {
    front = at_check + 1;
  }

  // HTTP and HTTPS are by default served on privileged ports (80 and 443).
  // If the port is manually specified, then parse it and check if it's
  // privileged or not.
  bool privileged_port = true;
  auto port_check = url.find(':', front);
  if (port_check != std::string::npos && port_check < back) {
    std::string port_substr = url.substr(port_check + 1, back - port_check - 1);
    int port = 0;
    if (base::StringToInt(port_substr, &port) && port > 1023) {
      privileged_port = false;
    }

    back = port_check;
  }

  // We don't care about URL validity, but our logic should ensure that front
  // is less than back at this point and this checks that.
  CHECK_LE(front, back);

  // Unprivileged ports are tunneled automatically by chunnel, so rewriting the
  // hostname is not necessary. Privileged ports are likely owned by system
  // daemons listening on all interfaces, so rewriting the hostname is the only
  // workable option.
  if (privileged_port) {
    std::string hostname = url.substr(front, back - front);
    for (const auto host_check : kLocalhostReplaceNames) {
      if (hostname == host_check) {
        // Replace the hostname with the alternate hostname which will be the
        // container's IP address.
        return url.substr(0, front) + alt_host + url.substr(back);
      }
    }
  }

  // Do replacements for file:// URLs.  Exit early if URL is not file scheme.
  if (!base::StartsWith(url, kUrlFileScheme,
                        base::CompareCase::INSENSITIVE_ASCII)) {
    return url;
  }
  std::pair<std::string, std::string> replacements[] = {
      {container.homedir(), "/media/fuse/crostini_" + owner_id + "_" + vm_name +
                                "_" + container.name()},
      {"/mnt/chromeos/MyFiles", "/home/chronos/u-" + owner_id + "/MyFiles"},
      {"/mnt/chromeos/GoogleDrive/MyDrive",
       container.drivefs_mount_path() + "/root"},
      {"/mnt/chromeos/GoogleDrive/SharedDrives",
       container.drivefs_mount_path() + "/team_drives"},
      {"/mnt/chromeos/GoogleDrive/Computers",
       container.drivefs_mount_path() + "/Computers"},
      {"/mnt/chromeos/GoogleDrive/SharedWithMe",
       container.drivefs_mount_path() + "/.files-by-id"},
      {"/mnt/chromeos/GoogleDrive/ShortcutsSharedWithMe",
       container.drivefs_mount_path() + "/.shortcut-targets-by-id"},
      {"/mnt/chromeos/PlayFiles", "/run/arc/sdcard/write/emulated/0"},
      {"/mnt/chromeos/removable", "/media/removable"},
      {"/mnt/chromeos/archive", "/media/archive"},
      {"/mnt/chromeos/SMB/", "/media/fuse/smbfs-"},
  };

  for (const auto& replacement : replacements) {
    auto back = sizeof(kUrlFileScheme) + replacement.first.length() - 1;
    // Match file://<replacement>, then url ends, or next char is '/'.
    if (replacement.first.length() > 0 &&
        base::StartsWith(url.substr(sizeof(kUrlFileScheme) - 1),
                         replacement.first, base::CompareCase::SENSITIVE) &&
        (url.length() == back || url[back] == '/' || url[back - 1] == '/')) {
      return url.substr(0, sizeof(kUrlFileScheme) - 1) + replacement.second +
             url.substr(back);
    }
  }

  return url;
}

void SetTimezoneForContainer(VirtualMachine* vm,
                             const std::string& container_name) {
  base::FilePath system_timezone;
  if (!base::NormalizeFilePath(base::FilePath(kLocaltimePath),
                               &system_timezone)) {
    LOG(ERROR) << "Getting system timezone failed";
    return;
  }

  auto posix_tz_result = brillo::timezone::GetPosixTimezone(system_timezone);
  LOG_IF(WARNING, !posix_tz_result.has_value())
      << "Reading POSIX TZ string failed for timezone file "
      << system_timezone.value();
  std::string posix_tz_string = posix_tz_result.value_or("");

  base::FilePath zoneinfo("/usr/share/zoneinfo");
  base::FilePath system_timezone_name;
  if (!zoneinfo.AppendRelativePath(system_timezone, &system_timezone_name)) {
    LOG(ERROR) << "Could not get name of timezone " << system_timezone.value();
    return;
  }

  std::string error;
  VirtualMachine::SetTimezoneResults results;
  if (!vm->SetTimezone(system_timezone_name.value(), posix_tz_string,
                       std::vector<std::string>({container_name}), &results,
                       &error)) {
    LOG(ERROR) << "Setting timezone failed for container " << container_name
               << " with error " << error;
    return;
  }

  int failure_count = results.failure_reasons.size();
  if (failure_count > 0) {
    LOG(ERROR) << "Setting timezone failed for container " << container_name;
    for (const std::string& error : results.failure_reasons) {
      LOG(ERROR) << "SetTimezone error: " << error;
    }
  }
}

std::optional<tremplin::StartContainerRequest_PrivilegeLevel>
ConvertPrivilegeLevelFromCiceroneToTremplin(
    StartLxdContainerRequest_PrivilegeLevel privilege_level) {
  switch (privilege_level) {
    case StartLxdContainerRequest_PrivilegeLevel_UNCHANGED:
      return tremplin::StartContainerRequest_PrivilegeLevel_UNCHANGED;
    case StartLxdContainerRequest_PrivilegeLevel_UNPRIVILEGED:
      return tremplin::StartContainerRequest_PrivilegeLevel_UNPRIVILEGED;
    case StartLxdContainerRequest_PrivilegeLevel_PRIVILEGED:
      return tremplin::StartContainerRequest_PrivilegeLevel_PRIVILEGED;
    default:
      LOG(ERROR) << "Bad privilege level value: " << privilege_level;
      return std::nullopt;
  }
}

class CiceroneGrpcCallbacks final : public grpc::Server::GlobalCallbacks {
 public:
  static void Register() {
    // GRPC wants to put this in a std::shared_ptr which will eventually get
    // reset during static destruction, so we need to allocate using new rather
    // then using base::NoDestructor.
    grpc::Server::SetGlobalCallbacks(new CiceroneGrpcCallbacks);
  }
  void PreSynchronousRequest(grpc::ServerContext* context) override {}
  void PostSynchronousRequest(grpc::ServerContext* context) override {}
  void AddPort(grpc::Server* server,
               const grpc::string& addr,
               grpc::ServerCredentials* creds,
               int port) override {
    if (addr == string("unix://") + kHostDomainSocket) {
      if (!SetPosixFilePermissions(base::FilePath(kHostDomainSocket), 0777)) {
        PLOG(WARNING) << "Failed to adjust permissions on host.sock";
      }
    }
  }

 private:
  friend class base::NoDestructor<CiceroneGrpcCallbacks>;

  CiceroneGrpcCallbacks() = default;
  CiceroneGrpcCallbacks(const CiceroneGrpcCallbacks&) = delete;
  CiceroneGrpcCallbacks& operator=(const CiceroneGrpcCallbacks&) = delete;
};

// Callback invoked after cicerone sends SelectFile request to chrome, and
// chrome shows the file select dialog and sends a FileSelectedSignal.
void OnFileSelected(std::vector<std::string>* result,
                    base::WaitableEvent* event,
                    std::vector<std::string> files) {
  std::copy(std::make_move_iterator(files.begin()),
            std::make_move_iterator(files.end()), std::back_inserter(*result));
  event->Signal();
}

}  // namespace

// Should Service create GuestMetric instance on initialization?  Used for
// testing.
bool Service::create_guest_metrics_ = true;

// Should Service start GRPC servers for ContainerListener and TremplinListener
// Used for testing
bool Service::run_grpc_ = true;

std::unique_ptr<Service> Service::Create(
    base::OnceClosure quit_closure,
    const std::optional<base::FilePath>& unix_socket_path_for_testing,
    scoped_refptr<dbus::Bus> bus) {
  auto service =
      base::WrapUnique(new Service(std::move(quit_closure), std::move(bus)));

  if (!service->Init(unix_socket_path_for_testing)) {
    service.reset();
  }

  return service;
}

Service::Service(base::OnceClosure quit_closure, scoped_refptr<dbus::Bus> bus)
    : bus_(std::move(bus)),
      quit_closure_(std::move(quit_closure)),
      weak_ptr_factory_(this) {
  container_listener_ =
      std::make_unique<ContainerListenerImpl>(weak_ptr_factory_.GetWeakPtr());
  tremplin_listener_ =
      std::make_unique<TremplinListenerImpl>(weak_ptr_factory_.GetWeakPtr());
  crash_listener_ =
      std::make_unique<CrashListenerImpl>(weak_ptr_factory_.GetWeakPtr());
}

Service::~Service() {
  if (grpc_server_container_ && run_grpc_) {
    grpc_server_container_->Shutdown();
  }

  if (grpc_server_tremplin_ && run_grpc_) {
    grpc_server_tremplin_->Shutdown();
  }

  if (grpc_server_crash_ && run_grpc_) {
    grpc_server_crash_->Shutdown();
  }
}

void Service::OnSignalReadable() {
  struct signalfd_siginfo siginfo;
  if (read(signal_fd_.get(), &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
    PLOG(ERROR) << "Failed to read from signalfd";
    return;
  }

  if (siginfo.ssi_signo == SIGCHLD) {
    HandleChildExit();
  } else if (siginfo.ssi_signo == SIGTERM) {
    HandleSigterm();
  } else {
    LOG(ERROR) << "Received unknown signal from signal fd: "
               << strsignal(siginfo.ssi_signo);
  }
}

void Service::OnDefaultNetworkServiceChanged() {
  for (auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    vm->HostNetworkChanged();
  }
}

void Service::ConnectTremplin(uint32_t cid,
                              bool* result,
                              base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  VirtualMachine* vm;
  std::string vm_name;
  std::string owner_id;
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }

  // Found the VM with a matching VM IP, so connect to the tremplin instance.
  if (!vm->ConnectTremplin()) {
    LOG(ERROR) << "Failed to connect to tremplin";
    event->Signal();
    return;
  }

  // Send the D-Bus signal out to indicate tremplin is ready.
  dbus::Signal signal(kVmCiceroneInterface, kTremplinStartedSignal);
  vm_tools::cicerone::TremplinStartedSignal proto;
  proto.set_vm_name(vm_name);
  proto.set_owner_id(owner_id);
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
  *result = true;
  event->Signal();
}

void Service::LxdContainerCreated(const uint32_t cid,
                                  std::string container_name,
                                  Service::CreateStatus status,
                                  std::string failure_reason,
                                  bool* result,
                                  base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  VirtualMachine* vm;
  std::string vm_name;
  std::string owner_id;
  if (container_name.empty()) {
    LOG(ERROR) << "container_name must be provided";
    event->Signal();
    return;
  }
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }

  dbus::Signal signal(kVmCiceroneInterface, kLxdContainerCreatedSignal);
  vm_tools::cicerone::LxdContainerCreatedSignal proto;
  proto.mutable_vm_name()->swap(vm_name);
  proto.set_container_name(container_name);
  proto.mutable_owner_id()->swap(owner_id);
  proto.set_failure_reason(failure_reason);
  switch (status) {
    case Service::CreateStatus::CREATED:
      proto.set_status(LxdContainerCreatedSignal::CREATED);
      break;
    case Service::CreateStatus::DOWNLOAD_TIMED_OUT:
      proto.set_status(LxdContainerCreatedSignal::DOWNLOAD_TIMED_OUT);
      break;
    case Service::CreateStatus::CANCELLED:
      proto.set_status(LxdContainerCreatedSignal::CANCELLED);
      break;
    case Service::CreateStatus::FAILED:
      proto.set_status(LxdContainerCreatedSignal::FAILED);
      break;
    default:
      proto.set_status(LxdContainerCreatedSignal::UNKNOWN);
      break;
  }
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
  *result = true;
  event->Signal();
}

void Service::LxdContainerDownloading(const uint32_t cid,
                                      std::string container_name,
                                      int download_progress,
                                      bool* result,
                                      base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  VirtualMachine* vm;
  std::string vm_name;
  std::string owner_id;
  if (container_name.empty()) {
    LOG(ERROR) << "container_name must be provided";
    event->Signal();
    return;
  }
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }

  dbus::Signal signal(kVmCiceroneInterface, kLxdContainerDownloadingSignal);
  vm_tools::cicerone::LxdContainerDownloadingSignal proto;
  proto.set_container_name(std::move(container_name));
  proto.set_vm_name(std::move(vm_name));
  proto.set_download_progress(std::move(download_progress));
  proto.set_owner_id(std::move(owner_id));
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
  *result = true;
  event->Signal();
}

void Service::LxdContainerDeleted(
    const uint32_t cid,
    std::string container_name,
    vm_tools::tremplin::ContainerDeletionProgress::Status status,
    std::string failure_reason,
    bool* result,
    base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  VirtualMachine* vm;
  std::string vm_name;
  std::string owner_id;
  if (container_name.empty()) {
    LOG(ERROR) << "container_name must be provided";
    event->Signal();
    return;
  }
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }

  dbus::Signal signal(kVmCiceroneInterface, kLxdContainerDeletedSignal);
  vm_tools::cicerone::LxdContainerDeletedSignal proto;
  proto.mutable_vm_name()->swap(vm_name);
  proto.set_container_name(container_name);
  proto.mutable_owner_id()->swap(owner_id);
  proto.set_failure_reason(failure_reason);
  switch (status) {
    case vm_tools::tremplin::ContainerDeletionProgress::DELETED:
      proto.set_status(LxdContainerDeletedSignal::DELETED);
      break;
    case vm_tools::tremplin::ContainerDeletionProgress::CANCELLED:
      proto.set_status(LxdContainerDeletedSignal::CANCELLED);
      break;
    case vm_tools::tremplin::ContainerDeletionProgress::FAILED:
      proto.set_status(LxdContainerDeletedSignal::FAILED);
      break;
    default:
      proto.set_status(LxdContainerDeletedSignal::UNKNOWN);
      break;
  }
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
  *result = true;
  event->Signal();
}

void Service::LxdContainerStarting(const uint32_t cid,
                                   std::string container_name,
                                   Service::StartStatus status,
                                   std::string failure_reason,
                                   bool* result,
                                   base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  VirtualMachine* vm;
  std::string vm_name;
  std::string owner_id;
  if (container_name.empty()) {
    LOG(ERROR) << "container_name must be provided";
    event->Signal();
    return;
  }
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }

  dbus::Signal signal(kVmCiceroneInterface, kLxdContainerStartingSignal);
  vm_tools::cicerone::LxdContainerStartingSignal proto;
  const OsRelease* os_release = vm->GetOsReleaseForContainer(container_name);
  if (os_release) {
    proto.mutable_os_release()->MergeFrom(*os_release);
  }
  proto.mutable_vm_name()->swap(vm_name);
  proto.set_container_name(container_name);
  proto.mutable_owner_id()->swap(owner_id);
  proto.set_failure_reason(failure_reason);
  switch (status) {
    case Service::StartStatus::STARTED:
      proto.set_status(LxdContainerStartingSignal::STARTED);
      break;
    case Service::StartStatus::CANCELLED:
      proto.set_status(LxdContainerStartingSignal::CANCELLED);
      break;
    case Service::StartStatus::FAILED:
      proto.set_status(LxdContainerStartingSignal::FAILED);
      break;
    case Service::StartStatus::STARTING:
      proto.set_status(LxdContainerStartingSignal::STARTING);
      break;
    default:
      proto.set_status(LxdContainerStartingSignal::UNKNOWN);
      break;
  }

  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
  *result = true;
  event->Signal();
}

void Service::LxdContainerStopping(const uint32_t cid,
                                   std::string container_name,
                                   Service::StopStatus status,
                                   std::string failure_reason,
                                   bool* result,
                                   base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  VirtualMachine* vm;
  std::string vm_name;
  std::string owner_id;
  if (container_name.empty()) {
    LOG(ERROR) << "container_name must be provided";
    event->Signal();
    return;
  }
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }

  dbus::Signal signal(kVmCiceroneInterface, kLxdContainerStoppingSignal);
  vm_tools::cicerone::LxdContainerStoppingSignal proto;

  proto.mutable_vm_name()->swap(vm_name);
  proto.set_container_name(container_name);
  proto.mutable_owner_id()->swap(owner_id);
  proto.set_failure_reason(failure_reason);
  switch (status) {
    case Service::StopStatus::STOPPED:
      proto.set_status(LxdContainerStoppingSignal::STOPPED);
      break;
    case Service::StopStatus::STOPPING:
      proto.set_status(LxdContainerStoppingSignal::STOPPING);
      break;
    case Service::StopStatus::CANCELLED:
      proto.set_status(LxdContainerStoppingSignal::CANCELLED);
      break;
    case Service::StopStatus::FAILED:
      proto.set_status(LxdContainerStoppingSignal::FAILED);
      break;
    default:
      proto.set_status(LxdContainerStoppingSignal::UNKNOWN);
      break;
  }

  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
  *result = true;
  event->Signal();
}

void Service::ContainerStartupCompleted(const std::string& container_token,
                                        const uint32_t cid,
                                        const uint32_t garcon_vsock_port,
                                        const uint32_t sftp_port,
                                        bool* result,
                                        base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  VirtualMachine* vm;
  std::string vm_name;
  std::string owner_id;
  if (!GetVirtualMachineForCidOrToken(cid, container_token, &vm, &owner_id,
                                      &vm_name)) {
    event->Signal();
    return;
  }

  Container* container = vm->GetPendingContainerForToken(container_token);
  if (!container) {
    // This could be a garcon restart.
    container = vm->GetContainerForToken(container_token);
    if (!container) {
      LOG(ERROR) << "Received ContainerStartupCompleted for unknown container";
      event->Signal();
      return;
    }
  }
  std::string string_ip;
  if (!vm->IsContainerless()) {
    VirtualMachine::LxdContainerInfo info;
    std::string error;
    VirtualMachine::GetLxdContainerInfoStatus status =
        vm->GetLxdContainerInfo(container->name(), &info, &error);
    if (status != VirtualMachine::GetLxdContainerInfoStatus::RUNNING) {
      LOG(ERROR) << "Failed to retrieve IPv4 address for container: " << error;
      event->Signal();
      return;
    }
    container->set_ipv4_address(info.ipv4_address);

    // Found the VM with a matching CID, register the IP address for the
    // container with that VM object.
    if (!IPv4AddressToString(info.ipv4_address, &string_ip)) {
      LOG(ERROR) << "Failed converting IP address to string: "
                 << info.ipv4_address;
      event->Signal();
      return;
    }
  }
  if (!vm->RegisterContainer(container_token, garcon_vsock_port, string_ip)) {
    LOG(ERROR) << "Invalid container token passed back from VM " << vm_name
               << " of " << container_token;
    event->Signal();
    return;
  }
  std::string container_name = vm->GetContainerNameForToken(container_token);
  LOG(INFO) << "Startup of container " << container_name << " at IP "
            << string_ip << " for VM " << vm_name << " completed.";

  std::string username;
  std::string homedir;
  if (owner_id == primary_owner_id_ && string_ip != "0.0.0.0") {
    // Register the IP address with the hostname resolver if it isn't 0.
    RegisterHostname(
        base::StringPrintf("%s.%s.linux.test", container_name.c_str(),
                           vm_name.c_str()),
        string_ip);
    if (vm_name == kDefaultVmName && container_name == kDefaultContainerName) {
      RegisterHostname(kDefaultContainerHostname, string_ip);

      std::string error_msg;
      if (vm->GetLxdContainerUsername(container_name, &username, &homedir,
                                      &error_msg) !=
          VirtualMachine::GetLxdContainerUsernameStatus::SUCCESS) {
        LOG(ERROR) << "Failed to get container " << container_name
                   << " username for SSH forwarding: " << error_msg;
      }
    }
  }
  container->set_homedir(homedir);

  SetTimezoneForContainer(vm, container_name);

  // Send the D-Bus signal out to indicate the container is ready.
  dbus::Signal signal(kVmCiceroneInterface, kContainerStartedSignal);
  vm_tools::cicerone::ContainerStartedSignal proto;
  proto.set_vm_name(vm_name);
  proto.set_container_name(container_name);
  proto.set_owner_id(owner_id);
  proto.set_container_username(username);
  proto.set_container_homedir(homedir);
  proto.set_ipv4_address(string_ip);
  proto.set_sftp_vsock_port(sftp_port);
  proto.set_container_token(container_token);
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
  *result = true;
  event->Signal();
}

void Service::ContainerShutdown(std::string container_name,
                                std::string container_token,
                                const uint32_t cid,
                                bool* result,
                                base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  VirtualMachine* vm;
  std::string owner_id;
  std::string vm_name;

  if (container_name.empty() && container_token.empty()) {
    LOG(ERROR) << "One of container_name or container_token must be provided";
    event->Signal();
    return;
  }
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }
  // Get container_name and container_token.
  if (container_name.empty()) {
    container_name = vm->GetContainerNameForToken(container_token);
  } else if (container_token.empty()) {
    Container* container = vm->GetContainerForName(container_name);
    if (!container) {
      LOG(ERROR) << "Container not found with name " << container_name;
      event->Signal();
      return;
    }
    container_token = container->token();
  }
  if (!vm->UnregisterContainer(container_token)) {
    LOG(ERROR) << "Invalid container token passed back from VM " << vm_name
               << " of " << container_token;
    event->Signal();
    return;
  }
  // Unregister this with the hostname resolver.
  UnregisterHostname(base::StringPrintf(
      "%s.%s.linux.test", container_name.c_str(), vm_name.c_str()));
  if (vm_name == kDefaultVmName && container_name == kDefaultContainerName) {
    UnregisterHostname(kDefaultContainerHostname);
    ssh_process_.Reset(0);
  }

  LOG(INFO) << "Shutdown of container " << container_name << " for VM "
            << vm_name;

  // Send the D-Bus signal out to indicate the container has shutdown.
  dbus::Signal signal(kVmCiceroneInterface, kContainerShutdownSignal);
  ContainerShutdownSignal proto;
  proto.set_vm_name(vm_name);
  proto.set_container_name(container_name);
  proto.set_owner_id(owner_id);
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  exported_object_->SendSignal(&signal);
  *result = true;
  event->Signal();
}

void Service::UpdateListeningPorts(
    std::map<std::string, std::vector<uint16_t>> listening_tcp4_ports,
    const uint32_t cid,
    bool* result,
    base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);

  *result = false;
  VirtualMachine* vm;
  std::string owner_id;
  std::string vm_name;

  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }

  for (auto pair : listening_tcp4_ports) {
    Container* c = vm->GetContainerForName(pair.first);
    if (c == nullptr) {
      // This is a container managed by LXD but not by cicerone.
      continue;
    }

    c->set_listening_tcp4_ports(pair.second);
  }

  SendListeningPorts();

  *result = true;
  event->Signal();
}

void Service::SendListeningPorts() {
  chunneld::UpdateListeningPortsRequest request;
  auto tcp4_forward_targets = request.mutable_tcp4_forward_targets();

  for (auto& vm_pair : vms_) {
    std::vector<std::string> container_names =
        vm_pair.second->GetContainerNames();

    for (auto container_name : container_names) {
      Container* c = vm_pair.second->GetContainerForName(container_name);
      std::vector<uint16_t> listening_ports = c->listening_tcp4_ports();
      for (uint16_t port : listening_ports) {
        bool is_restricted = false;
        for (uint16_t restricted_port : kRestrictedPorts) {
          if (port == restricted_port) {
            is_restricted = true;
            break;
          }
        }
        if (is_restricted)
          continue;

        chunneld::UpdateListeningPortsRequest_Tcp4ForwardTarget target;
        target.set_vm_name(vm_pair.first.second);
        target.set_container_name(container_name);
        target.set_owner_id(vm_pair.first.first);
        target.set_vsock_cid(vm_pair.second->cid());
        (*tcp4_forward_targets)[port] = target;
      }
    }
  }

  dbus::MethodCall method_call(chunneld::kChunneldInterface,
                               chunneld::kUpdateListeningPortsMethod);
  dbus::MessageWriter writer(&method_call);
  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode UpdateListeningPorts protobuf";
    return;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      chunneld_service_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    // If there's some issue with the chunneld service, don't make that
    // propagate to a higher level failure and just log it. We have logic for
    // setting this up again if that service restarts.
    LOG(WARNING) << "Failed to send dbus message to chunneld to update "
                 << "listening ports";
  }
}

void Service::ContainerExportProgress(
    const uint32_t cid,
    ExportLxdContainerProgressSignal* progress_signal,
    bool* result,
    base::WaitableEvent* event) {
  *result = SendSignal(kExportLxdContainerProgressSignal, cid, progress_signal);
  event->Signal();
}

void Service::ContainerImportProgress(
    const uint32_t cid,
    ImportLxdContainerProgressSignal* progress_signal,
    bool* result,
    base::WaitableEvent* event) {
  *result = SendSignal(kImportLxdContainerProgressSignal, cid, progress_signal);
  event->Signal();
}

void Service::ContainerUpgradeProgress(
    const uint32_t cid,
    UpgradeContainerProgressSignal* progress_signal,
    bool* result,
    base::WaitableEvent* event) {
  *result = SendSignal(kUpgradeContainerProgressSignal, cid, progress_signal);
  event->Signal();
}

void Service::StartLxdProgress(const uint32_t cid,
                               StartLxdProgressSignal* progress_signal,
                               bool* result,
                               base::WaitableEvent* event) {
  *result = SendSignal(kStartLxdProgressSignal, cid, progress_signal);
  event->Signal();
}

void Service::PendingUpdateApplicationListCalls(
    const std::string& container_token,
    const uint32_t cid,
    const uint32_t count,
    bool* result,
    base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;

  std::string owner_id;
  std::string vm_name;
  VirtualMachine* vm;
  if (!GetVirtualMachineForCidOrToken(cid, container_token, &vm, &owner_id,
                                      &vm_name)) {
    LOG(ERROR) << "Could not get virtual machine for cid " << cid;
    event->Signal();
    return;
  }
  std::string container_name = vm->GetContainerNameForToken(container_token);
  if (container_name.empty()) {
    LOG(ERROR) << "Could not get container";
    event->Signal();
    return;
  }

  PendingAppListUpdatesSignal msg;
  msg.set_vm_name(vm_name);
  msg.set_container_name(container_name);
  msg.set_count(count);

  // Send the D-Bus signal out updating progress/completion for the import.
  dbus::Signal signal(kVmCiceroneInterface, kPendingAppListUpdatesSignal);
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(msg);
  exported_object_->SendSignal(&signal);
  *result = true;
  event->Signal();
}

void Service::UpdateApplicationList(const std::string& container_token,
                                    const uint32_t cid,
                                    vm_tools::apps::ApplicationList* app_list,
                                    bool* result,
                                    base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(app_list);
  CHECK(result);
  CHECK(event);
  *result = false;
  std::string owner_id;
  std::string vm_name;
  VirtualMachine* vm;
  if (!GetVirtualMachineForCidOrToken(cid, container_token, &vm, &owner_id,
                                      &vm_name)) {
    LOG(ERROR) << "Could not get virtual machine for cid " << cid;
    event->Signal();
    return;
  }
  std::string container_name = vm->GetContainerNameForToken(container_token);
  if (container_name.empty()) {
    LOG(ERROR) << "Could not get container";
    event->Signal();
    return;
  }
  app_list->set_vm_name(vm_name);
  app_list->set_container_name(container_name);
  app_list->set_owner_id(owner_id);
  app_list->set_vm_type(vm->GetType());
  dbus::MethodCall method_call(
      vm_tools::apps::kVmApplicationsServiceInterface,
      vm_tools::apps::kVmApplicationsServiceUpdateApplicationListMethod);
  dbus::MessageWriter writer(&method_call);

  if (!writer.AppendProtoAsArrayOfBytes(*app_list)) {
    LOG(ERROR) << "Failed to encode ApplicationList protobuf";
    event->Signal();
    return;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      vm_applications_service_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to crostini app registry";
  } else {
    *result = true;
  }
  event->Signal();
}

void Service::OpenUrl(const std::string& container_token,
                      const std::string& url,
                      uint32_t cid,
                      bool* result,
                      base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;

  if (!base::IsStringUTF8(url)) {
    LOG(WARNING) << "Ignoring non-UTF8 URL";
    event->Signal();
    return;
  }

  dbus::MethodCall method_call(chromeos::kUrlHandlerServiceInterface,
                               chromeos::kUrlHandlerServiceOpenUrlMethod);
  dbus::MessageWriter writer(&method_call);

  // Validate that file:// URLs do not reference parent dir (..).
  if (base::StartsWith(url, kUrlFileScheme,
                       base::CompareCase::INSENSITIVE_ASCII) &&
      base::FilePath(url.substr(sizeof(kUrlFileScheme))).ReferencesParent()) {
    LOG(ERROR) << "Invalid file:// URL references parent";
    event->Signal();
    return;
  }
  std::string owner_id;
  std::string vm_name;
  VirtualMachine* vm;
  if (!GetVirtualMachineForCidOrToken(cid, container_token, &vm, &owner_id,
                                      &vm_name)) {
    LOG(ERROR) << "Requesting VM does not exist";
    event->Signal();
    return;
  }
  if (vm->GetType() == VirtualMachine::VmType::TERMINA) {
    Container* container = vm->GetContainerForToken(container_token);
    if (!container) {
      LOG(ERROR) << "No container found matching token: " << container_token;
      event->Signal();
      return;
    }
    std::string container_ip_str;
    if (!IPv4AddressToString(container->ipv4_address(), &container_ip_str)) {
      LOG(ERROR) << "Failed converting IP address to string: "
                 << container->ipv4_address();
      event->Signal();
      return;
    }
    if (container_ip_str == linuxhost_ip_) {
      container_ip_str = kDefaultContainerHostname;
    }
    writer.AppendString(TranslateUrlForHost(url, container_ip_str, owner_id,
                                            vm_name, *container));
  } else {
    writer.AppendString(url);
  }
  std::unique_ptr<dbus::Response> dbus_response =
      url_handler_service_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to Chrome for OpenUrl";
  } else {
    *result = true;
  }
  event->Signal();
}

void Service::SelectFile(const std::string& container_token,
                         const uint32_t cid,
                         vm_tools::apps::SelectFileRequest* select_file,
                         std::vector<std::string>* files,
                         base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(select_file);
  CHECK(files);
  CHECK(event);
  std::string owner_id;
  std::string vm_name;
  VirtualMachine* vm;
  if (!GetVirtualMachineForCidOrToken(cid, container_token, &vm, &owner_id,
                                      &vm_name)) {
    LOG(ERROR) << "Could not get virtual machine for cid " << cid;
    event->Signal();
    return;
  }
  std::string container_name = vm->GetContainerNameForToken(container_token);
  if (container_name.empty()) {
    LOG(ERROR) << "Could not get container";
    event->Signal();
    return;
  }
  select_file->set_vm_name(vm_name);
  select_file->set_container_name(container_name);
  select_file->set_owner_id(owner_id);
  std::string select_file_token =
      base::Uuid::GenerateRandomV4().AsLowercaseString();
  select_file->set_select_file_token(select_file_token);
  dbus::MethodCall method_call(
      vm_tools::apps::kVmApplicationsServiceInterface,
      vm_tools::apps::kVmApplicationsServiceSelectFileMethod);
  dbus::MessageWriter writer(&method_call);

  if (!writer.AppendProtoAsArrayOfBytes(*select_file)) {
    LOG(ERROR) << "Failed to encode SelectFile protobuf";
    event->Signal();
    return;
  }

  // |event| will be signalled when FileSelected() is called with a matching
  // |select_file_token|.
  select_file_dialogs_.emplace(select_file_token,
                               base::BindOnce(&OnFileSelected, files, event));

  std::unique_ptr<dbus::Response> dbus_response =
      vm_applications_service_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to Chrome for SelectFile";
    select_file_dialogs_.erase(select_file_token);
    event->Signal();
  }
}

void Service::InstallLinuxPackageProgress(
    const std::string& container_token,
    const uint32_t cid,
    InstallLinuxPackageProgressSignal* progress_signal,
    bool* result,
    base::WaitableEvent* event) {
  *result = SendSignal(kInstallLinuxPackageProgressSignal, container_token, cid,
                       progress_signal);
  event->Signal();
}

void Service::UninstallPackageProgress(
    const std::string& container_token,
    const uint32_t cid,
    UninstallPackageProgressSignal* progress_signal,
    bool* result,
    base::WaitableEvent* event) {
  *result = SendSignal(kUninstallPackageProgressSignal, container_token, cid,
                       progress_signal);
  event->Signal();
}

void Service::ApplyAnsiblePlaybookProgress(
    const std::string& container_token,
    const uint32_t cid,
    ApplyAnsiblePlaybookProgressSignal* progress_signal,
    bool* result,
    base::WaitableEvent* event) {
  *result = SendSignal(kApplyAnsiblePlaybookProgressSignal, container_token,
                       cid, progress_signal);
  event->Signal();
}

void Service::OpenTerminal(const std::string& container_token,
                           vm_tools::apps::TerminalParams terminal_params,
                           uint32_t cid,
                           bool* result,
                           base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  std::string owner_id;
  std::string vm_name;
  VirtualMachine* vm;
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }
  std::string container_name = vm->GetContainerNameForToken(container_token);
  if (container_name.empty()) {
    event->Signal();
    return;
  }
  terminal_params.set_vm_name(vm_name);
  terminal_params.set_container_name(container_name);
  terminal_params.set_owner_id(owner_id);
  dbus::MethodCall method_call(
      vm_tools::apps::kVmApplicationsServiceInterface,
      vm_tools::apps::kVmApplicationsServiceLaunchTerminalMethod);
  dbus::MessageWriter(&method_call)
      .AppendProtoAsArrayOfBytes(std::move(terminal_params));
  std::unique_ptr<dbus::Response> dbus_response =
      vm_applications_service_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to Chrome for OpenTerminal";
  } else {
    *result = true;
  }
  event->Signal();
}

void Service::ForwardSecurityKeyMessage(
    const uint32_t cid,
    vm_tools::sk_forwarding::ForwardSecurityKeyMessageRequest
        security_key_message,
    vm_tools::sk_forwarding::ForwardSecurityKeyMessageResponse*
        security_key_response,
    base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(security_key_response);
  CHECK(event);
  security_key_response->Clear();
  std::string owner_id;
  std::string vm_name;
  VirtualMachine* vm;
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    LOG(ERROR) << "Failed to get VirtualMachine for cid: " << cid;
    event->Signal();
    return;
  }

  security_key_message.set_vm_name(vm_name);
  security_key_message.set_owner_id(owner_id);
  dbus::MethodCall method_call(
      vm_tools::sk_forwarding::kVmSKForwardingServiceInterface,
      vm_tools::sk_forwarding::
          kVmSKForwardingServiceForwardSecurityKeyMessageMethod);
  dbus::MessageWriter(&method_call)
      .AppendProtoAsArrayOfBytes(std::move(security_key_message));
  std::unique_ptr<dbus::Response> dbus_response =
      vm_sk_forwarding_service_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to Chrome for "
               << "ForwardSecurityKeyMessage";
    event->Signal();
    return;
  }

  dbus::MessageReader reader(dbus_response.get());
  if (!reader.PopArrayOfBytesAsProto(security_key_response)) {
    LOG(ERROR) << "Failed to parse dbus message response for "
               << "ForwardSecurityKeyMessage";
    security_key_response->Clear();
  }

  event->Signal();
}

void Service::UpdateMimeTypes(const std::string& container_token,
                              vm_tools::apps::MimeTypes mime_types,
                              const uint32_t cid,
                              bool* result,
                              base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(result);
  CHECK(event);
  *result = false;
  std::string owner_id;
  std::string vm_name;
  VirtualMachine* vm;
  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    event->Signal();
    return;
  }
  std::string container_name = vm->GetContainerNameForToken(container_token);
  if (container_name.empty()) {
    event->Signal();
    return;
  }
  mime_types.set_vm_name(vm_name);
  mime_types.set_container_name(container_name);
  mime_types.set_owner_id(owner_id);
  dbus::MethodCall method_call(
      vm_tools::apps::kVmApplicationsServiceInterface,
      vm_tools::apps::kVmApplicationsServiceUpdateMimeTypesMethod);
  dbus::MessageWriter(&method_call)
      .AppendProtoAsArrayOfBytes(std::move(mime_types));
  std::unique_ptr<dbus::Response> dbus_response =
      vm_applications_service_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to Chrome for UpdateMimeTypes";
  } else {
    *result = true;
  }
  event->Signal();
}

void Service::GetDiskInfo(
    const std::string& container_token,
    const uint32_t cid,
    vm_tools::disk_management::GetDiskInfoResponse* result,
    base::WaitableEvent* event) {
  vm_tools::disk_management::GetDiskInfoRequest get_disk_info_request;
  SendDiskMethod(
      vm_tools::disk_management::kVmDiskManagementServiceGetDiskInfoMethod,
      container_token, cid, &get_disk_info_request, result);
  event->Signal();
}

void Service::RequestSpace(
    const std::string& container_token,
    const uint32_t cid,
    const uint64_t space_requested,
    vm_tools::disk_management::RequestSpaceResponse* result,
    base::WaitableEvent* event) {
  vm_tools::disk_management::RequestSpaceRequest request_space_request;
  request_space_request.set_space_requested(space_requested);
  SendDiskMethod(
      vm_tools::disk_management::kVmDiskManagementServiceRequestSpaceMethod,
      container_token, cid, &request_space_request, result);
  event->Signal();
}

void Service::ReleaseSpace(
    const std::string& container_token,
    const uint32_t cid,
    const uint64_t space_to_release,
    vm_tools::disk_management::ReleaseSpaceResponse* result,
    base::WaitableEvent* event) {
  vm_tools::disk_management::ReleaseSpaceRequest release_space_request;
  release_space_request.set_space_to_release(space_to_release);
  SendDiskMethod(
      vm_tools::disk_management::kVmDiskManagementServiceReleaseSpaceMethod,
      container_token, cid, &release_space_request, result);
  event->Signal();
}

void Service::ReportMetrics(
    const std::string& container_token,
    const uint32_t cid,
    const vm_tools::container::ReportMetricsRequest& request,
    vm_tools::container::ReportMetricsResponse* response,
    base::WaitableEvent* event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(response);
  CHECK(event);
  VirtualMachine* vm;
  std::string owner_id;
  std::string vm_name;

  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    LOG(ERROR) << "Failed to get VirtualMachine for cid: " << cid;
    response->set_error(1);
    event->Signal();
    return;
  }

  std::string container_name = vm->GetContainerNameForToken(container_token);
  if (container_name.empty()) {
    LOG(ERROR) << "Could not get container name for token";
    response->set_error(1);
    event->Signal();
    return;
  }

  // Check on rate limiting for the VM before processing any further.
  if (!CheckReportMetricsRateLimit(vm_name)) {
    LOG(ERROR) << "ReportMetrics rate limit exceeded, blocking request";
    response->set_error(1);
    event->Signal();
    return;
  }

  for (const auto& metric : request.metric()) {
    if (!guest_metrics_->HandleMetric(owner_id, vm_name, container_name,
                                      metric.name(), metric.value())) {
      LOG(ERROR) << "Error handling metric " << metric.name() << " for VM "
                 << vm_name << " container " << container_name;
      response->set_error(1);
      break;
    }
  }

  event->Signal();
}

void Service::InstallVmShaderCache(
    const uint32_t cid,
    const vm_tools::container::InstallShaderCacheRequest* request,
    std::string* error_out,
    base::WaitableEvent* event) {
  VirtualMachine* vm;
  std::string owner_id;
  std::string vm_name;

  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    *error_out =
        base::StringPrintf("Could not get virtual machine for cid %du", cid);
    event->Signal();
    return;
  }

  if (!vm->GetContainerForToken(request->token())) {
    *error_out = "Invalid container token: " + request->token();
    event->Signal();
    return;
  }

  if (vm->GetType() != VirtualMachine::VmType::BOREALIS) {
    *error_out = "Only Borealis VM supported";
    event->Signal();
    return;
  }

  shadercached_helper_->InstallShaderCache(
      owner_id, vm_name, request, error_out, event, shadercached_proxy_);
}

void Service::UninstallVmShaderCache(
    const uint32_t cid,
    const vm_tools::container::UninstallShaderCacheRequest* request,
    std::string* error_out,
    base::WaitableEvent* event) {
  VirtualMachine* vm;
  std::string owner_id;
  std::string vm_name;

  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    *error_out =
        base::StringPrintf("Could not get virtual machine for cid %du", cid);
    event->Signal();
    return;
  }

  if (!vm->GetContainerForToken(request->token())) {
    *error_out = "Invalid container token: " + request->token();
    event->Signal();
    return;
  }

  if (vm->GetType() != VirtualMachine::VmType::BOREALIS) {
    *error_out = "Only Borealis VM supported";
    event->Signal();
    return;
  }

  shadercached_helper_->UninstallShaderCache(
      owner_id, vm_name, request, error_out, event, shadercached_proxy_);
}

void Service::UnmountVmShaderCache(
    const uint32_t cid,
    const vm_tools::container::UnmountShaderCacheRequest* request,
    std::string* error_out,
    base::WaitableEvent* event) {
  VirtualMachine* vm;
  std::string owner_id;
  std::string vm_name;

  if (!GetVirtualMachineForCidOrToken(cid, "", &vm, &owner_id, &vm_name)) {
    *error_out =
        base::StringPrintf("Could not get virtual machine for cid %du", cid);
    event->Signal();
    return;
  }

  if (!vm->GetContainerForToken(request->token())) {
    *error_out = "Invalid container token: " + request->token();
    event->Signal();
    return;
  }

  if (vm->GetType() != VirtualMachine::VmType::BOREALIS) {
    *error_out = "Only Borealis VM supported";
    event->Signal();
    return;
  }

  shadercached_helper_->UnmountShaderCache(
      owner_id, vm_name, request, error_out, event, shadercached_proxy_);
}

void Service::InhibitScreensaver(const std::string& container_token,
                                 const uint32_t cid,
                                 InhibitScreensaverSignal* signal,
                                 bool* result,
                                 base::WaitableEvent* event) {
  *result = SendSignal(kInhibitScreensaverSignal, container_token, cid, signal);
  event->Signal();
}

void Service::UninhibitScreensaver(const std::string& container_token,
                                   const uint32_t cid,
                                   UninhibitScreensaverSignal* signal,
                                   bool* result,
                                   base::WaitableEvent* event) {
  *result =
      SendSignal(kUninhibitScreensaverSignal, container_token, cid, signal);
  event->Signal();
}

bool Service::CheckReportMetricsRateLimit(const std::string& vm_name) {
  RateLimitState& state = metric_rate_limit_state_[vm_name];
  base::TimeTicks now = base::TimeTicks::Now();
  if (now - state.window_start > kMetricRateWindow) {
    // Beyond the window, reset the window start time and counter.
    state.window_start = now;
    state.count = 1;
    return true;
  }
  if (++state.count <= kMetricRateLimit)
    return true;
  // Only log the first one over the limit to prevent log spam if this is
  // getting hit quickly.
  LOG_IF(ERROR, state.count == kMetricRateLimit + 1)
      << "ReportMetrics rate limit hit, blocking requests until window "
         "closes";
  return false;
}

bool Service::Init(
    const std::optional<base::FilePath>& unix_socket_path_for_testing) {
  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
    return false;
  }

  exported_object_ =
      bus_->GetExportedObject(dbus::ObjectPath(kVmCiceroneServicePath));
  if (!exported_object_) {
    LOG(ERROR) << "Failed to export " << kVmCiceroneServicePath << " object";
    return false;
  }

  using ServiceMethod =
      std::unique_ptr<dbus::Response> (Service::*)(dbus::MethodCall*);
  const std::map<const char*, ServiceMethod> kServiceMethods = {
      {kNotifyVmStartedMethod, &Service::NotifyVmStarted},
      {kNotifyVmStoppingMethod, &Service::NotifyVmStopping},
      {kNotifyVmStoppedMethod, &Service::NotifyVmStopped},
      {kGetContainerTokenMethod, &Service::GetContainerToken},
      {kLaunchContainerApplicationMethod, &Service::LaunchContainerApplication},
      {kGetContainerAppIconMethod, &Service::GetContainerAppIcon},
      {kLaunchVshdMethod, &Service::LaunchVshd},
      {kGetLinuxPackageInfoMethod, &Service::GetLinuxPackageInfo},
      {kInstallLinuxPackageMethod, &Service::InstallLinuxPackage},
      {kUninstallPackageOwningFileMethod, &Service::UninstallPackageOwningFile},
      {kCreateLxdContainerMethod, &Service::CreateLxdContainer},
      {kDeleteLxdContainerMethod, &Service::DeleteLxdContainer},
      {kStartLxdContainerMethod, &Service::StartLxdContainer},
      {kStopLxdContainerMethod, &Service::StopLxdContainer},
      {kSetTimezoneMethod, &Service::SetTimezone},
      {kGetLxdContainerUsernameMethod, &Service::GetLxdContainerUsername},
      {kSetUpLxdContainerUserMethod, &Service::SetUpLxdContainerUser},
      {kExportLxdContainerMethod, &Service::ExportLxdContainer},
      {kImportLxdContainerMethod, &Service::ImportLxdContainer},
      {kCancelExportLxdContainerMethod, &Service::CancelExportLxdContainer},
      {kCancelImportLxdContainerMethod, &Service::CancelImportLxdContainer},
      {kConnectChunnelMethod, &Service::ConnectChunnel},
      {kGetDebugInformationMethod, &Service::GetDebugInformation},
      {kApplyAnsiblePlaybookMethod, &Service::ApplyAnsiblePlaybook},
      {kConfigureForArcSideloadMethod, &Service::ConfigureForArcSideload},
      {kUpgradeContainerMethod, &Service::UpgradeContainer},
      {kCancelUpgradeContainerMethod, &Service::CancelUpgradeContainer},
      {kStartLxdMethod, &Service::StartLxd},
      {kAddFileWatchMethod, &Service::AddFileWatch},
      {kRemoveFileWatchMethod, &Service::RemoveFileWatch},
      {kRegisterVshSessionMethod, &Service::RegisterVshSession},
      {kGetVshSessionMethod, &Service::GetVshSession},
      {kFileSelectedMethod, &Service::FileSelected},
      {kAttachUsbToContainerMethod, &Service::AttachUsbToContainer},
      {kDetachUsbFromContainerMethod, &Service::DetachUsbFromContainer},
      {kListRunningContainersMethod, &Service::ListRunningContainers},
      {kGetGarconSessionInfoMethod, &Service::GetGarconSessionInfo},
      {kUpdateContainerDevicesMethod, &Service::UpdateContainerDevices},
  };

  for (const auto& iter : kServiceMethods) {
    bool ret = exported_object_->ExportMethodAndBlock(
        kVmCiceroneInterface, iter.first,
        base::BindRepeating(
            &HandleSynchronousDBusMethodCall,
            base::BindRepeating(iter.second, base::Unretained(this))));
    if (!ret) {
      LOG(ERROR) << "Failed to export method " << iter.first;
      return false;
    }
  }

  if (!bus_->RequestOwnershipAndBlock(kVmCiceroneServiceName,
                                      dbus::Bus::REQUIRE_PRIMARY)) {
    LOG(ERROR) << "Failed to take ownership of " << kVmCiceroneServiceName;
    return false;
  }

  // Set up the D-Bus client for shill.
  shill_client_ = std::make_unique<ShillClient>(bus_);
  shill_client_->RegisterDefaultServiceChangedHandler(
      base::BindRepeating(&Service::OnDefaultNetworkServiceChanged,
                          weak_ptr_factory_.GetWeakPtr()));

  // Get the D-Bus proxy for communicating with the crostini registry in Chrome
  // and for the URL handler service.
  vm_applications_service_proxy_ = bus_->GetObjectProxy(
      vm_tools::apps::kVmApplicationsServiceName,
      dbus::ObjectPath(vm_tools::apps::kVmApplicationsServicePath));
  if (!vm_applications_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::apps::kVmApplicationsServiceName;
    return false;
  }
  url_handler_service_proxy_ =
      bus_->GetObjectProxy(chromeos::kUrlHandlerServiceName,
                           dbus::ObjectPath(chromeos::kUrlHandlerServicePath));
  if (!url_handler_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << chromeos::kUrlHandlerServiceName;
    return false;
  }
  chunneld_service_proxy_ = bus_->GetObjectProxy(
      vm_tools::chunneld::kChunneldServiceName,
      dbus::ObjectPath(vm_tools::chunneld::kChunneldServicePath));
  if (!chunneld_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::chunneld::kChunneldServiceName;
    return false;
  }
  crosdns_service_proxy_ =
      bus_->GetObjectProxy(crosdns::kCrosDnsServiceName,
                           dbus::ObjectPath(crosdns::kCrosDnsServicePath));
  if (!crosdns_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << crosdns::kCrosDnsServiceName;
    return false;
  }
  crosdns_service_proxy_->WaitForServiceToBeAvailable(base::BindOnce(
      &Service::OnCrosDnsServiceAvailable, weak_ptr_factory_.GetWeakPtr()));

  concierge_service_proxy_ = bus_->GetObjectProxy(
      vm_tools::concierge::kVmConciergeServiceName,
      dbus::ObjectPath(vm_tools::concierge::kVmConciergeServicePath));
  if (!concierge_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::concierge::kVmConciergeServiceName;
    return false;
  }
  vm_sk_forwarding_service_proxy_ = bus_->GetObjectProxy(
      vm_tools::sk_forwarding::kVmSKForwardingServiceName,
      dbus::ObjectPath(vm_tools::sk_forwarding::kVmSKForwardingServicePath));
  if (!vm_sk_forwarding_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::sk_forwarding::kVmSKForwardingServiceName;
    return false;
  }
  shadercached_proxy_ = bus_->GetObjectProxy(
      shadercached::kShaderCacheServiceName,
      dbus::ObjectPath(shadercached::kShaderCacheServicePath));
  if (!shadercached_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << shadercached::kShaderCacheServiceName;
    return false;
  }
  shadercached_helper_ =
      std::make_unique<ShadercachedHelper>(shadercached_proxy_);

  vm_disk_management_service_proxy_ = bus_->GetObjectProxy(
      vm_tools::disk_management::kVmDiskManagementServiceName,
      dbus::ObjectPath(
          vm_tools::disk_management::kVmDiskManagementServicePath));
  if (!vm_disk_management_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::disk_management::kVmDiskManagementServiceName;
    return false;
  }

  std::vector<std::string> container_listener_addresses = {
      base::StringPrintf("vsock:%u:%u", VMADDR_CID_ANY, vm_tools::kGarconPort),
      base::StringPrintf("unix://%s", kHostDomainSocket)};
  std::vector<std::string> tremplin_listener_address = {base::StringPrintf(
      "vsock:%u:%u", VMADDR_CID_ANY, vm_tools::kTremplinListenerPort)};
  std::vector<std::string> crash_listener_address = {base::StringPrintf(
      "vsock:%u:%u", VMADDR_CID_ANY, vm_tools::kCrashListenerPort)};

  if (unix_socket_path_for_testing.has_value()) {
    container_listener_addresses = {
        "unix:" + unix_socket_path_for_testing.value()
                      .Append(base::NumberToString(vm_tools::kGarconPort))
                      .value()};
    tremplin_listener_address = {
        "unix:" +
        unix_socket_path_for_testing.value()
            .Append(base::NumberToString(vm_tools::kTremplinListenerPort))
            .value()};
    crash_listener_address = {"unix:" + unix_socket_path_for_testing.value()
                                            .Append(base::NumberToString(
                                                vm_tools::kCrashListenerPort))
                                            .value()};
  }

  if (run_grpc_) {
    // Install our own callbacks to catch "AddPort" action and update
    // permissions on unix domain sockets.
    CiceroneGrpcCallbacks::Register();

    // Setup & start the gRPC listener services.
    if (!SetupListenerService(
            &grpc_thread_container_, container_listener_.get(),
            container_listener_addresses, &grpc_server_container_)) {
      LOG(ERROR) << "Failed to setup/startup the container grpc server";
      return false;
    }

    if (!SetupListenerService(&grpc_thread_tremplin_, tremplin_listener_.get(),
                              tremplin_listener_address,
                              &grpc_server_tremplin_)) {
      LOG(ERROR) << "Failed to setup/startup the tremplin grpc server";
      return false;
    }

    if (!SetupListenerService(&grpc_thread_crash_, crash_listener_.get(),
                              crash_listener_address, &grpc_server_crash_)) {
      LOG(ERROR) << "Failed to setup/startup the crash reporting grpc server";
      return false;
    }

    LOG(INFO) << "Started tremplin grpc server";
  }

  // Set up the signalfd for receiving SIGCHLD and SIGTERM.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGTERM);

  signal_fd_.reset(signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
  if (!signal_fd_.is_valid()) {
    PLOG(ERROR) << "Failed to create signalfd";
    return false;
  }

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      signal_fd_.get(),
      base::BindRepeating(&Service::OnSignalReadable, base::Unretained(this)));
  if (!watcher_) {
    LOG(ERROR) << "Failed to watch signalfd";
    return false;
  }

  // Now block signals from the normal signal handling path so that we will get
  // them via the signalfd.
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
    PLOG(ERROR) << "Failed to block signals via sigprocmask";
    return false;
  }

  // Setup file path watcher to monitor for changes to kLocaltimePath. If the
  // file at kLocaltimePath is a symlink, the callback will be called when the
  // target of that symlink changes.
  localtime_watcher_.Watch(base::FilePath(kLocaltimePath),
                           base::FilePathWatcher::Type::kNonRecursive,
                           base::BindRepeating(&Service::OnLocaltimeFileChanged,
                                               weak_ptr_factory_.GetWeakPtr()));

  if (create_guest_metrics_) {
    // Setup metric accumulator for Borealis swap and disk IO.
    guest_metrics_ = std::make_unique<GuestMetrics>(bus_);
  }

  return true;
}

void Service::HandleChildExit() {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  // We can't just rely on the information in the siginfo structure because
  // more than one child may have exited but only one SIGCHLD will be
  // generated.
  while (true) {
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if (pid <= 0) {
      if (pid == -1 && errno != ECHILD) {
        PLOG(ERROR) << "Unable to reap child processes";
      }
      break;
    }

    if (WIFEXITED(status)) {
      LOG(INFO) << " Process " << pid << " exited with status "
                << WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      LOG(INFO) << " Process " << pid << " killed by signal "
                << WTERMSIG(status)
                << (WCOREDUMP(status) ? " (core dumped)" : "");
    } else {
      LOG(WARNING) << "Unknown exit status " << status << " for process "
                   << pid;
    }

    ssh_process_.Release();
    ssh_process_.Reset(0);
  }
}
void Service::HandleSigterm() {
  LOG(INFO) << "Shutting down due to SIGTERM";

  if (quit_closure_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(quit_closure_));
  }
}

std::unique_ptr<dbus::Response> Service::NotifyVmStarted(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received NotifyVmStarted request";

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  NotifyVmStartedRequest request;
  EmptyMessage response;
  writer.AppendProtoAsArrayOfBytes(response);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse NotifyVmStartedRequest from message";
    return dbus_response;
  }

  vms_[std::make_pair(request.owner_id(), std::move(request.vm_name()))] =
      std::make_unique<VirtualMachine>(request.cid(), request.pid(),
                                       std::move(request.vm_token()));
  // Only take this as the primary owner ID if this is not a plugin VM.
  if (request.cid() != 0 && (primary_owner_id_.empty() || vms_.empty())) {
    primary_owner_id_ = request.owner_id();
  }
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::NotifyVmStopping(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received NotifyVmStopping request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  NotifyVmStoppingRequest request;
  EmptyMessage response;
  writer.AppendProtoAsArrayOfBytes(response);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse NotifyVmStoppingRequest from message";
    return dbus_response;
  }

  VmKey vm_key =
      std::make_pair(std::move(request.owner_id()), request.vm_name());
  auto iter = vms_.find(vm_key);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist: " << request.vm_name();
    return dbus_response;
  }

  iter->second->notify_shutdown();

  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::NotifyVmStopped(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received NotifyVmStopped request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  NotifyVmStoppedRequest request;
  EmptyMessage response;
  writer.AppendProtoAsArrayOfBytes(response);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse NotifyVmStoppedRequest from message";
    return dbus_response;
  }

  VmKey vm_key =
      std::make_pair(std::move(request.owner_id()), request.vm_name());
  auto iter = vms_.find(vm_key);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist: " << request.vm_name();
    return dbus_response;
  }

  UnregisterVmContainers(iter->second.get(), iter->first.first,
                         iter->first.second);

  vms_.erase(iter);
  return dbus_response;
}

bool Service::SetTremplinStubOfVmForTesting(
    const std::string& owner_id,
    const std::string& vm_name,
    std::unique_ptr<vm_tools::tremplin::Tremplin::StubInterface>
        mock_tremplin_stub) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  VirtualMachine* vm = FindVm(owner_id, vm_name);
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << owner_id << ", " << vm_name;
    return false;
  }

  vm->SetTremplinStubForTesting(std::move(mock_tremplin_stub));
  return true;
}

bool Service::CreateContainerWithTokenForTesting(
    const std::string& owner_id,
    const std::string& vm_name,
    const std::string& container_name,
    const std::string& container_token) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  VirtualMachine* vm = FindVm(owner_id, vm_name);
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << owner_id << ", " << vm_name;
    return false;
  }

  vm->CreateContainerWithTokenForTesting(container_name, container_token);
  return true;
}

void Service::DisableGrpcForTesting() {
  run_grpc_ = false;
}

std::unique_ptr<dbus::Response> Service::GetContainerToken(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetContainerToken request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ContainerTokenRequest request;
  ContainerTokenResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ContainerTokenRequest from message";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  response.set_container_token(
      vm->GenerateContainerToken(std::move(request.container_name())));
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::LaunchContainerApplication(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received LaunchContainerApplication request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  LaunchContainerApplicationRequest request;
  LaunchContainerApplicationResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse LaunchContainerApplicationRequest from "
               << "message";
    response.set_success(false);
    response.set_failure_reason(
        "Unable to parse LaunchContainerApplicationRequest");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_success(false);
    response.set_failure_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  Container* container = vm->GetContainerForName(container_name);
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: " << container_name;
    response.set_success(false);
    response.set_failure_reason("Requested container does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.desktop_file_id().empty()) {
    LOG(ERROR) << "LaunchContainerApplicationRequest had an empty "
               << "desktop_file_id";
    response.set_success(false);
    response.set_failure_reason("Empty desktop_file_id in request");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  vm_tools::container::LaunchApplicationRequest::DisplayScaling display_scaling;
  if (request.display_scaling() ==
      vm_tools::cicerone::LaunchContainerApplicationRequest::UNSCALED) {
    display_scaling = vm_tools::container::LaunchApplicationRequest::UNSCALED;
  } else {
    display_scaling = vm_tools::container::LaunchApplicationRequest::SCALED;
  }

  std::vector<vm_tools::container::ContainerFeature> container_features;
  for (int feature : request.container_features()) {
    container_features.emplace_back(
        static_cast<vm_tools::container::ContainerFeature>(feature));
  }

  std::string error_msg;
  response.set_success(container->LaunchContainerApplication(
      request.desktop_file_id(),
      std::vector<string>(
          std::make_move_iterator(request.mutable_files()->begin()),
          std::make_move_iterator(request.mutable_files()->end())),
      display_scaling, std::move(container_features), &error_msg));
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

namespace {
DesktopIcon::Format ConvertFormat(
    vm_tools::container::DesktopIcon::Format format) {
  switch (format) {
    case container::DesktopIcon::SVG:
      return DesktopIcon::SVG;

    default:
      return DesktopIcon::PNG;
  }
}
}  // namespace

std::unique_ptr<dbus::Response> Service::GetContainerAppIcon(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetContainerAppIcon request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ContainerAppIconRequest request;
  ContainerAppIconResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ContainerAppIconRequest from message";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  Container* container = vm->GetContainerForName(container_name);
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: " << container_name;
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.desktop_file_ids().size() == 0) {
    LOG(ERROR) << "ContainerAppIconRequest had an empty desktop_file_ids";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::vector<std::string> desktop_file_ids;
  for (std::string& id : *request.mutable_desktop_file_ids()) {
    desktop_file_ids.emplace_back(std::move(id));
  }

  std::vector<Container::Icon> icons;
  icons.reserve(desktop_file_ids.size());

  if (!container->GetContainerAppIcon(std::move(desktop_file_ids),
                                      request.size(), request.scale(),
                                      &icons)) {
    LOG(ERROR) << "GetContainerAppIcon failed";
  }

  for (auto& container_icon : icons) {
    auto* icon = response.add_icons();
    *icon->mutable_desktop_file_id() =
        std::move(container_icon.desktop_file_id);
    *icon->mutable_icon() = std::move(container_icon.content);
    icon->set_format(ConvertFormat(container_icon.format));
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::LaunchVshd(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received LaunchVshd request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  LaunchVshdRequest request;
  LaunchVshdResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse LaunchVshdRequest from message";
    response.set_failure_reason(
        "unable to parse LaunchVshdRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  if (request.port() == 0) {
    LOG(ERROR) << "Port is not set in LaunchVshdRequest";
    response.set_failure_reason("port is not set in LaunchVshdRequest");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // TODO(jkardatzke): Remove the empty string check once Chrome is updated
  // to put the owner_id in this request.
  std::string owner_id = request.owner_id().empty()
                             ? primary_owner_id_
                             : std::move(request.owner_id());
  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist: " << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  Container* container = vm->GetContainerForName(container_name);
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: " << container_name;
    response.set_failure_reason(base::StringPrintf(
        "requested container does not exist: %s", container_name.c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::vector<vm_tools::container::ContainerFeature> container_features;
  for (int feature : request.container_features()) {
    container_features.emplace_back(
        static_cast<vm_tools::container::ContainerFeature>(feature));
  }

  std::string error_msg;
  container->LaunchVshd(request.port(), std::move(container_features),
                        &error_msg);

  response.set_success(true);
  response.set_failure_reason(error_msg);
  response.set_cid(vm->cid());
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::GetLinuxPackageInfo(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetLinuxPackageInfo request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  LinuxPackageInfoRequest request;
  LinuxPackageInfoResponse response;
  response.set_success(false);
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse LinuxPackageInfoRequest from message";
    response.set_failure_reason("Unable to parse request protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  if (request.file_path().empty() && request.package_name().empty()) {
    LOG(ERROR) << "Neither a Linux file path or package_id are set in request";
    response.set_failure_reason(
        "neither a Linux file path or package_id are set in request");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  Container* container = vm->GetContainerForName(container_name);
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: " << container_name;
    response.set_failure_reason(base::StringPrintf(
        "requested container does not exist: %s", container_name.c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  Container::LinuxPackageInfo pkg_info;
  response.set_success(container->GetLinuxPackageInfo(
      request.file_path(), request.package_name(), &pkg_info, &error_msg));

  if (response.success()) {
    response.set_package_id(pkg_info.package_id);
    response.set_license(pkg_info.license);
    response.set_description(pkg_info.description);
    response.set_project_url(pkg_info.project_url);
    response.set_size(pkg_info.size);
    response.set_summary(pkg_info.summary);
  } else {
    response.set_failure_reason(error_msg);
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::InstallLinuxPackage(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received InstallLinuxPackage request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  InstallLinuxPackageRequest request;
  InstallLinuxPackageResponse response;
  response.set_status(InstallLinuxPackageResponse::FAILED);
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse InstallLinuxPackageRequest from message";
    response.set_failure_reason("Unable to parse request protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  if (request.file_path().empty() && request.package_id().empty()) {
    LOG(ERROR) << "Neither a Linux file path or package_id are set in request";
    response.set_failure_reason(
        "neither a Linux file path or package_id are set in request");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  Container* container = vm->GetContainerForName(container_name);
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: " << container_name;
    response.set_failure_reason(base::StringPrintf(
        "requested container does not exist: %s", container_name.c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  vm_tools::container::InstallLinuxPackageResponse::Status status =
      container->InstallLinuxPackage(request.file_path(), request.package_id(),
                                     request.command_uuid(), &error_msg);
  response.set_failure_reason(error_msg);
  switch (status) {
    case vm_tools::container::InstallLinuxPackageResponse::STARTED:
      response.set_status(InstallLinuxPackageResponse::STARTED);
      break;
    case vm_tools::container::InstallLinuxPackageResponse::FAILED:
      response.set_status(InstallLinuxPackageResponse::FAILED);
      break;
    case vm_tools::container::InstallLinuxPackageResponse::
        INSTALL_ALREADY_ACTIVE:
      response.set_status(InstallLinuxPackageResponse::INSTALL_ALREADY_ACTIVE);
      break;
    default:
      LOG(ERROR) << "Unknown InstallLinuxPackageResponse Status " << status;
      response.set_failure_reason(
          "Unknown InstallLinuxPackageResponse Status from container");
      response.set_status(InstallLinuxPackageResponse::FAILED);
      break;
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::UninstallPackageOwningFile(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received UninstallPackageOwningFile request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  UninstallPackageOwningFileRequest request;
  UninstallPackageOwningFileResponse response;
  response.set_status(UninstallPackageOwningFileResponse::FAILED);
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR)
        << "Unable to parse UninstallPackageOwningFileRequest from message";
    response.set_failure_reason("Unable to parse request protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  if (request.desktop_file_id().empty()) {
    LOG(ERROR) << "desktop_file_id is not set in request";
    response.set_failure_reason("desktop_file_id is not set in request");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  Container* container = vm->GetContainerForName(container_name);
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: " << container_name;
    response.set_failure_reason(base::StringPrintf(
        "requested container does not exist: %s", container_name.c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  auto status = container->UninstallPackageOwningFile(request.desktop_file_id(),
                                                      &error_msg);
  switch (status) {
    case vm_tools::container::UninstallPackageOwningFileResponse::STARTED:
      response.set_status(UninstallPackageOwningFileResponse::STARTED);
      break;
    case vm_tools::container::UninstallPackageOwningFileResponse::FAILED:
      response.set_status(UninstallPackageOwningFileResponse::FAILED);
      response.set_failure_reason(error_msg);
      break;
    case vm_tools::container::UninstallPackageOwningFileResponse::
        BLOCKING_OPERATION_IN_PROGRESS:
      response.set_status(
          UninstallPackageOwningFileResponse::BLOCKING_OPERATION_IN_PROGRESS);
      response.set_failure_reason(error_msg);
      break;
    default:
      response.set_status(UninstallPackageOwningFileResponse::FAILED);
      response.set_failure_reason("Unknown return status " +
                                  base::NumberToString(status));
      break;
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::CreateLxdContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received CreateLxdContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  CreateLxdContainerRequest request;
  CreateLxdContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse CreateLxdRequest from message";
    response.set_failure_reason(
        "unable to parse CreateLxdRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::CreateLxdContainerStatus status = vm->CreateLxdContainer(
      request.container_name().empty() ? kDefaultContainerName
                                       : request.container_name(),
      request.image_server(), request.image_alias(), request.rootfs_path(),
      request.metadata_path(), &error_msg);

  switch (status) {
    case VirtualMachine::CreateLxdContainerStatus::UNKNOWN:
      response.set_status(CreateLxdContainerResponse::UNKNOWN);
      break;
    case VirtualMachine::CreateLxdContainerStatus::CREATING:
      response.set_status(CreateLxdContainerResponse::CREATING);
      break;
    case VirtualMachine::CreateLxdContainerStatus::EXISTS:
      response.set_status(CreateLxdContainerResponse::EXISTS);
      break;
    case VirtualMachine::CreateLxdContainerStatus::FAILED:
      response.set_status(CreateLxdContainerResponse::FAILED);
      break;
  }
  response.set_failure_reason(error_msg);

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::DeleteLxdContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received DeleteLxdContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  DeleteLxdContainerRequest request;
  DeleteLxdContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse DeleteLxdRequest from message";
    response.set_failure_reason(
        "unable to parse DeleteLxdRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::DeleteLxdContainerStatus status =
      vm->DeleteLxdContainer(request.container_name(), &error_msg);

  switch (status) {
    case VirtualMachine::DeleteLxdContainerStatus::UNKNOWN:
      response.set_status(DeleteLxdContainerResponse::UNKNOWN);
      break;
    case VirtualMachine::DeleteLxdContainerStatus::DELETING:
      response.set_status(DeleteLxdContainerResponse::DELETING);
      break;
    case VirtualMachine::DeleteLxdContainerStatus::DOES_NOT_EXIST:
      response.set_status(DeleteLxdContainerResponse::DOES_NOT_EXIST);
      break;
    case VirtualMachine::DeleteLxdContainerStatus::FAILED:
      response.set_status(DeleteLxdContainerResponse::FAILED);
      break;
  }
  response.set_failure_reason(error_msg);

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::StartLxdContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received StartLxdContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  StartLxdContainerRequest request;
  StartLxdContainerResponse response;
  response.set_status(StartLxdContainerResponse::UNKNOWN);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse StartLxdRequest from message";
    response.set_failure_reason("unable to parse StartLxdRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();

  std::string container_token = vm->GenerateContainerToken(container_name);
  Container* container = vm->GetPendingContainerForToken(container_token);
  CHECK(container);
  container->set_drivefs_mount_path(request.drivefs_mount_path());

  auto privilege_level =
      ConvertPrivilegeLevelFromCiceroneToTremplin(request.privilege_level());
  if (!privilege_level) {
    response.set_failure_reason("bad privilege level value");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string error_msg;
  VirtualMachine::StartLxdContainerStatus status =
      vm->StartLxdContainer(container_name, container_token, *privilege_level,
                            request.disable_audio_capture(), &error_msg);

  switch (status) {
    case VirtualMachine::StartLxdContainerStatus::UNKNOWN:
      response.set_status(StartLxdContainerResponse::UNKNOWN);
      break;
    case VirtualMachine::StartLxdContainerStatus::STARTING:
      response.set_status(StartLxdContainerResponse::STARTING);
      break;
    case VirtualMachine::StartLxdContainerStatus::STARTED:
      response.set_status(StartLxdContainerResponse::STARTED);
      break;
    case VirtualMachine::StartLxdContainerStatus::REMAPPING:
      response.set_status(StartLxdContainerResponse::REMAPPING);
      break;
    case VirtualMachine::StartLxdContainerStatus::RUNNING:
      response.set_status(StartLxdContainerResponse::RUNNING);
      break;
    case VirtualMachine::StartLxdContainerStatus::FAILED:
      response.set_status(StartLxdContainerResponse::FAILED);
      break;
  }

  const OsRelease* os_release = vm->GetOsReleaseForContainer(container_name);
  if (os_release) {
    response.mutable_os_release()->MergeFrom(*os_release);
  }

  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::StopLxdContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received StopLxdContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  StopLxdContainerRequest request;
  StopLxdContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse StopLxdRequest from message";
    response.set_failure_reason("unable to parse StopLxdRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::StopLxdContainerStatus status =
      vm->StopLxdContainer(request.container_name(), &error_msg);

  switch (status) {
    case VirtualMachine::StopLxdContainerStatus::UNKNOWN:
      response.set_status(StopLxdContainerResponse::UNKNOWN);
      break;
    case VirtualMachine::StopLxdContainerStatus::STOPPED:
      response.set_status(StopLxdContainerResponse::STOPPED);
      break;
    case VirtualMachine::StopLxdContainerStatus::STOPPING:
      response.set_status(StopLxdContainerResponse::STOPPING);
      break;
    case VirtualMachine::StopLxdContainerStatus::DOES_NOT_EXIST:
      response.set_status(StopLxdContainerResponse::DOES_NOT_EXIST);
      break;
    case VirtualMachine::StopLxdContainerStatus::FAILED:
      response.set_status(StopLxdContainerResponse::FAILED);
      break;
  }
  response.set_failure_reason(error_msg);

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::SetTimezone(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  SetTimezoneRequest request;
  SetTimezoneResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse SetTimezoneRequest from message";
    response.add_failure_reasons(
        "unable to parse SetTimezoneRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  LOG(INFO) << "Received request to SetTimezone to " << request.timezone_name();

  auto posix_tz_result = brillo::timezone::GetPosixTimezone(
      base::FilePath("/usr/share/zoneinfo").Append(request.timezone_name()));
  LOG_IF(WARNING, !posix_tz_result.has_value())
      << "Reading POSIX TZ string failed for timezone "
      << request.timezone_name();
  std::string posix_tz_string = posix_tz_result.value_or("");

  response.set_successes(0);
  for (const auto& elem : vms_) {
    const std::string& vm_name = elem.first.second;
    std::string error_msg;
    std::vector<std::string> container_names = elem.second->GetContainerNames();
    VirtualMachine::SetTimezoneResults results;
    bool success =
        elem.second->SetTimezone(request.timezone_name(), posix_tz_string,
                                 container_names, &results, &error_msg);
    if (success) {
      response.set_successes(response.successes() + results.successes);
      for (int i = 0; i < results.failure_reasons.size(); i++) {
        response.add_failure_reasons("VM " + vm_name + ": " +
                                     results.failure_reasons[i]);
      }
    } else {
      response.add_failure_reasons("Setting timezone failed entirely for VM " +
                                   vm_name + ": " + error_msg);
    }
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::GetLxdContainerUsername(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetLxdContainerUsername request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  GetLxdContainerUsernameRequest request;
  GetLxdContainerUsernameResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse GetLxdContainerUsernameRequest from message";
    response.set_failure_reason(
        "unable to parse GetLxdContainerUsernameRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg, username, homedir;
  VirtualMachine::GetLxdContainerUsernameStatus status =
      vm->GetLxdContainerUsername(request.container_name().empty()
                                      ? kDefaultContainerName
                                      : request.container_name(),
                                  &username, &homedir, &error_msg);

  switch (status) {
    case VirtualMachine::GetLxdContainerUsernameStatus::UNKNOWN:
      response.set_status(GetLxdContainerUsernameResponse::UNKNOWN);
      break;
    case VirtualMachine::GetLxdContainerUsernameStatus::SUCCESS:
      response.set_status(GetLxdContainerUsernameResponse::SUCCESS);
      break;
    case VirtualMachine::GetLxdContainerUsernameStatus::CONTAINER_NOT_FOUND:
      response.set_status(GetLxdContainerUsernameResponse::CONTAINER_NOT_FOUND);
      break;
    case VirtualMachine::GetLxdContainerUsernameStatus::CONTAINER_NOT_RUNNING:
      response.set_status(
          GetLxdContainerUsernameResponse::CONTAINER_NOT_RUNNING);
      break;
    case VirtualMachine::GetLxdContainerUsernameStatus::USER_NOT_FOUND:
      response.set_status(GetLxdContainerUsernameResponse::USER_NOT_FOUND);
      break;
    case VirtualMachine::GetLxdContainerUsernameStatus::FAILED:
      response.set_status(GetLxdContainerUsernameResponse::FAILED);
      break;
  }

  response.set_username(username);
  response.set_homedir(homedir);
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::SetUpLxdContainerUser(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received SetUpLxdContainerUser request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  SetUpLxdContainerUserRequest request;
  SetUpLxdContainerUserResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse SetUpLxdContainerUserRequest from message";
    response.set_failure_reason(
        "unable to parse SetUpLxdContainerUserRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string username;
  std::string error_msg;
  VirtualMachine::SetUpLxdContainerUserStatus status =
      vm->SetUpLxdContainerUser(
          request.container_name().empty() ? kDefaultContainerName
                                           : request.container_name(),
          request.container_username(), &username, &error_msg);

  switch (status) {
    case VirtualMachine::SetUpLxdContainerUserStatus::UNKNOWN:
      response.set_status(SetUpLxdContainerUserResponse::UNKNOWN);
      break;
    case VirtualMachine::SetUpLxdContainerUserStatus::SUCCESS:
      response.set_status(SetUpLxdContainerUserResponse::SUCCESS);
      break;
    case VirtualMachine::SetUpLxdContainerUserStatus::EXISTS:
      response.set_status(SetUpLxdContainerUserResponse::EXISTS);
      break;
    case VirtualMachine::SetUpLxdContainerUserStatus::FAILED:
      response.set_status(SetUpLxdContainerUserResponse::FAILED);
      break;
  }
  response.set_container_username(username);
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ExportLxdContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ExportLxdContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ExportLxdContainerRequest request;
  ExportLxdContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ExportLxdContainerRequest from message";
    response.set_status(ExportLxdContainerResponse::FAILED);
    response.set_failure_reason(
        "unable to parse ExportLxdContainerRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_status(ExportLxdContainerResponse::FAILED);
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::ExportLxdContainerStatus status = vm->ExportLxdContainer(
      request.container_name(), request.export_path(), &error_msg);

  response.set_status(ExportLxdContainerResponse::UNKNOWN);
  if (ExportLxdContainerResponse::Status_IsValid(static_cast<int>(status))) {
    response.set_status(
        static_cast<ExportLxdContainerResponse::Status>(status));
  }
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::CancelExportLxdContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received CancelExportLxdContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  CancelExportLxdContainerRequest request;
  CancelExportLxdContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR)
        << "Unable to parse CancelExportLxdContainerRequest from message";
    response.set_status(CancelExportLxdContainerResponse::FAILED);
    response.set_failure_reason(
        "unable to parse CancelExportLxdContainerRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_status(CancelExportLxdContainerResponse::FAILED);
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::CancelExportLxdContainerStatus status =
      vm->CancelExportLxdContainer(request.in_progress_container_name(),
                                   &error_msg);

  response.set_status(CancelExportLxdContainerResponse::UNKNOWN);
  if (CancelExportLxdContainerResponse::Status_IsValid(
          static_cast<int>(status))) {
    response.set_status(
        static_cast<CancelExportLxdContainerResponse::Status>(status));
  }
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ImportLxdContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ImportLxdContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ImportLxdContainerRequest request;
  ImportLxdContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ImportLxdContainerRequest from message";
    response.set_status(ImportLxdContainerResponse::FAILED);
    response.set_failure_reason(
        "unable to parse ImportLxdContainerRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_status(ImportLxdContainerResponse::FAILED);
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // AmountOfFreeDiskSpace returns a negative value if it fails.
  // Nothing can be done to resolve a failure here, so the import should still
  // be attempted. To this end, on failure we set free_disk_space to zero, which
  // is a sentinel value meaning unlimited free disk space.
  int64_t free_disk_space =
      base::SysInfo::AmountOfFreeDiskSpace(base::FilePath{"/home"});
  if (free_disk_space < 0) {
    LOG(ERROR) << "AmountofFreeDiskSpace for /home returned "
               << free_disk_space;
    free_disk_space = 0;
  }

  std::string error_msg;
  VirtualMachine::ImportLxdContainerStatus status =
      vm->ImportLxdContainer(request.container_name(), request.import_path(),
                             free_disk_space, &error_msg);

  response.set_status(ImportLxdContainerResponse::UNKNOWN);
  if (ImportLxdContainerResponse::Status_IsValid(static_cast<int>(status))) {
    response.set_status(
        static_cast<ImportLxdContainerResponse::Status>(status));
  }
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::CancelImportLxdContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received CancelImportLxdContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  CancelImportLxdContainerRequest request;
  CancelImportLxdContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR)
        << "Unable to parse CancelImportLxdContainerRequest from message";
    response.set_status(CancelImportLxdContainerResponse::FAILED);
    response.set_failure_reason(
        "unable to parse CancelImportLxdContainerRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_status(CancelImportLxdContainerResponse::FAILED);
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::CancelImportLxdContainerStatus status =
      vm->CancelImportLxdContainer(request.in_progress_container_name(),
                                   &error_msg);

  response.set_status(CancelImportLxdContainerResponse::UNKNOWN);
  if (CancelImportLxdContainerResponse::Status_IsValid(
          static_cast<int>(status))) {
    response.set_status(
        static_cast<CancelImportLxdContainerResponse::Status>(status));
  }
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ConnectChunnel(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Received ConnectChunnel request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ConnectChunnelRequest request;
  ConnectChunnelResponse response;
  response.set_status(ConnectChunnelResponse::UNKNOWN);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ConnectChunnelRequest from message";
    response.set_status(ConnectChunnelResponse::FAILED);
    response.set_failure_reason(
        "unable to parse ConnectChunnelRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_status(ConnectChunnelResponse::FAILED);
    response.set_failure_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  Container* container = vm->GetContainerForName(container_name);
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: " << container_name;
    response.set_status(ConnectChunnelResponse::FAILED);
    response.set_failure_reason(base::StringPrintf(
        "requested container does not exist: %s", container_name.c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  if (!container->ConnectChunnel(request.chunneld_port(),
                                 request.target_tcp4_port(), &error_msg)) {
    response.set_status(ConnectChunnelResponse::FAILED);
    response.set_failure_reason(error_msg);
  } else {
    response.set_status(ConnectChunnelResponse::SUCCESS);
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::GetDebugInformation(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Received GetDebugInformation request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageWriter writer(dbus_response.get());
  GetDebugInformationResponse response;

  std::string container_debug_information;
  std::string vm_debug_information;
  std::string* debug_information = response.mutable_debug_information();
  for (const auto& vm : vms_) {
    const std::string& vm_name = vm.first.second;
    *debug_information += "VM: ";
    *debug_information += vm_name;
    *debug_information += "\n";
    vm_debug_information.clear();
    if (!vm.second->GetTremplinDebugInfo(&vm_debug_information)) {
      *debug_information += "\tfailed to get debug information\n";
      *debug_information += "\t";
      *debug_information += vm_debug_information;
      *debug_information += "\n";
      LOG(ERROR) << "Failed to get tremplin debug information: "
                 << vm_debug_information;
    } else {
      std::vector<base::StringPiece> vm_info_lines = base::SplitStringPiece(
          vm_debug_information, "\n", base::KEEP_WHITESPACE,
          base::SPLIT_WANT_NONEMPTY);
      for (const auto& line : vm_info_lines) {
        *debug_information += "\t";
        debug_information->append(line.data(), line.size());
        *debug_information += "\n";
      }
    }
    for (const auto& container_name : vm.second->GetContainerNames()) {
      *debug_information += "\tContainer: ";
      *debug_information += container_name;
      *debug_information += "\n";

      container_debug_information.clear();
      Container* container = vm.second->GetContainerForName(container_name);
      if (!container->GetDebugInformation(&container_debug_information)) {
        *debug_information += "\t\tfailed to get debug information\n";
        *debug_information += "\t\t";
        *debug_information += container_debug_information;
        *debug_information += "\n";
        LOG(ERROR) << "Failed to get container debug information: "
                   << container_debug_information;
      } else {
        std::vector<base::StringPiece> container_info_lines =
            base::SplitStringPiece(container_debug_information, "\n",
                                   base::KEEP_WHITESPACE,
                                   base::SPLIT_WANT_NONEMPTY);
        for (const auto& line : container_info_lines) {
          *debug_information += "\t\t";
          debug_information->append(line.data(), line.size());
          *debug_information += "\n";
        }
      }
    }
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ApplyAnsiblePlaybook(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Received ApplyAnsiblePlaybook request";
  DCHECK(sequence_checker_.CalledOnValidSequence());
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ApplyAnsiblePlaybookRequest request;
  ApplyAnsiblePlaybookResponse response;
  response.set_status(ApplyAnsiblePlaybookResponse::FAILED);
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ApplyAnsiblePlaybookRequest from message";
    response.set_failure_reason("Unable to parse request protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  if (request.playbook().empty()) {
    LOG(ERROR) << "Playbook is not set in request";
    response.set_failure_reason("Playbook is not set in request");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  Container* container = vm->GetContainerForName(container_name);
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: " << container_name;
    response.set_failure_reason(base::StringPrintf(
        "requested container does not exist: %s", container_name.c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  vm_tools::container::ApplyAnsiblePlaybookResponse::Status status =
      container->ApplyAnsiblePlaybook(request.playbook(), &error_msg);
  response.set_failure_reason(error_msg);
  switch (status) {
    case vm_tools::container::ApplyAnsiblePlaybookResponse::STARTED:
      response.set_status(ApplyAnsiblePlaybookResponse::STARTED);
      break;
    case vm_tools::container::ApplyAnsiblePlaybookResponse::FAILED:
      response.set_status(ApplyAnsiblePlaybookResponse::FAILED);
      break;
    default:
      LOG(ERROR) << "Unknown ApplyAnsiblePlaybookResponse Status " << status;
      response.set_failure_reason(
          "Unknown ApplyAnsiblePlaybookResponse Status from container");
      response.set_status(ApplyAnsiblePlaybookResponse::FAILED);
      break;
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ConfigureForArcSideload(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Received ConfigureForArcSideload request";
  DCHECK(sequence_checker_.CalledOnValidSequence());
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ConfigureForArcSideloadRequest request;
  ConfigureForArcSideloadResponse response;
  response.set_status(ConfigureForArcSideloadResponse::FAILED);
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ConfigureForArcSideloadRequest from message";
    response.set_failure_reason("Unable to parse request protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason("Requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  std::string container_name = request.container_name().empty()
                                   ? kDefaultContainerName
                                   : request.container_name();
  Container* container = vm->GetContainerForName(container_name);
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: " << container_name;
    response.set_failure_reason(base::StringPrintf(
        "requested container does not exist: %s", container_name.c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  vm_tools::container::ConfigureForArcSideloadResponse::Status status =
      container->ConfigureForArcSideload(&error_msg);
  response.set_failure_reason(error_msg);
  switch (status) {
    case vm_tools::container::ConfigureForArcSideloadResponse::SUCCEEDED:
      response.set_status(ConfigureForArcSideloadResponse::SUCCEEDED);
      break;
    case vm_tools::container::ConfigureForArcSideloadResponse::FAILED:
      response.set_status(ConfigureForArcSideloadResponse::FAILED);
      break;
    default:
      LOG(ERROR) << "Unknown ConfigureForArcSideloadResponse Status " << status;
      response.set_failure_reason(
          "Unknown ConfigureForArcSideloadResponse Status from container");
      response.set_status(ConfigureForArcSideloadResponse::FAILED);
      break;
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::UpgradeContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received UpgradeContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  UpgradeContainerRequest request;
  UpgradeContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse UpgradeContainerRequest from message";
    response.set_status(UpgradeContainerResponse::FAILED);
    response.set_failure_reason(
        "unable to parse UpgradeContainerRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_status(UpgradeContainerResponse::FAILED);
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    std::string error_reason = base::StringPrintf(
        "requested container %s does not exist on vm %s",
        request.container_name().c_str(), request.vm_name().c_str());
    LOG(ERROR) << error_reason;
    response.set_status(UpgradeContainerResponse::FAILED);
    response.set_failure_reason(std::move(error_reason));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::UpgradeContainerStatus status =
      vm->UpgradeContainer(container, request.target_version(), &error_msg);

  response.set_status(UpgradeContainerResponse::UNKNOWN);
  if (UpgradeContainerResponse::Status_IsValid(static_cast<int>(status))) {
    response.set_status(static_cast<UpgradeContainerResponse::Status>(status));
  }
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::CancelUpgradeContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received CancelUpgradeContainer request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  CancelUpgradeContainerRequest request;
  CancelUpgradeContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse CancelUpgradeContainerRequest from message";
    response.set_status(CancelUpgradeContainerResponse::FAILED);
    response.set_failure_reason(
        "unable to parse CancelUpgradeContainerRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_status(CancelUpgradeContainerResponse::FAILED);
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    std::string error_reason = base::StringPrintf(
        "requested container %s does not exist on vm %s",
        request.container_name().c_str(), request.vm_name().c_str());
    LOG(ERROR) << error_reason;
    response.set_status(CancelUpgradeContainerResponse::FAILED);
    response.set_failure_reason(std::move(error_reason));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::CancelUpgradeContainerStatus status =
      vm->CancelUpgradeContainer(container, &error_msg);

  response.set_status(CancelUpgradeContainerResponse::UNKNOWN);
  if (CancelUpgradeContainerResponse::Status_IsValid(
          static_cast<int>(status))) {
    response.set_status(
        static_cast<CancelUpgradeContainerResponse::Status>(status));
  }
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::AttachUsbToContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received AttachUsbToContainer request";

  auto dbus_response = dbus::Response::FromMethodCall(method_call);

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  AttachUsbToContainerRequest request;
  AttachUsbToContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    std::string error_reason =
        "Unable to parse AttachUsbToContainerRequest from message";
    LOG(ERROR) << error_reason;
    response.set_status(AttachUsbToContainerResponse::FAILED);
    response.set_failure_reason(std::move(error_reason));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    std::string error_reason = base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str());
    LOG(ERROR) << error_reason;
    response.set_status(AttachUsbToContainerResponse::FAILED);
    response.set_failure_reason(std::move(error_reason));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    std::string error_reason = base::StringPrintf(
        "requested container %s does not exist on VM %s",
        request.container_name().c_str(), request.vm_name().c_str());
    LOG(ERROR) << error_reason;
    response.set_status(AttachUsbToContainerResponse::NO_SUCH_CONTAINER);
    response.set_failure_reason(std::move(error_reason));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::AttachUsbToContainerStatus status =
      vm->AttachUsbToContainer(container, request.port_num(), &error_msg);

  response.set_status(AttachUsbToContainerResponse::UNKNOWN);
  if (AttachUsbToContainerResponse::Status_IsValid(static_cast<int>(status))) {
    response.set_status(
        static_cast<AttachUsbToContainerResponse::Status>(status));
  }
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::DetachUsbFromContainer(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received DetachUsbFromContainer request";

  auto dbus_response = dbus::Response::FromMethodCall(method_call);

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  DetachUsbFromContainerRequest request;
  DetachUsbFromContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    std::string error_reason =
        "Unable to parse DetachUsbFromContainerRequest from message";
    LOG(ERROR) << error_reason;
    response.set_status(DetachUsbFromContainerResponse::FAILED);
    response.set_failure_reason(std::move(error_reason));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    std::string error_reason = base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str());
    LOG(ERROR) << error_reason;
    response.set_status(DetachUsbFromContainerResponse::FAILED);
    response.set_failure_reason(std::move(error_reason));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::DetachUsbFromContainerStatus status =
      vm->DetachUsbFromContainer(request.port_num(), &error_msg);

  response.set_status(DetachUsbFromContainerResponse::UNKNOWN);
  if (DetachUsbFromContainerResponse::Status_IsValid(
          static_cast<int>(status))) {
    response.set_status(
        static_cast<DetachUsbFromContainerResponse::Status>(status));
  }
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::StartLxd(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received StartLxd request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  StartLxdRequest request;
  StartLxdResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse StartLxdRequest from message";
    response.set_status(StartLxdResponse::FAILED);
    response.set_failure_reason(
        "unable to parse StartLxdResponse from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_status(StartLxdResponse::FAILED);
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  VirtualMachine::StartLxdStatus status =
      vm->StartLxd(request.reset_lxd_db(), &error_msg);

  response.set_status(StartLxdResponse::UNKNOWN);
  if (StartLxdResponse::Status_IsValid(static_cast<int>(status))) {
    response.set_status(static_cast<StartLxdResponse::Status>(status));
  }
  response.set_failure_reason(error_msg);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::AddFileWatch(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received AddFileWatch request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  AddFileWatchRequest request;
  AddFileWatchResponse response;
  response.set_status(AddFileWatchResponse::FAILED);
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse AddFileWatchRequest from message";
    response.set_failure_reason("unable to parse request protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  base::FilePath file_path(request.path());
  if (file_path.IsAbsolute() || file_path.ReferencesParent()) {
    LOG(ERROR) << "Invalid path format";
    response.set_failure_reason("invalid path format");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason("requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: "
               << request.container_name();
    response.set_failure_reason("requested container does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  if (container->AddFileWatch(request.path(), &error_msg)) {
    response.set_status(AddFileWatchResponse::SUCCEEDED);
  } else {
    response.set_failure_reason(error_msg);
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::RemoveFileWatch(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received RemoveFileWatch request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  RemoveFileWatchRequest request;
  RemoveFileWatchResponse response;
  response.set_status(RemoveFileWatchResponse::FAILED);
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse RemoveFileWatchRequest from message";
    response.set_failure_reason("unable to parse request protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  base::FilePath file_path(request.path());
  if (file_path.IsAbsolute() || file_path.ReferencesParent()) {
    LOG(ERROR) << "Invalid path format";
    response.set_failure_reason("invalid path format");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason("requested VM does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: "
               << request.container_name();
    response.set_failure_reason("requested container does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::string error_msg;
  if (container->RemoveFileWatch(request.path(), &error_msg)) {
    response.set_status(RemoveFileWatchResponse::SUCCEEDED);
  } else {
    response.set_failure_reason(error_msg);
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

void Service::FileWatchTriggered(const std::string& container_token,
                                 const uint32_t cid,
                                 FileWatchTriggeredSignal* changed_signal,
                                 bool* result,
                                 base::WaitableEvent* event) {
  *result = SendSignal(kFileWatchTriggeredSignal, container_token, cid,
                       changed_signal);
  event->Signal();
}

void Service::LowDiskSpaceTriggered(const std::string& container_token,
                                    const uint32_t cid,
                                    LowDiskSpaceTriggeredSignal* changed_signal,
                                    bool* result,
                                    base::WaitableEvent* event) {
  *result = SendSignal(kLowDiskSpaceTriggeredSignal, container_token, cid,
                       changed_signal);
  event->Signal();
}

std::unique_ptr<dbus::Response> Service::RegisterVshSession(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received RegisterVshSession request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  RegisterVshSessionRequest request;
  RegisterVshSessionResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse RegisterVshSessionRequest from message";
    response.set_failure_reason(
        "unable to parse RegisterVshSessionRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: "
               << request.container_name();
    response.set_failure_reason(
        base::StringPrintf("requested container does not exist: %s",
                           request.container_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  container->RegisterVshSession(request.host_vsh_pid(),
                                request.container_shell_pid());
  response.set_success(true);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::GetVshSession(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetVshSession request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  GetVshSessionRequest request;
  GetVshSessionResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse GetVshSessionRequest from message";
    response.set_failure_reason(
        "unable to parse GetVshSessionRequest from message");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason(base::StringPrintf(
        "requested VM does not exist: %s", request.vm_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: "
               << request.container_name();
    response.set_failure_reason(
        base::StringPrintf("requested container does not exist: %s",
                           request.container_name().c_str()));
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  int32_t pid = container->GetVshSession(request.host_vsh_pid());
  if (pid == 0) {
    response.set_failure_reason("container shell pid not found");
  } else {
    response.set_success(true);
    response.set_container_shell_pid(pid);
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::FileSelected(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received FileSelected request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  FileSelectedSignal request;
  EmptyMessage response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse FileSelectedSignal from message";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: "
               << request.container_name();
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  auto it = select_file_dialogs_.find(request.select_file_token());
  if (it == select_file_dialogs_.end()) {
    LOG(ERROR) << "Select file token not found: "
               << request.select_file_token();
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::move(it->second)
      .Run(std::vector<string>(
          std::make_move_iterator(request.mutable_files()->begin()),
          std::make_move_iterator(request.mutable_files()->end())));
  select_file_dialogs_.erase(it);
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::ListRunningContainers(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received ListRunningContainers request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  ListRunningContainersRequest request;
  ListRunningContainersResponse response;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ListRunningContainersRequest from message";
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  for (const auto& vm : vms_) {
    if (vm.first.first != request.owner_id()) {
      continue;
    }
    for (const auto& container_entry : vm.second->GetContainers()) {
      auto* info = response.add_containers();
      info->set_vm_name(vm.first.second);
      info->set_container_name(container_entry.second->name());
      info->set_container_token(container_entry.second->token());
      auto* os_release =
          vm.second->GetOsReleaseForContainer(container_entry.second->name());
      if (os_release) {
        info->mutable_os_release()->MergeFrom(*os_release);
      }
    }
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::GetGarconSessionInfo(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received GetGarconSessionInfo request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  GetGarconSessionInfoRequest request;
  GetGarconSessionInfoResponse response;
  response.set_status(GetGarconSessionInfoResponse::UNKNOWN);
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse GetGarconSessionInfoRequest from message";
    response.set_failure_reason("unable to parse request protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason("requested VM does not exist");
    response.set_status(GetGarconSessionInfoResponse::NOT_FOUND);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: "
               << request.container_name();
    response.set_failure_reason("requested container does not exist");
    response.set_status(GetGarconSessionInfoResponse::NOT_FOUND);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  uint32_t sftp_vsock_port;
  if (container->GetGarconSessionInfo(response.mutable_failure_reason(),
                                      response.mutable_container_username(),
                                      response.mutable_container_homedir(),
                                      &sftp_vsock_port)) {
    response.set_status(GetGarconSessionInfoResponse::SUCCEEDED);
    response.set_sftp_vsock_port(sftp_vsock_port);
  } else {
    response.set_status(GetGarconSessionInfoResponse::FAILED);
  }
  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

std::unique_ptr<dbus::Response> Service::UpdateContainerDevices(
    dbus::MethodCall* method_call) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Received UpdateContainerDevices request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());

  UpdateContainerDevicesRequest request;
  UpdateContainerDevicesResponse response;
  response.set_status(UpdateContainerDevicesResponse::UNKNOWN);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse UpdateContainerDevices from message";
    response.set_failure_reason("unable to parse request protobuf");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VirtualMachine* vm = FindVm(request.owner_id(), request.vm_name());
  if (!vm) {
    LOG(ERROR) << "Requested VM does not exist:" << request.vm_name();
    response.set_failure_reason("requested VM does not exist");
    response.set_status(UpdateContainerDevicesResponse::NO_SUCH_CONTAINER);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  Container* container = vm->GetContainerForName(request.container_name());
  if (!container) {
    LOG(ERROR) << "Requested container does not exist: "
               << request.container_name();
    response.set_failure_reason("requested container does not exist");
    response.set_status(UpdateContainerDevicesResponse::NO_SUCH_CONTAINER);
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  VirtualMachine::UpdateContainerDevicesStatus status =
      vm->UpdateContainerDevices(container, request.updates(),
                                 response.mutable_results(),
                                 response.mutable_failure_reason());
  if (UpdateContainerDevicesResponse::Status_IsValid(
          static_cast<int>(status))) {
    response.set_status(
        static_cast<UpdateContainerDevicesResponse::Status>(status));
  }

  writer.AppendProtoAsArrayOfBytes(response);
  return dbus_response;
}

bool Service::GetVirtualMachineForCidOrToken(const uint32_t cid,
                                             const std::string& vm_token,
                                             VirtualMachine** vm_out,
                                             std::string* owner_id_out,
                                             std::string* name_out) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(vm_out);
  CHECK(owner_id_out);
  CHECK(name_out);
  // If there is a nonzero CID, then we look for a VM based on that. Otherwise
  // we use the token to find the VM.
  if (cid) {
    for (const auto& vm : vms_) {
      if (vm.second->cid() != cid) {
        continue;
      }
      *owner_id_out = vm.first.first;
      *name_out = vm.first.second;
      *vm_out = vm.second.get();
      DCHECK((*vm_out)->GetType() != VirtualMachine::VmType::PLUGIN_VM);
      return true;
    }
    return false;
  } else {
    for (const auto& vm : vms_) {
      if (vm.second->vm_token() != vm_token) {
        continue;
      }
      *owner_id_out = vm.first.first;
      *name_out = vm.first.second;
      *vm_out = vm.second.get();
      // This DCHECK is asserting the inputs are valid. Since fuzzers are
      // intended to give us invalid inputs, skip the DCHECK when fuzzing.
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
      DCHECK((*vm_out)->GetType() == VirtualMachine::VmType::PLUGIN_VM);
#endif  // FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
      return true;
    }
    return false;
  }
}

void Service::RegisterHostname(const std::string& hostname,
                               const std::string& ip) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  dbus::MethodCall method_call(crosdns::kCrosDnsInterfaceName,
                               crosdns::kSetHostnameIpMappingMethod);
  dbus::MessageWriter writer(&method_call);
  // Params are hostname, IPv4, IPv6 (but we don't have IPv6 yet).
  writer.AppendString(hostname);
  writer.AppendString(ip);
  writer.AppendString("");
  std::unique_ptr<dbus::Response> dbus_response =
      crosdns_service_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    // If there's some issue with the resolver service, don't make that
    // propagate to a higher level failure and just log it. We have logic for
    // setting this up again if that service restarts.
    LOG(WARNING)
        << "Failed to send dbus message to crosdns to register hostname";
  } else {
    hostname_mappings_[hostname] = ip;
    if (hostname == kDefaultContainerHostname)
      linuxhost_ip_ = ip;
  }
}

void Service::UnregisterVmContainers(VirtualMachine* vm,
                                     const std::string& owner_id,
                                     const std::string& vm_name) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  if (!vm)
    return;
  // When we were in concierge, this method was important because we shared a
  // D-Bus thread with concierge who was stopping the VM. Now that we are in a
  // separate process, we should receive the gRPC call from the container for
  // container shutdown before we receive the D-Bus call from concierge for the
  // VM stopping. It is entirely possible that they come in out of order, so we
  // still need this in case that happens.
  std::vector<std::string> containers = vm->GetContainerNames();
  for (auto& container_name : containers) {
    // Containerless vms have a pretend container that never gets shut down, so
    // no need to complain about it.
    if (!vm->IsContainerless() || container_name != kDefaultContainerName) {
      LOG(WARNING) << "Latent container left in VM " << vm_name << " of "
                   << container_name;
    }

    if (owner_id == primary_owner_id_) {
      UnregisterHostname(base::StringPrintf(
          "%s.%s.linux.test", container_name.c_str(), vm_name.c_str()));
      if (vm_name == kDefaultVmName &&
          container_name == kDefaultContainerName) {
        UnregisterHostname(kDefaultContainerHostname);
        ssh_process_.Reset(0);
      }
    }

    // Send the D-Bus signal to indicate the container has shutdown.
    dbus::Signal signal(kVmCiceroneInterface, kContainerShutdownSignal);
    ContainerShutdownSignal proto;
    proto.set_vm_name(vm_name);
    proto.set_container_name(container_name);
    proto.set_owner_id(owner_id);
    dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
    exported_object_->SendSignal(&signal);
  }
}

void Service::UnregisterHostname(const std::string& hostname) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  dbus::MethodCall method_call(crosdns::kCrosDnsInterfaceName,
                               crosdns::kRemoveHostnameIpMappingMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendString(hostname);
  std::unique_ptr<dbus::Response> dbus_response =
      crosdns_service_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    // If there's some issue with the resolver service, don't make that
    // propagate to a higher level failure and just log it. We have logic for
    // setting this up again if that service restarts.
    LOG(WARNING) << "Failed to send dbus message to crosdns to unregister "
                 << "hostname";
  }
  hostname_mappings_.erase(hostname);
  if (hostname == kDefaultContainerHostname)
    linuxhost_ip_ = "";
}

void Service::OnCrosDnsNameOwnerChanged(const std::string& old_owner,
                                        const std::string& new_owner) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  if (!new_owner.empty()) {
    // Re-register everything in our map.
    for (auto& pair : hostname_mappings_) {
      RegisterHostname(pair.first, pair.second);
    }
  }
}

void Service::OnLocaltimeFileChanged(const base::FilePath& path, bool error) {
  LOG(INFO) << "System timezone changed, updating container timezones";

  base::FilePath system_timezone;
  if (!base::NormalizeFilePath(base::FilePath(kLocaltimePath),
                               &system_timezone)) {
    LOG(ERROR) << "Getting system timezone failed";
    return;
  }

  auto posix_tz_result = brillo::timezone::GetPosixTimezone(system_timezone);
  LOG_IF(WARNING, !posix_tz_result.has_value())
      << "Reading POSIX TZ string failed for timezone file "
      << system_timezone.value();
  std::string posix_tz_string = posix_tz_result.value_or("");

  base::FilePath zoneinfo("/usr/share/zoneinfo");
  base::FilePath system_timezone_name;
  if (!zoneinfo.AppendRelativePath(system_timezone, &system_timezone_name)) {
    LOG(ERROR) << "Could not get name of timezone " << system_timezone.value();
    return;
  }

  for (const auto& vm : vms_) {
    const std::string& vm_name = vm.first.second;
    std::vector<std::string> container_names = vm.second->GetContainerNames();
    VirtualMachine::SetTimezoneResults results;
    std::string error_msg;
    bool success =
        vm.second->SetTimezone(system_timezone_name.value(), posix_tz_string,
                               container_names, &results, &error_msg);
    if (success) {
      for (int i = 0; i < results.failure_reasons.size(); i++) {
        LOG(ERROR) << "VM " << vm_name << ": " << results.failure_reasons[i];
      }
    } else {
      LOG(ERROR) << "Setting timezone failed entirely for VM " << vm_name
                 << ": " << error_msg;
    }
  }
}

void Service::OnCrosDnsServiceAvailable(bool service_is_available) {
  if (service_is_available) {
    crosdns_service_proxy_->SetNameOwnerChangedCallback(base::BindRepeating(
        &Service::OnCrosDnsNameOwnerChanged, weak_ptr_factory_.GetWeakPtr()));
  }
}

VirtualMachine* Service::FindVm(const std::string& owner_id,
                                const std::string& vm_name) {
  VmKey vm_key = std::make_pair(owner_id, vm_name);
  auto iter = vms_.find(vm_key);
  if (iter != vms_.end())
    return iter->second.get();
  if (!owner_id.empty()) {
    // TODO(jkardatzke): Remove this empty owner check once the other CLs land
    // for setting this everywhere.
    vm_key = std::make_pair("", vm_name);
    auto iter = vms_.find(vm_key);
    if (iter != vms_.end())
      return iter->second.get();
  }
  return nullptr;
}

}  // namespace cicerone
}  // namespace vm_tools
