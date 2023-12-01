// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/plugin_vm.h"

#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <algorithm>
#include <sstream>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/notreached.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/patchpanel/net_util.h>

#include "vm_tools/common/vm_id.h"
#include "vm_tools/concierge/plugin_vm_config.h"
#include "vm_tools/concierge/plugin_vm_helper.h"
#include "vm_tools/concierge/tap_device_builder.h"
#include "vm_tools/concierge/vm_base_impl.h"
#include "vm_tools/concierge/vm_builder.h"
#include "vm_tools/concierge/vm_permission_interface.h"
#include "vm_tools/concierge/vm_util.h"
#include "vm_tools/concierge/vmplugin_dispatcher_interface.h"

using std::string;

namespace vm_tools {
namespace concierge {
namespace {

// How long we give VM to suspend.
constexpr base::TimeDelta kVmSuspendTimeout = base::Seconds(25);

// How long to wait before timing out on child process exits.
constexpr base::TimeDelta kChildExitTimeout = base::Seconds(10);

// By convention, the IPv4 address of the VM guest is always the second unicast
// address in the IPv4 subnet assigned to the guest.
constexpr size_t kGuestAddressOffset = 2;

std::unique_ptr<patchpanel::Subnet> MakeSubnet(
    const patchpanel::Client::IPv4Subnet& subnet) {
  const std::optional<net_base::IPv4Address> addr =
      net_base::IPv4Address::CreateFromBytes(subnet.base_addr.data(),
                                             subnet.base_addr.size());
  if (!addr) {
    return nullptr;
  }
  const std::optional<net_base::IPv4CIDR> cidr =
      net_base::IPv4CIDR::CreateFromAddressAndPrefix(*addr, subnet.prefix_len);
  if (!cidr) {
    return nullptr;
  }
  return std::make_unique<patchpanel::Subnet>(*cidr, base::DoNothing());
}

void TrySuspendVm(scoped_refptr<dbus::Bus> bus,
                  dbus::ObjectProxy* vmplugin_service_proxy,
                  const VmId& id) {
  bool dispatcher_shutting_down = false;
  base::TimeTicks suspend_start_time(base::TimeTicks::Now());
  do {
    pvm::dispatcher::VmOpResult result =
        pvm::dispatcher::SuspendVm(bus, vmplugin_service_proxy, id);

    switch (result) {
      case pvm::dispatcher::VmOpResult::SUCCESS:
        return;

      case pvm::dispatcher::VmOpResult::DISPATCHER_SHUTTING_DOWN:
        // The dispatcher is in process of shutting down, and is supposed
        // to suspend all running VMs. Wait a second, and try again, until we
        // get "dispatcher not available" response.
        if (!dispatcher_shutting_down) {
          LOG(INFO) << "Dispatcher is shutting down, will retry suspend";
          dispatcher_shutting_down = true;
        }
        base::PlatformThread::Sleep(base::Seconds(1));
        break;

      case pvm::dispatcher::VmOpResult::DISPATCHER_NOT_AVAILABLE:
        if (!dispatcher_shutting_down)
          LOG(ERROR) << "Failed to suspend VM: dispatcher is not available";
        return;

      default:
        // TODO(dtor): handle cases when suspend fails because VM is already
        // transitioning into some state, such as suspending or shutting down,
        // in which case dispatcher will reject our request.
        LOG(ERROR) << "Failed to suspend VM: " << static_cast<int>(result);
        return;
    }
  } while (base::TimeTicks::Now() - suspend_start_time < kVmSuspendTimeout);
}

}  // namespace

// static
std::unique_ptr<PluginVm> PluginVm::Create(Config config) {
  auto stateful_dir = std::move(config.stateful_dir);
  auto subnet_index = std::move(config.subnet_index);
  auto enable_vnet_hdr = std::move(config.enable_vnet_hdr);
  auto vm_builder = std::move(config.vm_builder);

  auto vm = base::WrapUnique(new PluginVm(std::move(config)));

  if (!vm->CreateUsbListeningSocket() ||
      !vm->Start(std::move(stateful_dir), subnet_index, enable_vnet_hdr,
                 std::move(vm_builder))) {
    vm.reset();
  }

  return vm;
}

PluginVm::~PluginVm() {
  StopVm();
}

bool PluginVm::StopVm() {
  // Notify arc-patchpanel that the VM is down.
  // This should run before the process existence check below since we still
  // want to release the network resources on crash.
  // Note the client will only be null during testing.
  if (network_client_ &&
      !network_client_->NotifyParallelsVmShutdown(id_hash_)) {
    LOG(WARNING) << "Unable to notify networking services";
  }

  // Notify permission service of VM destruction.
  if (!permission_token_.empty()) {
    vm_permission::UnregisterVm(bus_, vm_permission_service_proxy_, id_);
  }

  // Do a check here to make sure the process is still around.
  if (!CheckProcessExists(process_.pid())) {
    // The process is already gone.
    process_.Release();
    return true;
  }

  TrySuspendVm(bus_, vmplugin_service_proxy_, id_);
  if (!CheckProcessExists(process_.pid())) {
    process_.Release();
    return true;
  }

  // Kill the process with SIGTERM. For Plugin VMs this will cause plugin to
  // try to suspend the VM.
  if (process_.Kill(SIGTERM, kChildExitTimeout.InSeconds())) {
    return true;
  }

  LOG(WARNING) << "Failed to kill plugin VM with SIGTERM";

  // Kill it with fire.
  if (process_.Kill(SIGKILL, kChildExitTimeout.InSeconds())) {
    return true;
  }

  LOG(ERROR) << "Failed to kill plugin VM with SIGKILL";
  return false;
}

bool PluginVm::Shutdown() {
  // Notify arc-patchpanel that the VM is down.
  // This should run before the process existence check below since we still
  // want to release the network resources on crash.
  // Note the client will only be null during testing.
  if (network_client_ &&
      !network_client_->NotifyParallelsVmShutdown(id_hash_)) {
    LOG(WARNING) << "Unable to notify networking services";
  }

  return !CheckProcessExists(process_.pid()) ||
         pvm::dispatcher::ShutdownVm(bus_, vmplugin_service_proxy_, id_) ==
             pvm::dispatcher::VmOpResult::SUCCESS;
}

VmBaseImpl::Info PluginVm::GetInfo() {
  VmBaseImpl::Info info = {
      .ipv4_address = subnet_->CIDRAtOffset(kGuestAddressOffset)
                          .value_or(net_base::IPv4CIDR())
                          .address()
                          .ToInAddr()
                          .s_addr,
      .pid = process_.pid(),
      .cid = 0,
      .seneschal_server_handle = seneschal_server_handle(),
      .permission_token = permission_token_,
      .status = VmBaseImpl::Status::RUNNING,
      .type = VmId::Type::PLUGIN_VM,
  };

  return info;
}

bool PluginVm::GetVmEnterpriseReportingInfo(
    GetVmEnterpriseReportingInfoResponse* response) {
  response->set_success(false);
  response->set_failure_reason("Not implemented");
  return false;
}

vm_tools::concierge::DiskImageStatus PluginVm::ResizeDisk(
    uint64_t new_size, std::string* failure_reason) {
  *failure_reason = "Not implemented";
  return DiskImageStatus::DISK_STATUS_FAILED;
}

vm_tools::concierge::DiskImageStatus PluginVm::GetDiskResizeStatus(
    std::string* failure_reason) {
  *failure_reason = "Not implemented";
  return DiskImageStatus::DISK_STATUS_FAILED;
}

// static
base::ScopedFD PluginVm::CreateUnixSocket(const base::FilePath& path,
                                          int type) {
  base::ScopedFD fd(socket(AF_UNIX, type, 0));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to create AF_UNIX socket";
    return base::ScopedFD();
  }

  struct sockaddr_un sa;

  if (path.value().length() >= sizeof(sa.sun_path)) {
    LOG(ERROR) << "Path is too long for a UNIX socket: " << path.value();
    return base::ScopedFD();
  }

  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  // The memset above took care of NUL terminating, and we already verified
  // the length before that.
  memcpy(sa.sun_path, path.value().data(), path.value().length());

  // Delete any old socket instances.
  if (PathExists(path) && !DeleteFile(path)) {
    PLOG(ERROR) << "failed to delete " << path.value();
    return base::ScopedFD();
  }

  // Bind the socket.
  if (bind(fd.get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) < 0) {
    PLOG(ERROR) << "failed to bind " << path.value();
    return base::ScopedFD();
  }

  return fd;
}

// static
bool PluginVm::SetVmCpuRestriction(CpuRestrictionState cpu_restriction_state) {
  return VmBaseImpl::SetVmCpuRestriction(cpu_restriction_state,
                                         kPluginVmCpuCgroup) &&
         VmBaseImpl::SetVmCpuRestriction(cpu_restriction_state,
                                         kPluginVmVcpuCpuCgroup);
}

bool PluginVm::CreateUsbListeningSocket() {
  usb_listen_fd_ = CreateUnixSocket(runtime_dir_.GetPath().Append("usb.sock"),
                                    SOCK_SEQPACKET);
  if (!usb_listen_fd_.is_valid()) {
    return false;
  }

  // Start listening for connections. We only expect one client at a time.
  if (listen(usb_listen_fd_.get(), 1) < 0) {
    PLOG(ERROR) << "Unable to listen for connections on USB socket";
    return false;
  }

  usb_listen_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      usb_listen_fd_.get(),
      base::BindRepeating(&PluginVm::OnListenFileCanReadWithoutBlocking,
                          base::Unretained(this)));
  if (!usb_listen_watcher_) {
    LOG(ERROR) << "Failed to watch USB listening socket";
    return false;
  }

  return true;
}

bool PluginVm::AttachUsbDevice(uint8_t bus,
                               uint8_t addr,
                               uint16_t vid,
                               uint16_t pid,
                               int fd,
                               uint8_t* out_port) {
  base::ScopedFD dup_fd(dup(fd));
  if (!dup_fd.is_valid()) {
    PLOG(ERROR) << "Unable to duplicate incoming file descriptor";
    return false;
  }

  if (usb_vm_fd_.is_valid() && usb_req_waiting_xmit_.empty()) {
    usb_listen_watcher_.reset();
    usb_vm_read_watcher_ = base::FileDescriptorWatcher::WatchReadable(
        usb_vm_fd_.get(),
        base::BindRepeating(&PluginVm::OnVmFileCanReadWithoutBlocking,
                            base::Unretained(this)));
    usb_vm_write_watcher_ = base::FileDescriptorWatcher::WatchWritable(
        usb_vm_fd_.get(),
        base::BindRepeating(&PluginVm::OnVmFileCanWriteWithoutBlocking,
                            base::Unretained(this)));
    if (!usb_vm_read_watcher_ || !usb_vm_write_watcher_) {
      LOG(ERROR) << "Failed to start watching USB VM socket";
      usb_vm_read_watcher_.reset();
      usb_vm_write_watcher_.reset();
      return false;
    }
  }

  UsbCtrlRequest req{};
  req.type = ATTACH_DEVICE;
  req.handle = ++usb_last_handle_;
  req.DevInfo.bus = bus;
  req.DevInfo.addr = addr;
  req.DevInfo.vid = vid;
  req.DevInfo.pid = pid;
  usb_req_waiting_xmit_.emplace_back(std::move(req), std::move(dup_fd));

  *out_port = usb_last_handle_;
  return true;
}

bool PluginVm::DetachUsbDevice(uint8_t port) {
  auto iter = std::find_if(
      usb_devices_.begin(), usb_devices_.end(),
      [port](const auto& info) { return std::get<2>(info) == port; });
  if (iter == usb_devices_.end()) {
    return true;
  }

  if (usb_vm_fd_.is_valid() && usb_req_waiting_xmit_.empty()) {
    usb_listen_watcher_.reset();
    usb_vm_read_watcher_ = base::FileDescriptorWatcher::WatchReadable(
        usb_vm_fd_.get(),
        base::BindRepeating(&PluginVm::OnVmFileCanReadWithoutBlocking,
                            base::Unretained(this)));
    usb_vm_write_watcher_ = base::FileDescriptorWatcher::WatchWritable(
        usb_vm_fd_.get(),
        base::BindRepeating(&PluginVm::OnVmFileCanWriteWithoutBlocking,
                            base::Unretained(this)));
    if (!usb_vm_read_watcher_ || !usb_vm_write_watcher_) {
      LOG(ERROR) << "Failed to start watching USB VM socket";
      usb_vm_read_watcher_.reset();
      usb_vm_write_watcher_.reset();
      return false;
    }
  }

  UsbCtrlRequest req{};
  req.type = DETACH_DEVICE;
  req.handle = port;
  usb_req_waiting_xmit_.emplace_back(req, base::ScopedFD());

  // TODO(dtor): report status only when plugin responds; requires changes to
  // the VmBaseImpl API.
  return true;
}

bool PluginVm::ListUsbDevice(std::vector<UsbDeviceEntry>* device) {
  device->resize(usb_devices_.size());
  std::transform(usb_devices_.begin(), usb_devices_.end(), device->begin(),
                 [](const auto& info) {
                   UsbDeviceEntry d{};
                   std::tie(d.vendor_id, d.product_id, d.port) = info;
                   return d;
                 });
  return true;
}

void PluginVm::HandleUsbControlResponse() {
  UsbCtrlResponse resp;
  int ret = HANDLE_EINTR(read(usb_vm_fd_.get(), &resp, sizeof(resp)));
  if (ret <= 0) {
    // If we get 0 bytes from read() that means that the other side closed
    // the connection. Disconnect the socket and wait for new connection.
    // Do the same if we get any error besides EAGAIN.
    if (ret == 0 || errno != EAGAIN) {
      usb_vm_read_watcher_.reset();
      usb_vm_write_watcher_.reset();
      usb_vm_fd_.reset();

      usb_listen_watcher_ = base::FileDescriptorWatcher::WatchReadable(
          usb_listen_fd_.get(),
          base::BindRepeating(&PluginVm::OnListenFileCanReadWithoutBlocking,
                              base::Unretained(this)));
      if (!usb_listen_watcher_) {
        LOG(ERROR) << "Failed to restart watching USB listening socket";
      }
    }
  } else if (ret != sizeof(resp)) {
    LOG(ERROR) << "Partial read of " << ret
               << " from USB VM socket, discarding";
  } else {
    auto req_iter = std::find_if(
        usb_req_waiting_response_.begin(), usb_req_waiting_response_.end(),
        [&resp](const auto& req) {
          return resp.type == req.type && resp.handle == req.handle;
        });
    if (req_iter == usb_req_waiting_response_.end()) {
      LOG(ERROR) << "Unexpected response (type " << resp.type << ", handle "
                 << resp.handle << ")";
      return;
    }

    if (resp.status != UsbCtrlResponse::Status::OK) {
      LOG(ERROR) << "Request (type " << resp.type << ", handle " << resp.handle
                 << ") failed: " << resp.status;
    }

    switch (req_iter->type) {
      case ATTACH_DEVICE:
        if (resp.status == UsbCtrlResponse::Status::OK) {
          usb_devices_.emplace_back(req_iter->DevInfo.vid,
                                    req_iter->DevInfo.pid, req_iter->handle);
        }
        break;
      case DETACH_DEVICE: {
        // We will attempt to clean up even if plugin signalled error as there
        // is no way the device will continue be operational.
        auto dev_iter = std::find_if(usb_devices_.begin(), usb_devices_.end(),
                                     [&resp](const auto& info) {
                                       return std::get<2>(info) == resp.handle;
                                     });
        if (dev_iter == usb_devices_.end()) {
          LOG(ERROR) << "Received detach response for unknown handle "
                     << resp.handle;
        }
      } break;
      default:
        NOTREACHED();
    }

    usb_req_waiting_response_.erase(req_iter);
  }
}

void PluginVm::OnListenFileCanReadWithoutBlocking() {
  int ret = HANDLE_EINTR(accept4(usb_listen_fd_.get(), nullptr, nullptr,
                                 SOCK_CLOEXEC | SOCK_NONBLOCK));
  if (ret < 0) {
    PLOG(ERROR) << "Unable to accept connection on USB listening socket";
    return;
  }

  // Start managing socket connected to the VM.
  usb_vm_fd_.reset(ret);

  // Switch watcher from listener FD to connected socket FD.
  // We monitor both writes and reads to detect disconnects.
  usb_listen_watcher_.reset();
  usb_vm_read_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      usb_vm_fd_.get(),
      base::BindRepeating(&PluginVm::OnVmFileCanReadWithoutBlocking,
                          base::Unretained(this)));
  if (!usb_req_waiting_xmit_.empty()) {
    usb_vm_write_watcher_ = base::FileDescriptorWatcher::WatchWritable(
        usb_vm_fd_.get(),
        base::BindRepeating(&PluginVm::OnVmFileCanWriteWithoutBlocking,
                            base::Unretained(this)));
  }
  if (!usb_vm_read_watcher_ ||
      (!usb_req_waiting_xmit_.empty() && !usb_vm_write_watcher_)) {
    LOG(ERROR) << "Failed to start watching USB VM socket";
    usb_vm_write_watcher_.reset();
    usb_vm_read_watcher_.reset();
    usb_vm_fd_.reset();
    return;
  }
}

void PluginVm::OnVmFileCanReadWithoutBlocking() {
  PluginVm::HandleUsbControlResponse();
}

void PluginVm::OnVmFileCanWriteWithoutBlocking() {
  DCHECK(usb_vm_fd_.is_valid());

  if (!usb_req_waiting_xmit_.empty()) {
    UsbCtrlRequest req = usb_req_waiting_xmit_.front().first;
    struct iovec io {};
    io.iov_base = &req;
    io.iov_len = sizeof(req);

    struct msghdr msg {};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char buf[CMSG_SPACE(sizeof(int))];
    base::ScopedFD fd(std::move(usb_req_waiting_xmit_.front().second));
    if (fd.is_valid()) {
      msg.msg_control = buf;
      msg.msg_controllen = CMSG_LEN(sizeof(int));

      struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_len = CMSG_LEN(sizeof(int));
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;

      *(reinterpret_cast<int*> CMSG_DATA(cmsg)) = fd.get();
    }

    int ret = HANDLE_EINTR(sendmsg(usb_vm_fd_.get(), &msg, MSG_EOR));
    if (ret == sizeof(req)) {
      usb_req_waiting_response_.emplace_back(req);
      usb_req_waiting_xmit_.pop_front();
    } else if (ret >= 0) {
      PLOG(ERROR) << "Partial write of " << ret
                  << " while sending USB request; will retry";
    } else if (errno != EINTR) {
      PLOG(ERROR) << "Failed to send USB request";
    }
  } else {
    usb_listen_watcher_.reset();
    usb_vm_write_watcher_.reset();

    usb_vm_read_watcher_ = base::FileDescriptorWatcher::WatchReadable(
        usb_vm_fd_.get(),
        base::BindRepeating(&PluginVm::OnVmFileCanReadWithoutBlocking,
                            base::Unretained(this)));
    if (!usb_vm_read_watcher_) {
      LOG(ERROR) << "Failed to switch to watching USB VM socket for reads";
    }
  }
}

// static
bool PluginVm::WriteResolvConf(const base::FilePath& parent_dir,
                               const std::vector<string>& nameservers,
                               const std::vector<string>& search_domains) {
  // Create temporary directory on the same file system so that we
  // can atomically replace old resolv.conf with new one.
  base::ScopedTempDir temp_dir;
  if (!temp_dir.CreateUniqueTempDirUnderPath(parent_dir)) {
    LOG(ERROR) << "Failed to create temporary directory under "
               << parent_dir.value();
    return false;
  }

  base::FilePath path = temp_dir.GetPath().Append("resolv.conf");
  base::File file(path, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  if (!file.IsValid()) {
    LOG(ERROR) << "Failed to create temporary file " << path.value();
    return false;
  }

  for (auto& ns : nameservers) {
    string nameserver_line = base::StringPrintf("nameserver %s\n", ns.c_str());
    if (!file.WriteAtCurrentPos(nameserver_line.c_str(),
                                nameserver_line.length())) {
      LOG(ERROR) << "Failed to write nameserver to temporary file";
      return false;
    }
  }

  if (!search_domains.empty()) {
    string search_domains_line = base::StringPrintf(
        "search %s\n", base::JoinString(search_domains, " ").c_str());
    if (!file.WriteAtCurrentPos(search_domains_line.c_str(),
                                search_domains_line.length())) {
      LOG(ERROR) << "Failed to write search domains to temporary file";
      return false;
    }
  }

  constexpr char kResolvConfOptions[] =
      "options single-request timeout:1 attempts:5\n";
  if (!file.WriteAtCurrentPos(kResolvConfOptions, strlen(kResolvConfOptions))) {
    LOG(ERROR) << "Failed to write search resolver options to temporary file";
    return false;
  }

  // This should flush the buffers.
  file.Close();

  base::File::Error err;
  if (!ReplaceFile(path, parent_dir.Append("resolv.conf"), &err)) {
    LOG(ERROR) << "Failed to replace resolv.conf with new instance: "
               << base::File::ErrorToString(err);
    return false;
  }

  return true;
}

bool PluginVm::SetResolvConfig(const std::vector<string>& nameservers,
                               const std::vector<string>& search_domains) {
  return WriteResolvConf(root_dir_.GetPath().Append("etc"), nameservers,
                         search_domains);
}

void PluginVm::VmToolsStateChanged(bool running) {
  LOG(INFO) << "Tools are " << (running ? "" : "not ")
            << "running in plugin VM";

  if (running)
    pvm::helper::CleanUpAfterInstall(id_, iso_dir_);
}

PluginVm::PluginVm(Config config)
    : VmBaseImpl(VmBaseImpl::Config{
          .network_client = std::move(config.network_client),
          .seneschal_server_proxy = std::move(config.seneschal_server_proxy),
          .runtime_dir = std::move(config.runtime_dir),
      }),
      id_(std::move(config.id)),
      iso_dir_(std::move(config.iso_dir)),
      bus_(std::move(config.bus)),
      vm_permission_service_proxy_(config.vm_permission_service_proxy),
      vmplugin_service_proxy_(config.vmplugin_service_proxy),
      usb_last_handle_(0) {
  CHECK(vm_permission_service_proxy_);
  CHECK(vmplugin_service_proxy_);
  CHECK(base::DirectoryExists(iso_dir_));
  CHECK(base::DirectoryExists(config.root_dir));

  // Take ownership of the root and runtime directories.
  CHECK(root_dir_.Set(config.root_dir));

  std::ostringstream oss;
  oss << id_;
  id_hash_ = std::hash<std::string>{}(oss.str());
}

bool PluginVm::Start(base::FilePath stateful_dir,
                     int subnet_index,
                     bool enable_vnet_hdr,
                     VmBuilder vm_builder) {
  if (!base::PathExists(base::FilePath(pvm::kApplicationDir))) {
    LOG(ERROR) << "PluginVM DLC is not installed.";
    return false;
  }

  // Register the VM with permission service and obtain permission
  // token.
  if (!vm_permission::RegisterVm(bus_, vm_permission_service_proxy_, id_,
                                 vm_permission::VmType::PLUGIN_VM,
                                 &permission_token_)) {
    LOG(ERROR) << "Failed to register with permission service";
    return false;
  }

  // Get the network interface.
  patchpanel::Client::VirtualDevice network_device;
  if (!network_client_->NotifyParallelsVmStartup(id_hash_, subnet_index,
                                                 &network_device)) {
    LOG(ERROR) << "No network devices available";
    return false;
  }
  subnet_ = MakeSubnet(network_device.ipv4_subnet);
  if (!subnet_) {
    LOG(ERROR) << "Failed to read IPv4 subnet assigned to VM";
    return false;
  }

  // Open the tap device.
  base::ScopedFD tap_fd = OpenTapDevice(network_device.ifname, enable_vnet_hdr,
                                        nullptr /*ifname_out*/);
  if (!tap_fd.is_valid()) {
    LOG(ERROR) << "Unable to open and configure TAP device "
               << network_device.ifname;
    return false;
  }

  auto plugin_bin_path =
      base::FilePath(pvm::kApplicationDir).Append(pvm::plugin::kCommand);
  auto plugin_policy_dir =
      base::FilePath(pvm::kApplicationDir).Append(pvm::plugin::kPolicyDir);
  vm_builder.AppendTapFd(std::move(tap_fd))
      .AppendCustomParam("--plugin", plugin_bin_path.value())
      .AppendCustomParam("--seccomp-policy-dir", plugin_policy_dir.value())
      .AppendCustomParam("--plugin-gid-map-file",
                         plugin_bin_path.AddExtension("gid_maps").value());

  // These are bind mounts with parts may change (i.e. they are either VM
  // or config specific).
  std::vector<string> bind_mounts = {
      // This is directory where the VM image resides.
      base::StringPrintf("%s:%s:true", stateful_dir.value().c_str(),
                         pvm::plugin::kStatefulDir),
      // This is directory where ISO images for the VM reside.
      base::StringPrintf("%s:%s:false", iso_dir_.value().c_str(),
                         pvm::plugin::kIsoDir),
      // This is directory where control socket, 9p socket, and other axillary
      // runtime data lives.
      base::StringPrintf("%s:%s:true", runtime_dir_.GetPath().value().c_str(),
                         pvm::kRuntimeDir),
      // Plugin '/etc' directory.
      base::StringPrintf("%s:%s:true",
                         root_dir_.GetPath().Append("etc").value().c_str(),
                         "/etc"),
  };

  if (vm_permission::IsCameraEnabled(bus_, vm_permission_service_proxy_,
                                     permission_token_)) {
    LOG(INFO) << "VM " << id_ << ": camera access enabled";
    bind_mounts.push_back("/run/camera:/run/camera:true");
  } else {
    LOG(INFO) << "VM " << id_ << ": camera access disabled";
  }

  if (vm_permission::IsMicrophoneEnabled(bus_, vm_permission_service_proxy_,
                                         permission_token_)) {
    LOG(INFO) << "VM " << id_ << ": microphone access enabled";
    bind_mounts.push_back("/run/cras/plugin/unified:/run/cras:true");
  } else {
    LOG(INFO) << "VM " << id_ << ": microphone access disabled";
    bind_mounts.push_back("/run/cras/plugin/playback:/run/cras:true");
  }

  // Mount application files into jail, firs the DLC path, then the static
  // path that Parallels uses to locate their components.
  bind_mounts.push_back(base::StringPrintf("%s:%s:false", pvm::kApplicationDir,
                                           pvm::kApplicationDir));
  bind_mounts.push_back(base::StringPrintf("%s:%s:false", pvm::kApplicationDir,
                                           pvm::plugin::kPitaDir));

  for (auto& mount : bind_mounts)
    vm_builder.AppendCustomParam("--plugin-mount", std::move(mount));

  // Because some of the static paths are mounted in /run/pvm... in the
  // plugin jail, they have to come after the dynamic paths above.
  vm_builder.AppendCustomParam(
      "--plugin-mount-file",
      plugin_bin_path.AddExtension("bind_mounts").value());

  // Change the process group before exec so that crosvm sending SIGKILL to
  // the whole process group doesn't kill us as well. The function also
  // changes the cpu cgroup for PluginVm crosvm processes.
  process_.SetPreExecCallback(base::BindOnce(
      &SetUpCrosvmProcess, base::FilePath(kPluginVmCpuCgroup).Append("tasks")));

  if (!StartProcess(vm_builder.BuildVmArgs())) {
    LOG(ERROR) << "Failed to start VM process";
    return false;
  }

  return true;
}

}  // namespace concierge
}  // namespace vm_tools
