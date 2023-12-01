// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/adb_proxy.h"

#include <linux/vm_sockets.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sysexits.h>

#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/key_value_store.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <vboot/crossystem.h>
#include <net-base/ipv4_address.h>

#include "patchpanel/ipc.h"
#include "patchpanel/message_dispatcher.h"
#include "patchpanel/minijailed_process_runner.h"
#include "patchpanel/patchpanel_daemon.h"

namespace patchpanel {
namespace {
// adb-proxy will connect to adbd on its standard TCP port.
constexpr uint16_t kTcpConnectPort = 5555;
constexpr net_base::IPv4Address kTcpAddr(100, 115, 92, 2);
constexpr uint32_t kVsockPort = 5555;
constexpr int kMaxConn = 16;
// Reference: "device/google/cheets2/init.usb.rc".
constexpr char kUnixConnectAddr[] = "/run/arc/adb/adb.sock";
constexpr int kDbusTimeoutMs = 200;
// The maximum number of ADB sideloading query failures before stopping.
constexpr int kAdbSideloadMaxTry = 5;
constexpr base::TimeDelta kAdbSideloadUpdateDelay = base::Milliseconds(5000);

const std::set<GuestMessage::GuestType> kArcGuestTypes{GuestMessage::ARC,
                                                       GuestMessage::ARC_VM};

bool IsDevModeEnabled() {
  return VbGetSystemPropertyInt("cros_debug") == 1;
}
}  // namespace

AdbProxy::AdbProxy(base::ScopedFD control_fd)
    : msg_dispatcher_(std::move(control_fd)),
      arc_type_(GuestMessage::UNKNOWN_GUEST),
      arcvm_vsock_cid_(std::nullopt) {
  msg_dispatcher_.RegisterFailureHandler(base::BindRepeating(
      &AdbProxy::OnParentProcessExit, weak_factory_.GetWeakPtr()));

  msg_dispatcher_.RegisterMessageHandler(base::BindRepeating(
      &AdbProxy::OnGuestMessage, weak_factory_.GetWeakPtr()));
}

AdbProxy::~AdbProxy() = default;

int AdbProxy::OnInit() {
  // Prevent the main process from sending us any signals.
  if (setsid() < 0) {
    PLOG(ERROR) << "Failed to created a new session with setsid; exiting";
    return EX_OSERR;
  }
  EnterChildProcessJail();
  // Run after DBusDaemon::OnInit().
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&AdbProxy::InitialSetup, weak_factory_.GetWeakPtr()));
  return DBusDaemon::OnInit();
}

void AdbProxy::InitialSetup() {
  dev_mode_enabled_ = IsDevModeEnabled();
  if (dev_mode_enabled_) {
    return;
  }
  CheckAdbSideloadingStatus(/*num_try=*/0);
}

void AdbProxy::Reset() {
  src_watcher_.reset();
  src_.reset();
  fwd_.clear();
  arcvm_vsock_cid_ = std::nullopt;
  arc_type_ = GuestMessage::UNKNOWN_GUEST;
}

void AdbProxy::OnFileCanReadWithoutBlocking() {
  struct sockaddr_storage client_src = {};
  socklen_t sockaddr_len = sizeof(client_src);
  if (auto client_conn =
          src_->Accept((struct sockaddr*)&client_src, &sockaddr_len)) {
    LOG(INFO) << "new adb connection from " << client_src;
    if (auto adbd_conn = Connect()) {
      auto fwd = std::make_unique<SocketForwarder>(
          base::StringPrintf("adbp%d-%d", client_conn->fd(), adbd_conn->fd()),
          std::move(client_conn), std::move(adbd_conn));
      fwd->Start();
      fwd_.emplace_back(std::move(fwd));
    }
  } else {
    PLOG(ERROR) << "Failed to accept incoming adb connection";
  }

  // Cleanup any defunct forwarders.
  for (auto it = fwd_.begin(); it != fwd_.end();) {
    if (!(*it)->IsRunning() && (*it)->HasBeenStarted())
      it = fwd_.erase(it);
    else
      ++it;
  }
}

std::unique_ptr<Socket> AdbProxy::Connect() const {
  switch (arc_type_) {
    case GuestMessage::ARC: {
      struct sockaddr_un addr_un = {0};
      addr_un.sun_family = AF_UNIX;
      snprintf(addr_un.sun_path, sizeof(addr_un.sun_path), "%s",
               kUnixConnectAddr);
      auto dst = std::make_unique<Socket>(AF_UNIX, SOCK_STREAM);
      if (!dst->is_valid()) {
        PLOG(ERROR) << "Failed to create UNIX domain socket";
        return nullptr;
      }
      if (dst->Connect((const struct sockaddr*)&addr_un, sizeof(addr_un))) {
        LOG(INFO) << "Established adbd connection to " << addr_un;
        return dst;
      }
      PLOG(WARNING) << "Failed to connect UNIX domain socket to adbd: "
                    << kUnixConnectAddr << " - falling back to TCP";
      break;
    }
    case GuestMessage::ARC_VM: {
      if (!arcvm_vsock_cid_.has_value()) {
        LOG(ERROR) << "Undefined ARCVM CID";
        return nullptr;
      }
      struct sockaddr_vm addr_vm = {0};
      addr_vm.svm_family = AF_VSOCK;
      addr_vm.svm_port = kVsockPort;
      addr_vm.svm_cid = arcvm_vsock_cid_.value();
      auto dst = std::make_unique<Socket>(AF_VSOCK, SOCK_STREAM);
      if (!dst->is_valid()) {
        PLOG(ERROR) << "Failed to create VSOCK socket";
        return nullptr;
      }
      if (dst->Connect((const struct sockaddr*)&addr_vm, sizeof(addr_vm))) {
        LOG(INFO) << "Established adbd connection to " << addr_vm;
        return dst;
      }
      PLOG(WARNING) << "Failed to connect VSOCK socket to adbd at " << addr_vm
                    << " - falling back to TCP";
      break;
    }
    default:
      LOG(DFATAL) << "Unexpected ARC guest type";
      return nullptr;
  }

  // Fallback to TCP.
  struct sockaddr_in addr_in = {0};
  addr_in.sin_family = AF_INET;
  addr_in.sin_port = htons(kTcpConnectPort);
  addr_in.sin_addr = kTcpAddr.ToInAddr();
  auto dst = std::make_unique<Socket>(AF_INET, SOCK_STREAM);
  if (!dst->is_valid()) {
    PLOG(ERROR) << "Failed to create TCP socket";
    return nullptr;
  }
  if (dst->Connect((const struct sockaddr*)&addr_in, sizeof(addr_in))) {
    LOG(INFO) << "Established adbd connection to " << addr_in;
    return dst;
  }
  PLOG(ERROR) << "Failed to connect TCP socket to adbd at " << addr_in;
  return nullptr;
}

void AdbProxy::OnParentProcessExit() {
  LOG(ERROR) << "Quitting because the parent process died";
  Reset();
  Quit();
}

void AdbProxy::OnGuestMessage(const SubprocessMessage& root_msg) {
  if (!root_msg.has_control_message()) {
    LOG(ERROR) << "Unexpected message type";
    return;
  }
  if (!root_msg.control_message().has_guest_message()) {
    return;
  }
  const GuestMessage& msg = root_msg.control_message().guest_message();
  if (msg.type() == GuestMessage::UNKNOWN_GUEST) {
    LOG(DFATAL) << "Unexpected message from unknown guest";
    return;
  }

  if (kArcGuestTypes.find(msg.type()) == kArcGuestTypes.end()) {
    return;
  }

  // On ARC down, cull any open connections and stop listening.
  if (msg.event() == GuestMessage::STOP) {
    if (msg.type() == GuestMessage::ARC_VM && !arcvm_vsock_cid_.has_value()) {
      LOG(WARNING)
          << "Received STOP message for ARC_VM but ARCVM CID was undefined";
      return;
    }
    // The stop message for ARCVM may be sent after a new VM is started. Only
    // stop if the CID matched the latest started ARCVM CID.
    if (msg.type() == GuestMessage::ARC_VM &&
        msg.arcvm_vsock_cid() != arcvm_vsock_cid_.value()) {
      LOG(WARNING) << "Mismatched ARCVM CIDs " << arcvm_vsock_cid_.value()
                   << " != " << msg.arcvm_vsock_cid();
      return;
    }
    Reset();
    return;
  }

  arc_type_ = msg.type();
  arcvm_vsock_cid_ = msg.arcvm_vsock_cid();

  // On ARC up, start accepting connections.
  if (msg.event() == GuestMessage::START) {
    Listen();
  }
}

void AdbProxy::Listen() {
  // Only start listening on either developer mode or sideloading on.
  if (!dev_mode_enabled_ && !adb_sideloading_enabled_) {
    return;
  }
  // ADB proxy is already listening.
  if (src_) {
    return;
  }
  // Listen on IPv4 and IPv6. Listening on AF_INET explicitly is not needed
  // because net.ipv6.bindv6only sysctl is defaulted to 0 and is not
  // explicitly turned on in the codebase.
  std::unique_ptr<Socket> src =
      std::make_unique<Socket>(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK);
  if (!src->is_valid()) {
    PLOG(ERROR) << "Failed to created TCP listening socket";
    return;
  }
  // Need to set this to reuse the port.
  int on = 1;
  if (setsockopt(src->fd(), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0) {
    PLOG(ERROR) << "setsockopt(SO_REUSEADDR) failed";
    return;
  }
  struct sockaddr_in6 addr = {0};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(kAdbProxyTcpListenPort);
  addr.sin6_addr = in6addr_any;
  if (!src->Bind((const struct sockaddr*)&addr, sizeof(addr))) {
    LOG(ERROR) << "Cannot bind source socket to " << addr;
    return;
  }

  if (!src->Listen(kMaxConn)) {
    LOG(ERROR) << "Cannot listen on " << addr;
    return;
  }

  src_ = std::move(src);

  // Run the accept loop.
  LOG(INFO) << "Accepting connections on " << addr;
  src_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      src_->fd(), base::BindRepeating(&AdbProxy::OnFileCanReadWithoutBlocking,
                                      base::Unretained(this)));
  return;
}

void AdbProxy::CheckAdbSideloadingStatus(int num_try) {
  if (num_try >= kAdbSideloadMaxTry) {
    LOG(WARNING) << "Failed to get ADB sideloading status after " << num_try
                 << " tries. ADB sideloading will not work";
    return;
  }

  dbus::ObjectProxy* proxy = bus_->GetObjectProxy(
      login_manager::kSessionManagerServiceName,
      dbus::ObjectPath(login_manager::kSessionManagerServicePath));
  dbus::MethodCall method_call(login_manager::kSessionManagerInterface,
                               login_manager::kSessionManagerQueryAdbSideload);
  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDbusTimeoutMs);

  if (!dbus_response) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&AdbProxy::CheckAdbSideloadingStatus,
                       weak_factory_.GetWeakPtr(), num_try + 1),
        kAdbSideloadUpdateDelay);
    return;
  }

  dbus::MessageReader reader(dbus_response.get());
  reader.PopBool(&adb_sideloading_enabled_);
  if (!adb_sideloading_enabled_) {
    LOG(INFO) << "Chrome OS is not in developer mode and ADB sideloading is "
                 "not enabled. ADB proxy is not listening";
    return;
  }

  // If ADB sideloading is enabled and ARC guest is started, start listening.
  if (arc_type_ != GuestMessage::UNKNOWN_GUEST) {
    Listen();
  }
}

}  // namespace patchpanel
