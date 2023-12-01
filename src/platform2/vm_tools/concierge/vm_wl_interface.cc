// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vm_wl_interface.h"

#include <memory>
#include <string>
#include <utility>

#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/dbus/dbus_proxy_util.h>
#include <chromeos/dbus/vm_wl/dbus-constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <dbus/scoped_dbus_error.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <vm_wl/wl.pb.h>

#include "base/check.h"
#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/callback_helpers.h"
#include "vm_tools/common/vm_id.h"
#include "vm_tools/concierge/vm_util.h"

namespace vm_tools::concierge {

namespace {

// When binding unix sockets, the address must fit into the sun_path field.
constexpr size_t kAddressMaxLength = sizeof(sockaddr_un().sun_path);

dbus::ObjectProxy* GetVmWlProxy(dbus::Bus* bus) {
  // The bus owns all the Proxy objects, so it is sufficient to just re-request
  // a handle as-needed.
  return bus->GetObjectProxy(wl::kVmWlServiceName,
                             dbus::ObjectPath(wl::kVmWlServicePath));
}

base::FilePath GetSocketPath(const base::ScopedTempDir& socket_dir) {
  return socket_dir.GetPath().Append("wayland-0");
}

}  // namespace

ScopedWlSocket::~ScopedWlSocket() {
  wl::CloseSocketRequest request;
  *request.mutable_desc() = description_;
  dbus::MethodCall method_call(wl::kVmWlServiceInterface,
                               wl::kVmWlServiceCloseSocketMethod);
  dbus::MessageWriter writer(&method_call);
  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode request when removing socket: "
               << socket_fd_.get() << " for vm: " << description_.name();
    return;
  }

  GetVmWlProxy(bus_.get())
      ->CallMethodWithErrorCallback(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
          base::DoNothing(), base::BindOnce([](dbus::ErrorResponse* err) {
            // Failing to close the server is not critical, so just log an
            // error. This probably can only happen during shutdown anyway.
            LOG(ERROR) << "Failed to clean up socket: " << err->GetErrorName()
                       << " - " << err->GetMember();
          }));
}

base::FilePath ScopedWlSocket::GetPath() const {
  return GetSocketPath(socket_dir_);
}

ScopedWlSocket::ScopedWlSocket(base::ScopedTempDir socket_dir,
                               base::ScopedFD socket_fd,
                               scoped_refptr<dbus::Bus> bus,
                               wl::VmDescription description)
    : socket_dir_(std::move(socket_dir)),
      socket_fd_(std::move(socket_fd)),
      bus_(bus),
      description_(std::move(description)) {}

// static
VmWlInterface::Result VmWlInterface::CreateWaylandServer(
    scoped_refptr<dbus::Bus> bus,
    const VmId& vm_id,
    VmId::Type classification) {
  // Create a temp dir where the socket will live, this makes cleanup easy.
  base::ScopedTempDir socket_dir;
  if (!socket_dir.CreateUniqueTempDir()) {
    return base::unexpected("Failed to create directory");
  }

  // Create a socket for the server.
  int raw_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (raw_socket_fd == -1) {
    return base::unexpected(std::string("Failed to create socket: ") +
                            strerror(errno));
  }
  base::ScopedFD socket_fd(raw_socket_fd);

  // Bind() the server, so that we can listen/connect to it later.
  struct sockaddr_un addr;
  std::string socket_path = GetSocketPath(socket_dir).value();
  CHECK(!socket_path.empty());
  // The path (and '\0') needs to fit inside the address.
  CHECK_LT(socket_path.length() + 1, kAddressMaxLength);
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path.c_str(), kAddressMaxLength);
  if (HANDLE_EINTR(bind(socket_fd.get(),
                        reinterpret_cast<struct sockaddr*>(&addr),
                        sizeof(addr))) != 0) {
    return base::unexpected(std::string("Failed to create socket: ") +
                            strerror(errno));
  }

  // Prepare the dbus request to turn the socket into a wayland server.
  wl::ListenOnSocketRequest request;
  request.mutable_desc()->set_name(vm_id.name());
  request.mutable_desc()->set_owner_id(vm_id.owner_id());
  request.mutable_desc()->set_type(classification);
  dbus::MethodCall method_call(wl::kVmWlServiceInterface,
                               wl::kVmWlServiveListenOnSocketMethod);
  dbus::MessageWriter writer(&method_call);
  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    return base::unexpected("Failed to encode ListenOnSocketRequest protobuf");
  }
  writer.AppendFileDescriptor(socket_fd.get());

  dbus::ScopedDBusError dbus_error;
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethodWithErrorResponse(
          bus, GetVmWlProxy(bus.get()), &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &dbus_error);
  if (!dbus_response) {
    if (dbus_error.is_set()) {
      return base::unexpected(std::string("ListenOnSocket call failed: ") +
                              dbus_error.name() + " (" + dbus_error.message() +
                              ")");
    } else {
      return base::unexpected(
          "Failed to send ListenOnSocket message to vm_wl service");
    }
  }

  // WrapUnique is necessary since ScopedWlSocket has a private constructor.
  return base::WrapUnique(new ScopedWlSocket(
      std::move(socket_dir), std::move(socket_fd), bus, request.desc()));
}

}  // namespace vm_tools::concierge
