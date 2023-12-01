// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cups_proxy/daemon.h"

#include <stdlib.h>
#include <sysexits.h>

#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <mojo/core/embedder/embedder.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

namespace cups_proxy {

namespace {

constexpr char kCupsProxySocketPath[] = "/run/cups_proxy/cups.sock";

base::ScopedFD InitSocket() {
  base::ScopedFD fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to create socket";
    return {};
  }

  struct sockaddr_un unix_addr = {};
  base::FilePath socket_path(kCupsProxySocketPath);
  std::string socket_name = socket_path.value();

  unix_addr.sun_family = AF_UNIX;
  CHECK(socket_name.size() < sizeof(unix_addr.sun_path));
  strncpy(unix_addr.sun_path, socket_name.c_str(), socket_name.size());
  size_t unix_addr_len =
      offsetof(struct sockaddr_un, sun_path) + socket_name.size();

  // Delete any old FS instances.
  if (unlink(socket_name.c_str()) < 0 && errno != ENOENT) {
    PLOG(ERROR) << "unlink " << socket_name;
    return {};
  }

  // Bind the socket.
  if (bind(fd.get(), reinterpret_cast<const sockaddr*>(&unix_addr),
           unix_addr_len) < 0) {
    PLOG(ERROR) << "bind " << socket_path.value();
    return {};
  }

  // Sets the correct socket permissions.
  if (chmod(socket_name.c_str(), 0660) < 0) {
    PLOG(ERROR) << "Failed to set permissions";
    unlink(socket_name.c_str());
    return {};
  }

  // Start listening on the socket.
  if (listen(fd.get(), SOMAXCONN) < 0) {
    PLOG(ERROR) << "listen " << socket_path.value();
    unlink(socket_name.c_str());
    return {};
  }

  return fd;
}

}  // namespace

Daemon::Daemon() : weak_ptr_factory_(this) {}

Daemon::~Daemon() {}

int Daemon::OnInit() {
  int exit_code = DBusDaemon::OnInit();
  if (exit_code != EX_OK)
    return exit_code;

  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

  CHECK(mojo_handler_.CreateTaskRunner());

  InitDBus();

  base::ScopedFD listen_fd = InitSocket();
  if (!listen_fd.is_valid()) {
    LOG(ERROR) << "Error initializing unix listen socket.";
    return EX_UNAVAILABLE;
  }

  mhd_daemon_ = StartMHDDaemon(std::move(listen_fd), &mojo_handler_);
  if (!mhd_daemon_) {
    LOG(ERROR) << "Error initializing MHD daemon.";
    return EX_UNAVAILABLE;
  }

  return EX_OK;
}

void Daemon::InitDBus() {
  LOG(INFO) << "Registering as handler for CupsProxyDaemon in D-Bus ...";

  // Get or create the ExportedObject for the CupsProxyDaemon
  dbus::ExportedObject* const cups_proxy_exported_object =
      bus_->GetExportedObject(dbus::ObjectPath(printing::kCupsProxyDaemonPath));
  CHECK(cups_proxy_exported_object);

  // Register a handler of the BootstrapMojoConnection method.
  CHECK(cups_proxy_exported_object->ExportMethodAndBlock(
      printing::kCupsProxyDaemonInterface,
      printing::kBootstrapMojoConnectionMethod,
      base::BindRepeating(&Daemon::BootstrapMojoConnection,
                          weak_ptr_factory_.GetWeakPtr())));

  // Take ownership of the CupsProxy service.
  CHECK(bus_->RequestOwnershipAndBlock(printing::kCupsProxyDaemonName,
                                       dbus::Bus::REQUIRE_PRIMARY));
}

void Daemon::BootstrapMojoConnection(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  if (mojo_handler_.IsInitialized()) {
    LOG(ERROR) << "CupsProxyService already initialized";
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_FAILED, "Bootstrap already completed"));
    return;
  }

  base::ScopedFD file_handle;
  dbus::MessageReader reader(method_call);

  if (!reader.PopFileDescriptor(&file_handle)) {
    LOG(ERROR) << "Couldn't extract file descriptor from D-Bus call";
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS, "Expected file descriptor"));
    return;
  }

  if (!file_handle.is_valid()) {
    LOG(ERROR) << "ScopedFD extracted from D-Bus call was invalid (i.e. empty)";
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS,
            "Invalid (empty) file descriptor"));
    return;
  }

  if (!base::SetCloseOnExec(file_handle.get())) {
    PLOG(ERROR) << "Failed setting FD_CLOEXEC on file descriptor";
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_FAILED,
            "Failed setting FD_CLOEXEC on file descriptor"));
    return;
  }

  // Connect to mojo in the requesting process.
  mojo_handler_.SetupMojoPipe(
      std::move(file_handle),
      base::BindOnce(&Daemon::OnConnectionError, base::Unretained(this)));

  // Send success response.
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void Daemon::OnConnectionError() {
  // Die upon Mojo error. Reconnection can occur when the daemon is restarted.
  // (A future Mojo API may enable Mojo re-bootstrap without a process restart.)
  LOG(ERROR) << "CupsProxyDaemon MojoConnectionError; quitting.";
  quick_exit(0);
}

}  // namespace cups_proxy
