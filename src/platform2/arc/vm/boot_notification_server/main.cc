// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <linux/vm_sockets.h>

#include <optional>
#include <tuple>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <brillo/files/file_util.h>
#include <brillo/syslog_logging.h>

#include "arc/vm/boot_notification_server/util.h"

// Port that the server listens on
constexpr unsigned int kVsockPort = 5500;
// Location of host-side UDS
constexpr char kHostSocketPath[] =
    "/run/arcvm_boot_notification_server/host.socket";
// Command that signals to client that /data is ready
constexpr char kDataReadyCommand[] = "DATA_READY";

int main(int argc, const char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::OpenLog(base::CommandLine::ForCurrentProcess()
                      ->GetProgram()
                      .BaseName()
                      .value()
                      .c_str(),
                  true /* log_pid */);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  // Listen for connection from ARCVM.
  sockaddr_vm vm_addr{.svm_family = AF_VSOCK,
                      .svm_port = kVsockPort,
                      .svm_cid = VMADDR_CID_HOST};
  base::ScopedFD vm_fd = StartListening(reinterpret_cast<sockaddr*>(&vm_addr));

  if (!vm_fd.is_valid())
    return -1;

  // Delete host socket path if it exists.
  if (!brillo::DeleteFile(base::FilePath(kHostSocketPath)))
    LOG(FATAL) << "Unable to delete pre-existing socket at " << kHostSocketPath;

  // Listen for connection from host/Chrome. Chrome expects that by the time it
  // connects to this server, we are already listening for connections from
  // ARCVM as well. Thus, we must listen on the VSOCK before listening on the
  // Unix socket.
  sockaddr_un host_addr{.sun_family = AF_UNIX};
  memcpy(host_addr.sun_path, kHostSocketPath, sizeof(kHostSocketPath));
  base::ScopedFD host_fd =
      StartListening(reinterpret_cast<sockaddr*>(&host_addr));
  if (!host_fd.is_valid())
    return -1;

  // Allow access to socket.
  if (!base::SetPosixFilePermissions(base::FilePath(kHostSocketPath), 0720))
    LOG(FATAL) << "Unable to chmod " << kHostSocketPath;

  // Chrome will connect first to check that the server is listening, without
  // sending anything.
  {
    base::ScopedFD conn = WaitForClientConnect(host_fd.get());
    if (!conn.is_valid())
      LOG(FATAL) << "Unable to accept connection from host";
  }

  // Receive props from Chrome.
  base::ScopedFD host_client = WaitForClientConnect(host_fd.get());
  if (!host_client.is_valid())
    LOG(FATAL) << "Unable to accept connection from host";

  std::optional<std::string> props = ReadFD(host_client.get());
  if (!props)
    LOG(FATAL) << "Did not receive props from host";

  LOG(INFO) << "Received " << *props << " from host.";

  std::optional<std::pair<unsigned int, std::string>> extracted =
      ExtractCidValue(*props);
  if (!extracted)
    LOG(FATAL) << "The received props did not contain 'CID=<CID>' line";

  unsigned int expected_cid;
  std::string send_props;
  std::tie(expected_cid, send_props) = *extracted;
  LOG(INFO) << "Waiting for connection from ARCVM(" << expected_cid << ").";

  // Accept connection from ARCVM, then send DATA_READY followed by props.
  // It is possible, in the case of a Chrome crash or restart during early boot,
  // that a previous VM client will connect before the current VM client (see
  // b/188450841). To handle this, keep accept()ing connections until we the CID
  // of the connected peer matches the expected CID sent from Chrome.
  while (true) {
    base::ScopedFD vm_client = WaitForClientConnect(vm_fd.get());
    if (!vm_client.is_valid()) {
      LOG(ERROR) << "Unable to accept() connection from guest; retrying.";
      continue;
    }

    // Ignore connection if the CID of connection peer is not what we expect.
    std::optional<unsigned int> peer_cid = GetPeerCid(vm_client.get());
    if (!peer_cid) {
      LOG(ERROR) << "Unable to get CID of VM client connection.";
      continue;
    }

    if (expected_cid != *peer_cid) {
      LOG(ERROR) << "Received connection from ARCVM(" << *peer_cid
                 << "), expected connection from ARCVM(" << expected_cid
                 << "); retrying.";
      continue;
    }

    LOG(INFO) << "Sending " << kDataReadyCommand << " to ARCVM(" << *peer_cid
              << ").";
    if (!base::WriteFileDescriptor(vm_client.get(), kDataReadyCommand)) {
      PLOG(FATAL) << "Unable to send " << kDataReadyCommand << " to client.";
    }
    if (!base::WriteFileDescriptor(vm_client.get(), send_props)) {
      PLOG(FATAL) << "Unable to send props to client";
    }
    break;
  }

  return 0;
}
