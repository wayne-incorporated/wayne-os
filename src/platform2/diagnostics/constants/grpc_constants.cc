// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/constants/grpc_constants.h"

#include <sys/socket.h>
// Needs to come after sys/socket.h.
#include <linux/vm_sockets.h>  // NOLINT(build/include_alpha)

#include <base/strings/stringprintf.h>

namespace {

// Helper function to format and create a vsock URI given a context id |cid| and
// |port|.
std::string CreateVsockUri(unsigned int cid, unsigned int port) {
  return base::StringPrintf("vsock:%u:%u", cid, port);
}

}  // namespace

namespace diagnostics {

// Context ID for Wilco DTC VM. Must match the CID parameter given to crosvm in
// wilco_dtc.conf
constexpr int kWilcoDtcVmCid = 512;

// Vsock port numbers must be larger than the reserved ports 1024 and must not
// conflict with the port numbers defined in vm_tools/common/constants.h

// Port on which the wilco_dtc_supportd is listening on the host.
constexpr int kWilcoDtcSupportdPort = 6666;
// Port on which the wilco_dtc is listening in the guest VM.
constexpr int kWilcoDtcPort = 6667;
// Port on which the wilco_dtc VM is listening in the guest VM that is eligeble
// to receive UI messages.
constexpr int kUiMessageReceiverWilcoDtcPort = 6668;

const char kWilcoDtcSupportdGrpcDomainSocketUri[] =
    "unix:/run/wilco_dtc/grpc_sockets/wilco_dtc_supportd_socket";

std::string GetWilcoDtcSupportdGrpcHostVsockUri() {
  return CreateVsockUri(VMADDR_CID_ANY, kWilcoDtcSupportdPort);
}

std::string GetWilcoDtcSupportdGrpcGuestVsockUri() {
  return CreateVsockUri(VMADDR_CID_HOST, kWilcoDtcSupportdPort);
}

std::string GetWilcoDtcGrpcHostVsockUri() {
  return CreateVsockUri(kWilcoDtcVmCid, kWilcoDtcPort);
}

std::string GetWilcoDtcGrpcGuestVsockUri() {
  return CreateVsockUri(VMADDR_CID_ANY, kWilcoDtcPort);
}

std::string GetUiMessageReceiverWilcoDtcGrpcHostVsockUri() {
  return CreateVsockUri(kWilcoDtcVmCid, kUiMessageReceiverWilcoDtcPort);
}

std::string GetUiMessageReceiverWilcoDtcGrpcGuestVsockUri() {
  return CreateVsockUri(VMADDR_CID_ANY, kUiMessageReceiverWilcoDtcPort);
}

}  // namespace diagnostics
