// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CONSTANTS_GRPC_CONSTANTS_H_
#define DIAGNOSTICS_CONSTANTS_GRPC_CONSTANTS_H_

#include <string>

namespace diagnostics {

// URI on which the gRPC interface exposed by the wilco_dtc_supportd daemon is
// listening on a unix socket.
extern const char kWilcoDtcSupportdGrpcDomainSocketUri[];

// URI on which the gRPC interface is exposed by wilco_dtc_supportd daemon is
// listening on a vsock socket. To be used by the host.
std::string GetWilcoDtcSupportdGrpcHostVsockUri();

// URI for connecting to the gRPC interface exposed by the wilco_dtc_supportd
// daemon over a vsock socket. To be used by the guest VM.
std::string GetWilcoDtcSupportdGrpcGuestVsockUri();

// URI for connecting to the gRPC interface exposed by wilco_dtc VM
// over a vsock socket. To be used by the host.
std::string GetWilcoDtcGrpcHostVsockUri();

// URI on which the gRPC interface is exposed by the wilco_dtc VM is
// listening on a vsock socket. To be used by the guest VM.
std::string GetWilcoDtcGrpcGuestVsockUri();

// URI for connecting to the UI Receiver gRPC interface exposed by wilco_dtc VM
// over a vsock socket. To be used by the host.
std::string GetUiMessageReceiverWilcoDtcGrpcHostVsockUri();

// URI on which the gRPC interface is exposed by the wilco_dtc VM is
// listening on a vsock socket. To be used by the guest VM.
std::string GetUiMessageReceiverWilcoDtcGrpcGuestVsockUri();

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CONSTANTS_GRPC_CONSTANTS_H_
