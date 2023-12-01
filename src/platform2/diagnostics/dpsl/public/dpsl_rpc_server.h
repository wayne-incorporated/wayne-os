// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_PUBLIC_DPSL_RPC_SERVER_H_
#define DIAGNOSTICS_DPSL_PUBLIC_DPSL_RPC_SERVER_H_

#include <memory>

namespace diagnostics {

class DpslRpcHandler;
class DpslThreadContext;

// Interface of the class that runs a gRPC server listening on the specified
// URI. All incoming gRPC requests are passed to the given DpslRpcHandler
// instance.
//
// Obtain an instance of this class via the Create() method. For hints on usage,
// see dpsl_rpc_handler.h.
//
// NOTE ON THREADING MODEL: This class is NOT thread-safe. This instance must be
// destroyed on the same thread on which it was created. The DPSL itself
// guarantees that it will run methods of the given DpslRpcHandler instance on
// that same thread too.
//
// PRECONDITIONS:
// 1. An instance of DpslThreadContext must exist on the current thread during
//    the whole lifetime of this object.
class DpslRpcServer {
 public:
  // Specifies predefined options for the URI on which the started gRPC server
  // should be listening. Only one server with each URI may run at a time;
  // breaking this requirement will lead to unspecified behavior.
  enum class GrpcServerUri {
    // A vsock URI for communicating across the VM boundary. This option is
    // available only when running INSIDE a VM.
    kVmVsock = 0,
    // A vsock URI for communicating across the VM boundary. This option is
    // available only when running INSIDE a VM. A server is eligible to
    // receive EC notifications and messages from UI extension (hosted by
    // browser). No other server is eligible to receive UI messages.
    kUiMessageReceiverVmVsock = 1,
  };

  // Factory method that returns an instance of the real implementation of this
  // interface.
  //
  // Returns a null pointer when the server startup fails (for example, when the
  // specified gRPC URI is unavailable).
  //
  // Both |thread_context| and |rpc_handler| are passed as unowned pointers;
  // they must outlive the created DpslRpcServer instance.
  static std::unique_ptr<DpslRpcServer> Create(
      DpslThreadContext* thread_context,
      DpslRpcHandler* rpc_handler,
      GrpcServerUri grpc_server_uri);

  virtual ~DpslRpcServer() = default;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_PUBLIC_DPSL_RPC_SERVER_H_
