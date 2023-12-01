// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_GRPC_CLIENT_MANAGER_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_GRPC_CLIENT_MANAGER_H_

#include <base/functional/callback_forward.h>
#include <brillo/grpc/async_grpc_client.h>

#include <memory>
#include <string>
#include <vector>

#include "wilco_dtc.grpc.pb.h"  // NOLINT(build/include_directory)

namespace diagnostics {
namespace wilco {

class GrpcClientManager final {
 public:
  GrpcClientManager();
  GrpcClientManager(const GrpcClientManager&) = delete;
  GrpcClientManager& operator=(const GrpcClientManager&) = delete;
  ~GrpcClientManager();

  // Starts gRPC clients.
  // |ui_message_receiver_wilco_dtc_grpc_uri| is the URI which is
  // used for making requests to the gRPC interface exposed by the
  // wilco_dtc daemon which is explicitly eligible to receive
  // messages from UI extension (hosted by browser), no other gRPC client
  // receives messages from UI extension.
  // |wilco_dtc_grpc_client_uris| is the list of URI's which are used for
  // making requests to the gRPC interface exposed by the wilco_dtc
  // daemons. Should not contain the URI equal to
  // |ui_message_receiver_wilco_dtc_grpc_uri|.
  void Start(const std::string& ui_message_receiver_wilco_dtc_grpc_uri,
             const std::vector<std::string>& wilco_dtc_grpc_client_uris);

  // Performs asynchronous shutdown and cleanup of gRPC clients.
  // This must be used before deleting this instance in case Start() was
  // called.
  void ShutDown(base::OnceClosure on_shutdown_callback);

  // Returns a pointer to the ui client
  brillo::AsyncGrpcClient<grpc_api::WilcoDtc>* GetUiClient() const;

  // Returns a reference the managed grpc clients
  const std::vector<
      std::unique_ptr<brillo::AsyncGrpcClient<grpc_api::WilcoDtc>>>&
  GetClients() const;

 private:
  // Allows to make outgoing requests to the gRPC interfaces exposed by the
  // wilco_dtc daemons.
  std::vector<std::unique_ptr<brillo::AsyncGrpcClient<grpc_api::WilcoDtc>>>
      wilco_dtc_grpc_clients_;
  // The pre-defined gRPC client that is allowed to respond to UI messages.
  // Owned by |wilco_dtc_grpc_clients_|.
  brillo::AsyncGrpcClient<grpc_api::WilcoDtc>*
      ui_message_receiver_wilco_dtc_grpc_client_ = nullptr;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_GRPC_CLIENT_MANAGER_H_
