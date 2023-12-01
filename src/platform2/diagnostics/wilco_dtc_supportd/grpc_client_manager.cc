// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/grpc_client_manager.h"

#include <utility>

#include <base/barrier_closure.h>
#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>

namespace diagnostics {
namespace wilco {

GrpcClientManager::GrpcClientManager() = default;
GrpcClientManager::~GrpcClientManager() = default;

void GrpcClientManager::Start(
    const std::string& ui_message_receiver_wilco_dtc_grpc_uri,
    const std::vector<std::string>& wilco_dtc_grpc_client_uris) {
  // Start the gRPC clients that talk to the wilco_dtc daemon.
  for (const auto& uri : wilco_dtc_grpc_client_uris) {
    wilco_dtc_grpc_clients_.push_back(
        std::make_unique<brillo::AsyncGrpcClient<grpc_api::WilcoDtc>>(
            base::SingleThreadTaskRunner::GetCurrentDefault(), uri));
    VLOG(0) << "Created gRPC wilco_dtc client on " << uri;
  }

  // Start the gRPC client that is allowed to receive UI messages as a normal
  // gRPC client that talks to the wilco_dtc daemon.
  wilco_dtc_grpc_clients_.push_back(
      std::make_unique<brillo::AsyncGrpcClient<grpc_api::WilcoDtc>>(
          base::SingleThreadTaskRunner::GetCurrentDefault(),
          ui_message_receiver_wilco_dtc_grpc_uri));
  VLOG(0) << "Created gRPC wilco_dtc client on "
          << ui_message_receiver_wilco_dtc_grpc_uri;
  ui_message_receiver_wilco_dtc_grpc_client_ =
      wilco_dtc_grpc_clients_.back().get();
}

void GrpcClientManager::ShutDown(base::OnceClosure on_shutdown_callback) {
  const base::RepeatingClosure barrier_closure = base::BarrierClosure(
      wilco_dtc_grpc_clients_.size(), std::move(on_shutdown_callback));
  for (const auto& client : wilco_dtc_grpc_clients_) {
    client->ShutDown(barrier_closure);
  }
  ui_message_receiver_wilco_dtc_grpc_client_ = nullptr;
}

brillo::AsyncGrpcClient<grpc_api::WilcoDtc>* GrpcClientManager::GetUiClient()
    const {
  return ui_message_receiver_wilco_dtc_grpc_client_;
}

const std::vector<std::unique_ptr<brillo::AsyncGrpcClient<grpc_api::WilcoDtc>>>&
GrpcClientManager::GetClients() const {
  return wilco_dtc_grpc_clients_;
}

}  // namespace wilco
}  // namespace diagnostics
