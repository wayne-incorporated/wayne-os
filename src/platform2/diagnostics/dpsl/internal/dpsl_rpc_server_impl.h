// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_INTERNAL_DPSL_RPC_SERVER_IMPL_H_
#define DIAGNOSTICS_DPSL_INTERNAL_DPSL_RPC_SERVER_IMPL_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/sequence_checker_impl.h>
#include <brillo/grpc/async_grpc_server.h>

#include "diagnostics/dpsl/public/dpsl_rpc_server.h"

#include "wilco_dtc.grpc.pb.h"  // NOLINT(build/include_directory)
#include "wilco_dtc.pb.h"       // NOLINT(build/include_directory)

namespace diagnostics {

class DpslRpcHandler;

// Real implementation of the DpslRpcServer interface.
class DpslRpcServerImpl final : public DpslRpcServer {
 public:
  DpslRpcServerImpl(DpslRpcHandler* rpc_handler,
                    GrpcServerUri grpc_server_uri,
                    const std::string& grpc_server_uri_string);
  DpslRpcServerImpl(const DpslRpcServerImpl&) = delete;
  DpslRpcServerImpl& operator=(const DpslRpcServerImpl&) = delete;

  ~DpslRpcServerImpl() override;

  // Starts the gRPC server. Returns whether the startup succeeded.
  bool Init();

 private:
  using HandleMessageFromUiCallback = base::OnceCallback<void(
      grpc::Status, std::unique_ptr<grpc_api::HandleMessageFromUiResponse>)>;
  using HandleEcNotificationCallback = base::OnceCallback<void(
      grpc::Status, std::unique_ptr<grpc_api::HandleEcNotificationResponse>)>;
  using HandlePowerNotificationCallback = base::OnceCallback<void(
      grpc::Status,
      std::unique_ptr<grpc_api::HandlePowerNotificationResponse>)>;
  using HandleConfigurationDataChangedCallback = base::OnceCallback<void(
      grpc::Status,
      std::unique_ptr<grpc_api::HandleConfigurationDataChangedResponse>)>;
  using HandleBluetoothDataChangedCallback = base::OnceCallback<void(
      grpc::Status,
      std::unique_ptr<grpc_api::HandleBluetoothDataChangedResponse>)>;

  // Methods corresponding to the "WilcoDtc" gRPC interface (each of these
  // methods just calls the corresponding method of |rpc_handler_|):
  void HandleMessageFromUi(
      std::unique_ptr<grpc_api::HandleMessageFromUiRequest> request,
      HandleMessageFromUiCallback callback);
  void HandleEcNotification(
      std::unique_ptr<grpc_api::HandleEcNotificationRequest> request,
      HandleEcNotificationCallback callback);
  void HandlePowerNotification(
      std::unique_ptr<grpc_api::HandlePowerNotificationRequest> request,
      HandlePowerNotificationCallback callback);
  void HandleConfigurationDataChanged(
      std::unique_ptr<grpc_api::HandleConfigurationDataChangedRequest> request,
      HandleConfigurationDataChangedCallback callback);
  void HandleBluetoothDataChanged(
      std::unique_ptr<grpc_api::HandleBluetoothDataChangedRequest> request,
      HandleBluetoothDataChangedCallback callback);

  // The method corresponding to the HandleMessageFromUi method of the
  // "WilcoDtc" gRPC interface and returning back a nullptr response.
  void HandleMessageFromUiStub(
      std::unique_ptr<grpc_api::HandleMessageFromUiRequest> request,
      HandleMessageFromUiCallback callback);

  // Unowned.
  DpslRpcHandler* const rpc_handler_;

  brillo::AsyncGrpcServer<grpc_api::WilcoDtc::AsyncService> async_grpc_server_;

  base::SequenceCheckerImpl sequence_checker_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_INTERNAL_DPSL_RPC_SERVER_IMPL_H_
