// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/mojo_grpc_adapter.h"

#include <memory>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>

#include "diagnostics/wilco_dtc_supportd/grpc_client_manager.h"
#include "diagnostics/wilco_dtc_supportd/json_utils.h"

#include "wilco_dtc.grpc.pb.h"  // NOLINT(build/include_directory)

namespace diagnostics {
namespace wilco {

MojoGrpcAdapter::MojoGrpcAdapter(GrpcClientManager* grpc_client_manager)
    : grpc_client_manager_(grpc_client_manager) {}

MojoGrpcAdapter::~MojoGrpcAdapter() = default;

void MojoGrpcAdapter::SendGrpcUiMessageToWilcoDtc(
    base::StringPiece json_message,
    const SendGrpcUiMessageToWilcoDtcCallback& callback) {
  VLOG(1) << "Core::SendGrpcMessageToWilcoDtc";

  if (!grpc_client_manager_->GetUiClient()) {
    VLOG(1) << "The UI message is discarded since the recipient has been shut "
            << "down.";
    callback.Run(std::string() /* response_json_message */);
    return;
  }

  grpc_api::HandleMessageFromUiRequest request;
  request.set_json_message(json_message.data() ? json_message.data() : "",
                           json_message.length());

  grpc_client_manager_->GetUiClient()->CallRpc(
      &grpc_api::WilcoDtc::Stub::AsyncHandleMessageFromUi, request,
      base::BindOnce(
          [](const SendGrpcUiMessageToWilcoDtcCallback& callback,
             grpc::Status status,
             std::unique_ptr<grpc_api::HandleMessageFromUiResponse> response) {
            if (!status.ok()) {
              VLOG(1) << "Failed to call HandleMessageFromUiRequest gRPC method"
                         " on wilco_dtc. grpc error code: "
                      << status.error_code()
                      << ", error message: " << status.error_message();
              callback.Run(std::string() /* response_json_message */);
              return;
            }

            VLOG(1) << "gRPC method HandleMessageFromUiRequest was "
                       "successfully called on wilco_dtc";

            std::string json_error_message;
            if (!IsJsonValid(
                    base::StringPiece(response->response_json_message()),
                    &json_error_message)) {
              LOG(ERROR) << "Invalid JSON error: " << json_error_message;
              callback.Run(std::string() /* response_json_message */);
              return;
            }

            callback.Run(response->response_json_message());
          },
          callback));
}

void MojoGrpcAdapter::NotifyConfigurationDataChangedToWilcoDtc() {
  VLOG(1) << "Core::NotifyConfigurationDataChanged";

  grpc_api::HandleConfigurationDataChangedRequest request;
  for (auto& client : grpc_client_manager_->GetClients()) {
    client->CallRpc(
        &grpc_api::WilcoDtc::Stub::AsyncHandleConfigurationDataChanged, request,
        base::BindOnce(
            [](grpc::Status status,
               std::unique_ptr<grpc_api::HandleConfigurationDataChangedResponse>
                   response) {
              if (!status.ok()) {
                VLOG(1) << "Failed to call HandleConfigurationDataChanged gRPC "
                           "method on wilco_dtc. grpc error code: "
                        << status.error_code()
                        << ", error message: " << status.error_message();
                return;
              }
              VLOG(1) << "gRPC method HandleConfigurationDaraChanged was "
                         "successfully called on wilco_dtc";
            }));
  }
}

}  // namespace wilco
}  // namespace diagnostics
