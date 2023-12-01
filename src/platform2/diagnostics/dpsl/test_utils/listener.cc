// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See help usage message in main() for basic description.

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include <brillo/flag_helper.h>

#include "diagnostics/dpsl/public/dpsl_global_context.h"
#include "diagnostics/dpsl/public/dpsl_rpc_handler.h"
#include "diagnostics/dpsl/public/dpsl_rpc_server.h"
#include "diagnostics/dpsl/public/dpsl_thread_context.h"
#include "diagnostics/dpsl/test_utils/common.h"

#include "wilco_dtc.pb.h"           // NOLINT(build/include_directory)
#include "wilco_dtc_supportd.pb.h"  // NOLINT(build/include_directory)

namespace diagnostics {
namespace {

class DpslTestListener final : public DpslRpcHandler {
 public:
  DpslTestListener(
      std::unique_ptr<grpc_api::HandleMessageFromUiResponse> ui_response) {
    ui_response_ = std::move(ui_response);
  }

  // DpslRpcHandler overrides:
  void HandleMessageFromUi(
      std::unique_ptr<grpc_api::HandleMessageFromUiRequest> request,
      HandleMessageFromUiCallback callback) override {
    test_utils::PrintProto(*request);
    // Note: every incoming RPC must be answered.
    callback(
        std::make_unique<grpc_api::HandleMessageFromUiResponse>(*ui_response_));
  };

  void HandleEcNotification(
      std::unique_ptr<grpc_api::HandleEcNotificationRequest> request,
      HandleEcNotificationCallback callback) override {
    test_utils::PrintProto(*request);
    // Note: every incoming RPC must be answered.
    callback(std::make_unique<grpc_api::HandleEcNotificationResponse>());
  };

  void HandlePowerNotification(
      std::unique_ptr<grpc_api::HandlePowerNotificationRequest> request,
      HandlePowerNotificationCallback callback) override {
    test_utils::PrintProto(*request);
    // Note: every incoming RPC must be answered.
    callback(std::make_unique<grpc_api::HandlePowerNotificationResponse>());
  };

  void HandleConfigurationDataChanged(
      std::unique_ptr<grpc_api::HandleConfigurationDataChangedRequest> request,
      HandleConfigurationDataChangedCallback callback) override {
    test_utils::PrintProto(*request);
    // Note: every incoming RPC must be answered.
    callback(
        std::make_unique<grpc_api::HandleConfigurationDataChangedResponse>());
  };

  void HandleBluetoothDataChanged(
      std::unique_ptr<grpc_api::HandleBluetoothDataChangedRequest> request,
      HandleBluetoothDataChangedCallback callback) override {
    test_utils::PrintProto(*request);
    // Note: every incoming RPC must be answered.
    callback(std::make_unique<grpc_api::HandleBluetoothDataChangedResponse>());
  };

 private:
  std::unique_ptr<grpc_api::HandleMessageFromUiResponse> ui_response_;
};

}  // namespace
}  // namespace diagnostics

int main(int argc, char** argv) {
  DEFINE_string(ui_response_body, "",
                "optional JSON-formatted body of proto to send as the response "
                "to HandleMessageFromUi");
  constexpr char kUsageMessage[] =
      R"(DPSL Listener Utility
Command line utility to test DPSL communication into and out of a VM. The
utility blocks indefinitely, monitoring and printing any incoming gRPC requests
from wilco_dtc_supportd. The request is printed as JSON, so you can see both the
name and the actual content of the proto.

EXAMPLE USAGE
(VM)$ diagnostics_dpsl_test_listener \
  --ui_response_body='{"response_json_message": "{test: 1}"}'
...THEN YOU FORCE THE EC TO GENERATE AN EVENT...
{
   "body": {
      "type": 19,
      "payload":"AAABAAIAAwAEAAUA"
   },
   "name": "HandleEcNotificationRequest"
})";
  brillo::FlagHelper::Init(argc, argv, kUsageMessage);

  std::unique_ptr<diagnostics::grpc_api::HandleMessageFromUiResponse>
      ui_response;
  if (!FLAGS_ui_response_body.empty()) {
    ui_response = diagnostics::test_utils::JsonToProto<
        diagnostics::grpc_api::HandleMessageFromUiResponse>(
        FLAGS_ui_response_body);

    if (!ui_response) {
      std::cerr << "Failed to parse ui_response_body\n";
      return EXIT_FAILURE;
    }
  } else {
    ui_response =
        std::make_unique<diagnostics::grpc_api::HandleMessageFromUiResponse>();
  }

  auto global_context = diagnostics::DpslGlobalContext::Create();
  auto thread_context =
      diagnostics::DpslThreadContext::Create(global_context.get());
  diagnostics::DpslTestListener listener(std::move(ui_response));
  auto rpc_server = diagnostics::DpslRpcServer::Create(
      thread_context.get(), &listener,
      diagnostics::DpslRpcServer::GrpcServerUri::kUiMessageReceiverVmVsock);
  if (!rpc_server) {
    std::cerr << "Failed to create DpslRpcServer\n";
    return EXIT_FAILURE;
  }

  // This blocks forever, responding to any incoming gRPC requests.
  thread_context->RunEventLoop();

  return EXIT_SUCCESS;
}
