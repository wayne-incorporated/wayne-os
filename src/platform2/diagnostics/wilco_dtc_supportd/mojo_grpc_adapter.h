// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_MOJO_GRPC_ADAPTER_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_MOJO_GRPC_ADAPTER_H_

#include <string>

#include <base/functional/callback.h>
#include <base/strings/string_piece_forward.h>

namespace diagnostics {
namespace wilco {

class GrpcClientManager;

// Forwards calls from Mojo service to wilco gRPC clients.
class MojoGrpcAdapter final {
 public:
  using SendGrpcUiMessageToWilcoDtcCallback =
      base::RepeatingCallback<void(std::string response_json_message)>;

  explicit MojoGrpcAdapter(GrpcClientManager* grpc_client_manager);
  MojoGrpcAdapter(const MojoGrpcAdapter&) = delete;
  MojoGrpcAdapter& operator=(const MojoGrpcAdapter&) = delete;
  ~MojoGrpcAdapter();

  // Called when wilco_dtc_supportd daemon mojo function
  // |SendUiMessageToWilcoDtc| was called.
  //
  // Calls gRPC HandleMessageFromUiRequest method on wilco_dtc and puts
  // |json_message| to the gRPC |HandleMessageFromUiRequest| request message.
  // Result of the call is returned via |callback|; if the request succeeded,
  // it will receive the message returned by the wilco_dtc.
  void SendGrpcUiMessageToWilcoDtc(
      base::StringPiece json_message,
      const SendGrpcUiMessageToWilcoDtcCallback& callback);

  // Called when wilco_dtc_supportd daemon mojo function
  // |NotifyConfigurationDataChanged| was called.
  //
  // Calls gRPC HandleConfigurationDataChanged method on wilco_dtc to notify
  // that new JSON configuration data is available and can be retrieved by
  // calling |GetConfigurationData|.
  void NotifyConfigurationDataChangedToWilcoDtc();

 private:
  // Unowned. The grpc clients must outlive this instance.
  const GrpcClientManager* const grpc_client_manager_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_MOJO_GRPC_ADAPTER_H_
