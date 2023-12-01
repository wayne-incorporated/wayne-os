// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_FAKE_WILCO_DTC_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_FAKE_WILCO_DTC_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/functional/callback.h>

#include <brillo/grpc/async_grpc_client.h>
#include <brillo/grpc/async_grpc_server.h>

#include "wilco_dtc.grpc.pb.h"           // NOLINT(build/include_directory)
#include "wilco_dtc_supportd.grpc.pb.h"  // NOLINT(build/include_directory)

namespace diagnostics {
namespace wilco {

// Helper class that allows to test gRPC communication between wilco_dtc and
// support daemon.
//
// This class runs a "WilcoDtc" gRPC server on the given |grpc_server_uri| URI,
// and a gRPC client to the "WilcoDtcSupportd" gRPC service on the
// |wilco_dtc_supportd_grpc_uri| gRPC URI.
class FakeWilcoDtc final {
 public:
  using SendMessageToUiCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::SendMessageToUiResponse> response)>;
  using GetProcDataCallback = base::OnceCallback<void(
      grpc::Status status, std::unique_ptr<grpc_api::GetProcDataResponse>)>;
  using GetEcTelemetryCallback = base::OnceCallback<void(
      grpc::Status status, std::unique_ptr<grpc_api::GetEcTelemetryResponse>)>;
  using HandleMessageFromUiCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::HandleMessageFromUiResponse>)>;
  using HandleEcNotificationCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::HandleEcNotificationResponse>)>;
  using HandlePowerNotificationCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::HandlePowerNotificationResponse>)>;
  using PerformWebRequestResponseCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::PerformWebRequestResponse>)>;
  using GetConfigurationDataCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::GetConfigurationDataResponse>)>;
  using GetDriveSystemDataCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::GetDriveSystemDataResponse>)>;
  using RequestBluetoothDataNotificationCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::RequestBluetoothDataNotificationResponse>)>;
  using GetStatefulPartitionAvailableCapacityCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<
          grpc_api::GetStatefulPartitionAvailableCapacityResponse>)>;
  using HandleConfigurationDataChangedCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::HandleConfigurationDataChangedResponse>)>;
  using HandleBluetoothDataChangedCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::HandleBluetoothDataChangedResponse>)>;
  using GetAvailableRoutinesCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<grpc_api::GetAvailableRoutinesResponse>)>;

  using HandleEcNotificationRequestCallback =
      base::RepeatingCallback<void(int32_t, const std::string&)>;
  using HandlePowerNotificationRequestCallback = base::RepeatingCallback<void(
      grpc_api::HandlePowerNotificationRequest::PowerEvent)>;
  using HandleBluetoothDataChangedRequestCallback =
      base::RepeatingCallback<void(
          const grpc_api::HandleBluetoothDataChangedRequest&)>;

  FakeWilcoDtc(const std::string& grpc_server_uri,
               const std::string& wilco_dtc_supportd_grpc_uri);
  FakeWilcoDtc(const FakeWilcoDtc&) = delete;
  FakeWilcoDtc& operator=(const FakeWilcoDtc&) = delete;

  ~FakeWilcoDtc();

  // Methods that correspond to the "WilcoDtcSupportd" gRPC interface and allow
  // to perform actual gRPC requests as if the wilco_dtc daemon would do them:
  void SendMessageToUi(const grpc_api::SendMessageToUiRequest& request,
                       SendMessageToUiCallback callback);
  void GetProcData(const grpc_api::GetProcDataRequest& request,
                   GetProcDataCallback callback);
  void GetEcTelemetry(const grpc_api::GetEcTelemetryRequest& request,
                      GetEcTelemetryCallback callback);
  void PerformWebRequest(const grpc_api::PerformWebRequestParameter& parameter,
                         PerformWebRequestResponseCallback callback);
  void GetConfigurationData(
      const grpc_api::GetConfigurationDataRequest& request,
      GetConfigurationDataCallback callback);
  void GetDriveSystemData(const grpc_api::GetDriveSystemDataRequest& request,
                          GetDriveSystemDataCallback callback);
  void RequestBluetoothDataNotification(
      const grpc_api::RequestBluetoothDataNotificationRequest& request,
      RequestBluetoothDataNotificationCallback callback);
  void GetStatefulPartitionAvailableCapacity(
      const grpc_api::GetStatefulPartitionAvailableCapacityRequest& request,
      GetStatefulPartitionAvailableCapacityCallback callback);
  void GetAvailableRoutines(GetAvailableRoutinesCallback callback);

  // Sets up the passed callback to be used for subsequent
  // |HandleMessageFromUi| gRPC calls.
  void set_handle_message_from_ui_callback(
      base::OnceClosure handle_message_from_ui_callback) {
    handle_message_from_ui_callback_.emplace(
        std::move(handle_message_from_ui_callback));
  }

  // Sets up the passed json message to be used as a response for subsequent
  // |HandleMessageFromUi| gRPC calls.
  void set_handle_message_from_ui_json_message_response(
      const std::string& json_message_response) {
    handle_message_from_ui_json_message_response_.emplace(
        json_message_response);
  }

  // Sets up the passed callback to be used for subsequent
  // |HandleEcNotification| gRPC calls.
  void set_handle_ec_event_request_callback(
      HandleEcNotificationRequestCallback handle_ec_event_request_callback) {
    handle_ec_event_request_callback_ = handle_ec_event_request_callback;
  }

  // Sets up the passed callback to be used for subsequent
  // |HandlePowerNotification| gRPC calls.
  void set_handle_power_event_request_callback(
      HandlePowerNotificationRequestCallback
          handle_powerd_event_request_callback) {
    handle_power_event_request_callback_ = handle_powerd_event_request_callback;
  }

  const std::optional<std::string>& handle_message_from_ui_actual_json_message()
      const {
    return handle_message_from_ui_actual_json_message_;
  }

  // Sets up the passed callback to be used for subsequent
  // |HandleConfigurationDataChanged| gRPC calls.
  void set_configuration_data_changed_callback(base::OnceClosure callback) {
    configuration_data_changed_callback_.emplace(std::move(callback));
  }

  // Sets up the passed callback to be used for subsequent
  // |HandleBluetoothDataChanged| gRPC calls.
  void set_bluetooth_data_changed_callback(
      HandleBluetoothDataChangedRequestCallback callback) {
    bluetooth_data_changed_request_callback_.emplace(std::move(callback));
  }

 private:
  using AsyncGrpcWilcoDtcServer =
      brillo::AsyncGrpcServer<grpc_api::WilcoDtc::AsyncService>;
  using AsyncGrpcWilcoDtcSupportdClient =
      brillo::AsyncGrpcClient<grpc_api::WilcoDtcSupportd>;

  // Receives gRPC request and saves json message from request in
  // |handle_message_from_ui_actual_json_message_|.
  // Calls the callback |handle_message_from_ui_callback_| after all.
  void HandleMessageFromUi(
      std::unique_ptr<grpc_api::HandleMessageFromUiRequest> request,
      HandleMessageFromUiCallback callback);

  // Receives gRPC request and invokes the given |callback| with gRPC response.
  // Calls the callback |handle_ec_event_request_callback_| after all with the
  // request type and payload.
  void HandleEcNotification(
      std::unique_ptr<grpc_api::HandleEcNotificationRequest> request,
      HandleEcNotificationCallback callback);

  // Receives gRPC request and invokes the given |callback| with gRPC response.
  // Calls the callback |handle_power_event_request_callback_| after all with
  // the request type and payload.
  void HandlePowerNotification(
      std::unique_ptr<grpc_api::HandlePowerNotificationRequest> request,
      HandlePowerNotificationCallback callback);

  // Receives gRPC request and invokes the given |callback| with gRPC response.
  // Calls the callback |configuration_data_changed_callback_| after all.
  void HandleConfigurationDataChanged(
      std::unique_ptr<grpc_api::HandleConfigurationDataChangedRequest> request,
      HandleConfigurationDataChangedCallback callback);

  // Receives gRPC request and invokes the given |callback| with gRPC response.
  // Calls the callback |bluetooth_data_changed_callback_| after all.
  void HandleBluetoothDataChanged(
      std::unique_ptr<grpc_api::HandleBluetoothDataChangedRequest> request,
      HandleBluetoothDataChangedCallback callback);

  AsyncGrpcWilcoDtcServer grpc_server_;
  AsyncGrpcWilcoDtcSupportdClient wilco_dtc_supportd_grp_client_;

  std::optional<base::OnceClosure> handle_message_from_ui_callback_;
  std::optional<std::string> handle_message_from_ui_actual_json_message_;
  std::optional<std::string> handle_message_from_ui_json_message_response_;

  std::optional<HandleEcNotificationRequestCallback>
      handle_ec_event_request_callback_;

  std::optional<HandlePowerNotificationRequestCallback>
      handle_power_event_request_callback_;

  std::optional<base::OnceClosure> configuration_data_changed_callback_;

  std::optional<HandleBluetoothDataChangedRequestCallback>
      bluetooth_data_changed_request_callback_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_FAKE_WILCO_DTC_H_
