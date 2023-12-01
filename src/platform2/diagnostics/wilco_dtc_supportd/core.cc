// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/core.h"

#include <algorithm>
#include <cstddef>
#include <utility>

#include <base/barrier_closure.h>
#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>

#include "diagnostics/wilco_dtc_supportd/grpc_client_manager.h"
#include "diagnostics/wilco_dtc_supportd/mojo_service.h"
#include "diagnostics/wilco_dtc_supportd/mojo_service_factory.h"
#include "diagnostics/wilco_dtc_supportd/probe_service_impl.h"

#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace wilco {

namespace {

using EcEvent = EcService::EcEvent;
using EcEventReason = EcService::EcEvent::Reason;
using MojomWilcoDtcSupportdWebRequestStatus =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdWebRequestStatus;
using MojomWilcoDtcSupportdWebRequestHttpMethod =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdWebRequestHttpMethod;

// Converts HTTP method into an appropriate mojom one.
bool ConvertWebRequestHttpMethodToMojom(
    Core::WebRequestHttpMethod http_method,
    MojomWilcoDtcSupportdWebRequestHttpMethod* mojo_http_method_out) {
  DCHECK(mojo_http_method_out);
  switch (http_method) {
    case Core::WebRequestHttpMethod::kGet:
      *mojo_http_method_out = MojomWilcoDtcSupportdWebRequestHttpMethod::kGet;
      return true;
    case Core::WebRequestHttpMethod::kHead:
      *mojo_http_method_out = MojomWilcoDtcSupportdWebRequestHttpMethod::kHead;
      return true;
    case Core::WebRequestHttpMethod::kPost:
      *mojo_http_method_out = MojomWilcoDtcSupportdWebRequestHttpMethod::kPost;
      return true;
    case Core::WebRequestHttpMethod::kPut:
      *mojo_http_method_out = MojomWilcoDtcSupportdWebRequestHttpMethod::kPut;
      return true;
    case Core::WebRequestHttpMethod::kPatch:
      *mojo_http_method_out = MojomWilcoDtcSupportdWebRequestHttpMethod::kPatch;
      return true;
  }
  return false;
}

// Convert the result back from mojom status.
bool ConvertStatusFromMojom(MojomWilcoDtcSupportdWebRequestStatus mojo_status,
                            Core::WebRequestStatus* status_out) {
  DCHECK(status_out);
  switch (mojo_status) {
    case MojomWilcoDtcSupportdWebRequestStatus::kOk:
      *status_out = Core::WebRequestStatus::kOk;
      return true;
    case MojomWilcoDtcSupportdWebRequestStatus::kNetworkError:
      *status_out = Core::WebRequestStatus::kNetworkError;
      return true;
    case MojomWilcoDtcSupportdWebRequestStatus::kHttpError:
      *status_out = Core::WebRequestStatus::kHttpError;
      return true;
    case MojomWilcoDtcSupportdWebRequestStatus::kUnmappedEnumField:
      return false;
  }
}

bool ConvertPowerEventToGrpc(
    PowerdEventService::Observer::PowerEventType type,
    grpc_api::HandlePowerNotificationRequest::PowerEvent* type_out) {
  DCHECK(type_out);
  switch (type) {
    case PowerdEventService::Observer::PowerEventType::kAcInsert:
      *type_out = grpc_api::HandlePowerNotificationRequest::AC_INSERT;
      return true;
    case PowerdEventService::Observer::PowerEventType::kAcRemove:
      *type_out = grpc_api::HandlePowerNotificationRequest::AC_REMOVE;
      return true;
    case PowerdEventService::Observer::PowerEventType::kOsSuspend:
      *type_out = grpc_api::HandlePowerNotificationRequest::OS_SUSPEND;
      return true;
    case PowerdEventService::Observer::PowerEventType::kOsResume:
      *type_out = grpc_api::HandlePowerNotificationRequest::OS_RESUME;
      return true;
  }
  return false;
}

}  // namespace

Core::Core(Delegate* delegate,
           const GrpcClientManager* grpc_client_manager,
           const std::vector<std::string>& grpc_service_uris,
           MojoServiceFactory* mojo_service_factory)
    : delegate_(delegate),
      grpc_client_manager_(grpc_client_manager),
      grpc_service_uris_(grpc_service_uris),
      grpc_server_(base::SingleThreadTaskRunner::GetCurrentDefault(),
                   grpc_service_uris_),
      mojo_service_factory_(mojo_service_factory) {
  DCHECK(delegate);
  DCHECK(grpc_client_manager_);
  DCHECK(mojo_service_factory_);
  ec_service_ = delegate_->CreateEcService();
  probe_service_ = delegate->CreateProbeService(this);
  DCHECK(ec_service_);
  ec_service_->AddObserver(this);
}

Core::~Core() = default;

bool Core::Start() {
  // Associate RPCs of the to-be-exposed gRPC interface with methods of
  // |grpc_service_|.
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestSendMessageToUi,
      base::BindRepeating(&GrpcService::SendMessageToUi,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetProcData,
      base::BindRepeating(&GrpcService::GetProcData,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetSysfsData,
      base::BindRepeating(&GrpcService::GetSysfsData,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetEcTelemetry,
      base::BindRepeating(&GrpcService::GetEcTelemetry,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestPerformWebRequest,
      base::BindRepeating(&GrpcService::PerformWebRequest,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetAvailableRoutines,
      base::BindRepeating(&GrpcService::GetAvailableRoutines,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestRunRoutine,
      base::BindRepeating(&GrpcService::RunRoutine,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetRoutineUpdate,
      base::BindRepeating(&GrpcService::GetRoutineUpdate,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetOsVersion,
      base::BindRepeating(&GrpcService::GetOsVersion,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetVpdField,
      base::BindRepeating(&GrpcService::GetVpdField,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetConfigurationData,
      base::BindRepeating(&GrpcService::GetConfigurationData,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::RequestGetDriveSystemData,
      base::BindRepeating(&GrpcService::GetDriveSystemData,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::
          RequestRequestBluetoothDataNotification,
      base::BindRepeating(&GrpcService::RequestBluetoothDataNotification,
                          base::Unretained(&grpc_service_)));
  grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtcSupportd::AsyncService::
          RequestGetStatefulPartitionAvailableCapacity,
      base::BindRepeating(&GrpcService::GetStatefulPartitionAvailableCapacity,
                          base::Unretained(&grpc_service_)));

  // Start the gRPC server that listens for incoming gRPC requests.
  VLOG(1) << "Starting gRPC server";
  if (!grpc_server_.Start()) {
    LOG(ERROR) << "Failed to start the gRPC server listening on: "
               << base::JoinString(grpc_service_uris_, ", ");
    return false;
  }

  VLOG(0) << "Successfully started gRPC server listening on "
          << base::JoinString(grpc_service_uris_, ",");

  // Start EC event service.
  if (!ec_service_->Start()) {
    LOG(WARNING)
        << "Failed to start EC event service. EC events will be ignored.";
  }

  return true;
}

void Core::ShutDown(base::OnceClosure on_shutdown_callback) {
  VLOG(1) << "Tearing down gRPC server, gRPC wilco_dtc clients, "
             "EC event service and D-Bus server";
  UnsubscribeFromEventServices();
  const base::RepeatingClosure barrier_closure =
      base::BarrierClosure(2, std::move(on_shutdown_callback));
  ec_service_->ShutDown(barrier_closure);
  grpc_server_.ShutDown(barrier_closure);
}

void Core::CreateDbusAdapters(const scoped_refptr<dbus::Bus>& bus) {
  DCHECK(bus);

  bluetooth_client_ = delegate_->CreateBluetoothClient(bus);
  DCHECK(bluetooth_client_);

  debugd_adapter_ = delegate_->CreateDebugdAdapter(bus);
  DCHECK(debugd_adapter_);

  powerd_adapter_ = delegate_->CreatePowerdAdapter(bus);
  DCHECK(powerd_adapter_);

  bluetooth_event_service_ =
      delegate_->CreateBluetoothEventService(bluetooth_client_.get());
  DCHECK(bluetooth_event_service_);
  bluetooth_event_service_->AddObserver(this);

  powerd_event_service_ =
      delegate_->CreatePowerdEventService(powerd_adapter_.get());
  DCHECK(powerd_event_service_);
  powerd_event_service_->AddObserver(this);
}

bool Core::GetCrosHealthdDiagnosticsService(
    mojo::PendingReceiver<
        ash::cros_healthd::mojom::CrosHealthdDiagnosticsService> service) {
  MojoService* mojo_service = mojo_service_factory_->Get();
  if (!mojo_service) {
    LOG(WARNING) << "GetCrosHealthdDiagnosticsService happens before Mojo "
                 << "connection is established.";
    return false;
  }

  mojo_service->GetCrosHealthdDiagnosticsService(std::move(service));
  return true;
}

bool Core::BindCrosHealthdProbeService(
    mojo::PendingReceiver<ash::cros_healthd::mojom::CrosHealthdProbeService>
        service) {
  MojoService* mojo_service = mojo_service_factory_->Get();
  if (!mojo_service) {
    LOG(WARNING) << "BindCrosHealthdProbeService happens before Mojo "
                 << "connection is established.";
    return false;
  }

  mojo_service->GetCrosHealthdProbeService(std::move(service));
  return true;
}

void Core::SendWilcoDtcMessageToUi(const std::string& json_message,
                                   SendMessageToUiCallback callback) {
  VLOG(1) << "SendWilcoDtcMessageToUi() json_message=" << json_message;
  MojoService* mojo_service = mojo_service_factory_->Get();
  if (!mojo_service) {
    constexpr char kErrMsg[] =
        "GetConfigurationDataFromBrowser happens before "
        "Mojo connection is established.";
    LOG(WARNING) << kErrMsg;
    std::move(callback).Run(grpc::Status(grpc::StatusCode::UNKNOWN, kErrMsg),
                            "");
    return;
  }
  mojo_service->SendWilcoDtcMessageToUi(json_message, std::move(callback));
}

void Core::PerformWebRequestToBrowser(
    WebRequestHttpMethod http_method,
    const std::string& url,
    const std::vector<std::string>& headers,
    const std::string& request_body,
    PerformWebRequestToBrowserCallback callback) {
  VLOG(1) << "Core::PerformWebRequestToBrowser";

  MojoService* mojo_service = mojo_service_factory_->Get();
  if (!mojo_service) {
    LOG(WARNING) << "PerformWebRequestToBrowser happens before Mojo connection "
                 << "is established.";
    std::move(callback).Run(WebRequestStatus::kInternalError,
                            0 /* http_status */, "" /* response_body */);
    return;
  }

  MojomWilcoDtcSupportdWebRequestHttpMethod mojo_http_method;
  if (!ConvertWebRequestHttpMethodToMojom(http_method, &mojo_http_method)) {
    LOG(ERROR) << "Unknown gRPC http method: " << static_cast<int>(http_method);
    std::move(callback).Run(WebRequestStatus::kInternalError,
                            0 /* http_status */, "" /* response_body */);
    return;
  }

  mojo_service->PerformWebRequest(
      mojo_http_method, url, headers, request_body,
      base::BindOnce(
          [](PerformWebRequestToBrowserCallback callback,
             MojomWilcoDtcSupportdWebRequestStatus mojo_status, int http_status,
             base::StringPiece response_body) {
            WebRequestStatus status;
            if (!ConvertStatusFromMojom(mojo_status, &status)) {
              LOG(ERROR) << "Unknown mojo web request status: " << mojo_status;
              std::move(callback).Run(WebRequestStatus::kInternalError,
                                      0 /* http_status */,
                                      "" /* response_body */);
              return;
            }
            std::move(callback).Run(status, http_status, response_body);
          },
          std::move(callback)));
}

void Core::GetAvailableRoutinesToService(
    GetAvailableRoutinesToServiceCallback callback) {
  routine_service_.GetAvailableRoutines(std::move(callback));
}

void Core::RunRoutineToService(const grpc_api::RunRoutineRequest& request,
                               RunRoutineToServiceCallback callback) {
  routine_service_.RunRoutine(request, std::move(callback));
}

void Core::GetRoutineUpdateRequestToService(
    int uuid,
    grpc_api::GetRoutineUpdateRequest::Command command,
    bool include_output,
    GetRoutineUpdateRequestToServiceCallback callback) {
  routine_service_.GetRoutineUpdate(uuid, command, include_output,
                                    std::move(callback));
}

void Core::GetConfigurationDataFromBrowser(
    GetConfigurationDataFromBrowserCallback callback) {
  VLOG(1) << "Core::GetConfigurationDataFromBrowser";

  MojoService* mojo_service = mojo_service_factory_->Get();
  if (!mojo_service) {
    LOG(WARNING) << "GetConfigurationDataFromBrowser happens before Mojo "
                 << "connection is established.";
    std::move(callback).Run("" /* json_configuration_data */);
    return;
  }

  mojo_service->GetConfigurationData(std::move(callback));
}

void Core::GetDriveSystemData(DriveSystemDataType data_type,
                              GetDriveSystemDataCallback callback) {
  if (!debugd_adapter_) {
    LOG(WARNING) << "DebugdAdapter is not yet ready for incoming requests";
    std::move(callback).Run("", false /* success */);
    return;
  }

  auto result_callback = base::BindOnce(
      [](GetDriveSystemDataCallback callback, const std::string& result,
         brillo::Error* error) {
        if (error) {
          LOG(WARNING) << "Debugd smartctl failed with error: "
                       << error->GetMessage();
          std::move(callback).Run("", false /* success */);
          return;
        }
        std::move(callback).Run(result, true /* success */);
      },
      std::move(callback));

  switch (data_type) {
    case DriveSystemDataType::kSmartAttributes:
      debugd_adapter_->GetSmartAttributes(std::move(result_callback));
      break;
    case DriveSystemDataType::kIdentityAttributes:
      debugd_adapter_->GetNvmeIdentity(std::move(result_callback));
      break;
  }
}

void Core::RequestBluetoothDataNotification() {
  VLOG(1) << "WilcoDtcSupportdCore::RequestBluetoothDataNotification";

  if (!bluetooth_event_service_) {
    VLOG(1) << "Bluetooth event service not yet ready";
    return;
  }

  NotifyClientsBluetoothAdapterState(
      bluetooth_event_service_->GetLatestEvent());
}

void Core::ProbeTelemetryInfo(
    std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum> categories,
    ProbeTelemetryInfoCallback callback) {
  VLOG(1) << "Core::ProbeTelemetryInfo";
  probe_service_->ProbeTelemetryInfo(std::move(categories),
                                     std::move(callback));
}

EcService* Core::GetEcService() {
  DCHECK(ec_service_);
  return ec_service_.get();
}

void Core::BluetoothAdapterDataChanged(
    const std::vector<BluetoothEventService::AdapterData>& adapters) {
  VLOG(1) << "Core::BluetoothAdapterDataChanged";

  NotifyClientsBluetoothAdapterState(adapters);
}

void Core::OnPowerdEvent(PowerEventType type) {
  VLOG(1) << "Core::OnPowerdEvent: " << static_cast<int>(type);

  grpc_api::HandlePowerNotificationRequest::PowerEvent grpc_type;
  if (!ConvertPowerEventToGrpc(type, &grpc_type)) {
    LOG(ERROR) << "Unable to convert power event to gRPC power event: "
               << static_cast<int>(type);
    return;
  }

  grpc_api::HandlePowerNotificationRequest request;
  request.set_power_event(grpc_type);

  for (auto& client : grpc_client_manager_->GetClients()) {
    client->CallRpc(
        &grpc_api::WilcoDtc::Stub::AsyncHandlePowerNotification, request,
        base::BindOnce(
            [](grpc::Status status,
               std::unique_ptr<grpc_api::HandlePowerNotificationResponse>
                   response) {
              if (!status.ok()) {
                VLOG(1) << "Failed to call HandlePowerNotification gRPC "
                           "method on wilco_dtc. grpc error code: "
                        << status.error_code()
                        << ", error message: " << status.error_message();
                return;
              }
              VLOG(1) << "gRPC method HandlePowerNotification was "
                         "successfully called on wilco_dtc";
            }));
  }
}

void Core::OnEcEvent(const EcEvent& ec_event) {
  VLOG(1) << "Core::OnEcEvent: type=" << static_cast<int>(ec_event.type)
          << " reason=" << static_cast<int>(ec_event.GetReason());

  SendGrpcEcEventToWilcoDtc(ec_event);

  // Parse EcEventReason into a MojoEvent and forward to the delegate.
  // We only will forward certain events. If they aren't relevant, ignore.
  switch (ec_event.GetReason()) {
    case EcEventReason::kNonWilcoCharger:
      SendMojoEcEventToBrowser(MojoEvent::kNonWilcoCharger);
      break;
    case EcEventReason::kLowPowerCharger:
      SendMojoEcEventToBrowser(MojoEvent::kLowPowerCharger);
      break;
    case EcEventReason::kBatteryAuth:
      SendMojoEcEventToBrowser(MojoEvent::kBatteryAuth);
      break;
    case EcEventReason::kDockDisplay:
      SendMojoEcEventToBrowser(MojoEvent::kDockDisplay);
      break;
    case EcEventReason::kDockThunderbolt:
      SendMojoEcEventToBrowser(MojoEvent::kDockThunderbolt);
      break;
    case EcEventReason::kIncompatibleDock:
      SendMojoEcEventToBrowser(MojoEvent::kIncompatibleDock);
      break;
    case EcEventReason::kDockError:
      SendMojoEcEventToBrowser(MojoEvent::kDockError);
      break;
    case EcEventReason::kSysNotification:
      VLOG(2) << "Received EC event that doesn't trigger a mojo event";
      break;
    case EcEventReason::kNonSysNotification:
      VLOG(2) << "Received a non-system notification EC event";
      break;
  }
}

void Core::SendGrpcEcEventToWilcoDtc(const EcEvent& ec_event) {
  VLOG(1) << "Core::SendGrpcEcEventToWilcoDtc";

  size_t payload_size = ec_event.PayloadSizeInBytes();
  if (payload_size > sizeof(ec_event.payload)) {
    VLOG(2) << "Received EC event with invalid payload size: " << payload_size;
    return;
  }

  grpc_api::HandleEcNotificationRequest request;
  request.set_type(ec_event.type);
  request.set_payload(&ec_event.payload, payload_size);

  for (auto& client : grpc_client_manager_->GetClients()) {
    client->CallRpc(
        &grpc_api::WilcoDtc::Stub::AsyncHandleEcNotification, request,
        base::BindOnce([](grpc::Status status,
                          std::unique_ptr<
                              grpc_api::HandleEcNotificationResponse>
                              response) {
          if (!status.ok()) {
            VLOG(1)
                << "Failed to call HandleEcNotificationRequest gRPC method on "
                   "wilco_dtc. grpc error code: "
                << status.error_code()
                << ", error message: " << status.error_message();
            return;
          }
          VLOG(1) << "gRPC method HandleEcNotificationRequest was successfully"
                     "called on wilco_dtc";
        }));
  }
}

void Core::SendMojoEcEventToBrowser(const MojoEvent& mojo_event) {
  VLOG(1) << "Core::HandleEvent";

  MojoService* mojo_service = mojo_service_factory_->Get();
  if (!mojo_service) {
    LOG(WARNING) << "SendMojoEcEventToBrowser happens before Mojo connection "
                    "is established.";
    return;
  }

  mojo_service->HandleEvent(mojo_event);
}

void Core::NotifyClientsBluetoothAdapterState(
    const std::vector<BluetoothEventService::AdapterData>& adapters) {
  grpc_api::HandleBluetoothDataChangedRequest request;
  for (const auto& adapter : adapters) {
    VLOG(1) << base::StringPrintf(
        "Bluetooth adapter adapter: name=%s addres=%s powered=%d "
        "connected_devices_count=%d",
        adapter.name.c_str(), adapter.address.c_str(), adapter.powered,
        adapter.connected_devices_count);

    auto adapter_data = request.add_adapters();
    adapter_data->set_adapter_name(adapter.name);
    adapter_data->set_adapter_mac_address(adapter.address);
    adapter_data->set_connected_devices_count(adapter.connected_devices_count);
    if (adapter.powered) {
      adapter_data->set_carrier_status(
          grpc_api::HandleBluetoothDataChangedRequest::AdapterData::STATUS_UP);
    } else {
      adapter_data->set_carrier_status(
          grpc_api::HandleBluetoothDataChangedRequest::AdapterData::
              STATUS_DOWN);
    }
  }

  for (auto& client : grpc_client_manager_->GetClients()) {
    client->CallRpc(
        &grpc_api::WilcoDtc::Stub::AsyncHandleBluetoothDataChanged, request,
        base::BindOnce(
            [](grpc::Status status,
               std::unique_ptr<grpc_api::HandleBluetoothDataChangedResponse>
                   response) {
              if (!status.ok()) {
                VLOG(1) << "Failed to call HandleBluetoothDataChanged gRPC "
                           "method on wilco_dtc. grpc error code: "
                        << status.error_code()
                        << ", error message: " << status.error_message();
                return;
              }
              VLOG(1) << "gRPC method HandleBluetoothDataChanged was "
                         "successfully called on wilco_dtc";
            }));
  }
}

void Core::UnsubscribeFromEventServices() {
  if (bluetooth_event_service_) {
    bluetooth_event_service_->RemoveObserver(this);
  }
  if (powerd_event_service_) {
    powerd_event_service_->RemoveObserver(this);
  }
  ec_service_->RemoveObserver(this);
}

}  // namespace wilco
}  // namespace diagnostics
