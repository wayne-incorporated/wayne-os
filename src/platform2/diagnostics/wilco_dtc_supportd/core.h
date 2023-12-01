// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_CORE_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_CORE_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/strings/string_piece.h>
#include <brillo/grpc/async_grpc_client.h>
#include <brillo/grpc/async_grpc_server.h>
#include <dbus/bus.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>

#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"
#include "diagnostics/mojom/public/wilco_dtc_supportd.mojom.h"
#include "diagnostics/wilco_dtc_supportd/dbus_service.h"
#include "diagnostics/wilco_dtc_supportd/grpc_service.h"
#include "diagnostics/wilco_dtc_supportd/mojo_service.h"
#include "diagnostics/wilco_dtc_supportd/probe_service.h"
#include "diagnostics/wilco_dtc_supportd/routine_service.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/bluetooth_event_service.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/ec_service.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/powerd_event_service.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/bluetooth_client.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/debugd_adapter.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/powerd_adapter.h"
#include "wilco_dtc.grpc.pb.h"           // NOLINT(build/include_directory)
#include "wilco_dtc_supportd.grpc.pb.h"  // NOLINT(build/include_directory)

namespace diagnostics {
namespace wilco {

class GrpcClientManager;
class MojoServiceFactory;

// Integrates together all pieces which implement separate IPC services exposed
// by the wilco_dtc_supportd daemon and IPC clients.
class Core final : public GrpcService::Delegate,
                   public ProbeService::Delegate,
                   public RoutineService::Delegate,
                   public BluetoothEventService::Observer,
                   public EcService::Observer,
                   public PowerdEventService::Observer {
 public:
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Creates BluetoothClient. For performance reason, must be called no more
    // than once.
    virtual std::unique_ptr<BluetoothClient> CreateBluetoothClient(
        const scoped_refptr<dbus::Bus>& bus) = 0;

    // Creates DebugdAdapter. For performance reason, must be called no more
    // than once.
    virtual std::unique_ptr<DebugdAdapter> CreateDebugdAdapter(
        const scoped_refptr<dbus::Bus>& bus) = 0;

    // Creates PowerdAdapter. For performance reason, must be called no more
    // than once.
    virtual std::unique_ptr<PowerdAdapter> CreatePowerdAdapter(
        const scoped_refptr<dbus::Bus>& bus) = 0;

    // Creates BluetoothEventService. For performance reason, must be called no
    // more than once.
    virtual std::unique_ptr<BluetoothEventService> CreateBluetoothEventService(
        BluetoothClient* bluetooth_client) = 0;

    // Creates EcService. For performance reason, must be called no
    // more than once.
    virtual std::unique_ptr<EcService> CreateEcService() = 0;

    // Creates PowerdEventService. For performance reason, must be called no
    // more than once.
    virtual std::unique_ptr<PowerdEventService> CreatePowerdEventService(
        PowerdAdapter* powerd_adapter) = 0;

    // Creates ProbeService. For performance reason, must be called no
    // more than once.
    virtual std::unique_ptr<ProbeService> CreateProbeService(
        ProbeService::Delegate* delegate) = 0;
  };

  // |grpc_service_uris| are the URIs on which the gRPC interface exposed by the
  // wilco_dtc_supportd daemon will be listening.
  Core(Delegate* delegate,
       const GrpcClientManager* grpc_client_manager,
       const std::vector<std::string>& grpc_service_uris,
       MojoServiceFactory* mojo_service_factory);
  Core(const Core&) = delete;
  Core& operator=(const Core&) = delete;

  ~Core() override;

  // Overrides the file system root directory for file operations in tests.
  void set_root_dir_for_testing(const base::FilePath& root_dir) {
    ec_service_->set_root_dir_for_testing(root_dir);
    grpc_service_.set_root_dir_for_testing(root_dir);
  }

  // Starts gRPC servers, gRPC clients and EC event service.
  bool Start();

  // Performs asynchronous shutdown and cleanup of gRPC servers
  // and EC event service. Destroys |dbus_object_| object.
  // This must be used before deleting this instance in case Start() was
  // called and returned success - in that case, the instance must be
  // destroyed only after |on_shutdown_callback| has been called.
  void ShutDown(base::OnceClosure on_shutdown_callback);

  // Creates the D-Bus adapters.
  void CreateDbusAdapters(const scoped_refptr<dbus::Bus>& bus);

 private:
  using MojoEvent = chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdEvent;
  using MojomWilcoDtcSupportdClient =
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdClient;
  using MojomWilcoDtcSupportdService =
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdService;

  // WilcoDtcSupportdGrpcService::Delegate overrides:
  void SendWilcoDtcMessageToUi(const std::string& json_message,
                               SendMessageToUiCallback callback) override;
  void PerformWebRequestToBrowser(
      WebRequestHttpMethod http_method,
      const std::string& url,
      const std::vector<std::string>& headers,
      const std::string& request_body,
      PerformWebRequestToBrowserCallback callback) override;
  void GetAvailableRoutinesToService(
      GetAvailableRoutinesToServiceCallback callback) override;
  void RunRoutineToService(const grpc_api::RunRoutineRequest& request,
                           RunRoutineToServiceCallback callback) override;
  void GetRoutineUpdateRequestToService(
      int uuid,
      grpc_api::GetRoutineUpdateRequest::Command command,
      bool include_output,
      GetRoutineUpdateRequestToServiceCallback callback) override;
  void GetConfigurationDataFromBrowser(
      GetConfigurationDataFromBrowserCallback callback) override;
  void GetDriveSystemData(DriveSystemDataType data_type,
                          GetDriveSystemDataCallback callback) override;
  void RequestBluetoothDataNotification() override;
  void ProbeTelemetryInfo(
      std::vector<ash::cros_healthd::mojom::ProbeCategoryEnum> categories,
      ProbeTelemetryInfoCallback callback) override;
  EcService* GetEcService() override;

  // ProbeService::Delegate overrides:
  bool BindCrosHealthdProbeService(
      mojo::PendingReceiver<ash::cros_healthd::mojom::CrosHealthdProbeService>
          service) override;

  // RoutineService::Delegate overrides:
  bool GetCrosHealthdDiagnosticsService(
      mojo::PendingReceiver<
          ash::cros_healthd::mojom::CrosHealthdDiagnosticsService> service)
      override;

  // BluetoothEventService::Observer overrides:
  void BluetoothAdapterDataChanged(
      const std::vector<BluetoothEventService::AdapterData>& adapters) override;

  // EcService::Observer overrides:
  void OnEcEvent(const EcService::EcEvent& ec_event) override;

  // PowerdEventService::Observer overrides:
  void OnPowerdEvent(PowerEventType type) override;

  // OnEcEvent should trigger the following:
  void SendGrpcEcEventToWilcoDtc(const EcService::EcEvent& ec_event);
  void SendMojoEcEventToBrowser(const MojoEvent& mojo_event);

  // Called by BluetoothAdapterDataChanged and RequestBluetoothDataNotification.
  void NotifyClientsBluetoothAdapterState(
      const std::vector<BluetoothEventService::AdapterData>& adapters);

  // Unsubscribes Core from observing events in preparation to shut down.
  void UnsubscribeFromEventServices();

  // Unowned. The delegate should outlive this instance.
  Delegate* const delegate_;

  // gRPC-related members:

  // Unowned.
  // Allows to make outgoing requests to the gRPC interfaces exposed by the
  // wilco_dtc daemons.
  const GrpcClientManager* grpc_client_manager_;
  // gRPC URIs on which the |grpc_server_| is listening for incoming requests.
  const std::vector<std::string> grpc_service_uris_;
  // Implementation of the gRPC interface exposed by the wilco_dtc_supportd
  // daemon.
  GrpcService grpc_service_{this /* delegate */};
  // Connects |grpc_service_| with the gRPC server that listens for incoming
  // requests.
  brillo::AsyncGrpcServer<grpc_api::WilcoDtcSupportd::AsyncService>
      grpc_server_;

  // Mojo-related members:

  // Unowned. Provides mojo service (after being bootstrapped).
  MojoServiceFactory* mojo_service_factory_ = nullptr;

  // D-Bus adapters for system daemons.
  std::unique_ptr<BluetoothClient> bluetooth_client_;
  std::unique_ptr<DebugdAdapter> debugd_adapter_;
  std::unique_ptr<PowerdAdapter> powerd_adapter_;

  // Telemetry services:
  std::unique_ptr<BluetoothEventService> bluetooth_event_service_;
  std::unique_ptr<EcService> ec_service_;
  std::unique_ptr<PowerdEventService> powerd_event_service_;

  // Diagnostic routine-related members:

  // Implementation of the diagnostic routine interface exposed by the
  // wilco_dtc_supportd daemon.
  RoutineService routine_service_{this /* delegate */};

  std::unique_ptr<ProbeService> probe_service_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_CORE_H_
