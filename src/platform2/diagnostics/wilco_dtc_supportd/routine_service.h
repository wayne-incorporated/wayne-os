// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_ROUTINE_SERVICE_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_ROUTINE_SERVICE_H_

#include <cstddef>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "wilco_dtc_supportd.pb.h"  // NOLINT(build/include_directory)

namespace diagnostics {
namespace wilco {

// The routine service is responsible for creating and managing diagnostic
// routines.
class RoutineService final {
 public:
  using GetAvailableRoutinesToServiceCallback = base::OnceCallback<void(
      const std::vector<grpc_api::DiagnosticRoutine>& routines,
      grpc_api::RoutineServiceStatus service_status)>;
  using RunRoutineToServiceCallback =
      base::OnceCallback<void(int uuid,
                              grpc_api::DiagnosticRoutineStatus status,
                              grpc_api::RoutineServiceStatus service_status)>;
  using GetRoutineUpdateRequestToServiceCallback = base::OnceCallback<void(
      int uuid,
      grpc_api::DiagnosticRoutineStatus status,
      int progress_percent,
      grpc_api::DiagnosticRoutineUserMessage user_message,
      const std::string& output,
      const std::string& status_message,
      grpc_api::RoutineServiceStatus service_status)>;

  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Binds |service| to an implementation of CrosHealthdDiagnosticsService. In
    // production, the implementation is provided by cros_healthd. Returns false
    // if wilco_dtc_supportd's mojo service has not been started by Chrome at
    // the time this is called.
    virtual bool GetCrosHealthdDiagnosticsService(
        mojo::PendingReceiver<
            ash::cros_healthd::mojom::CrosHealthdDiagnosticsService>
            service) = 0;
  };

  // |delegate| - Unowned pointer; must outlive this instance.
  explicit RoutineService(Delegate* delegate);
  RoutineService(const RoutineService&) = delete;
  RoutineService& operator=(const RoutineService&) = delete;

  ~RoutineService();

  void GetAvailableRoutines(GetAvailableRoutinesToServiceCallback callback);
  void RunRoutine(const grpc_api::RunRoutineRequest& request,
                  RunRoutineToServiceCallback callback);
  void GetRoutineUpdate(int uuid,
                        grpc_api::GetRoutineUpdateRequest::Command command,
                        bool include_output,
                        GetRoutineUpdateRequestToServiceCallback callback);

 private:
  // Forwards and wraps the result of a GetAvailableRoutines call into a gRPC
  // response.
  void ForwardGetAvailableRoutinesResponse(
      size_t callback_key,
      const std::vector<ash::cros_healthd::mojom::DiagnosticRoutineEnum>&
          mojo_routines);
  // Forwards and wraps the result of a RunRoutine call into a gRPC response.
  void ForwardRunRoutineResponse(
      size_t callback_key,
      ash::cros_healthd::mojom::RunRoutineResponsePtr response);
  // Forwards and wraps the result of a GetRoutineUpdate call into a gRPC
  // response.
  void ForwardGetRoutineUpdateResponse(
      size_t callback_key, ash::cros_healthd::mojom::RoutineUpdatePtr response);

  // Binds |service_ptr_| to an implementation of CrosHealthdDiagnosticsService,
  // if it is not already bound. Returns false if wilco_dtc_supportd's mojo
  // service is not yet running and the binding cannot be attempted.
  bool BindCrosHealthdDiagnosticsServiceIfNeeded();
  // Disconnect handler called if the mojo connection to cros_healthd is lost.
  void OnDisconnect();
  // Runs all in flight callbacks.
  void RunInFlightCallbacks();

  // Unowned. Should outlive this instance.
  Delegate* delegate_ = nullptr;

  // Mojo interface to the CrosHealthdDiagnosticsService endpoint.
  //
  // In production this interface is implemented by the cros_healthd process.
  mojo::Remote<ash::cros_healthd::mojom::CrosHealthdDiagnosticsService>
      service_;

  // The following three maps each hold in flight callbacks to |service_ptr_|.
  // In case the remote mojo endpoint closes while there are any in flight
  // callbacks, the disconnect handler will call those callbacks with error
  // responses. This allows wilco_dtc_supportd to remain responsive if
  // cros_healthd dies.
  std::unordered_map<size_t, GetAvailableRoutinesToServiceCallback>
      get_available_routines_callbacks_;
  std::unordered_map<size_t, RunRoutineToServiceCallback>
      run_routine_callbacks_;
  // This map needs to also store the uuids, so the callbacks can be run from
  // inside the disconnect handler, which otherwise doesn't have access to the
  // uuid.
  std::unordered_map<size_t,
                     std::pair<int, GetRoutineUpdateRequestToServiceCallback>>
      get_routine_update_callbacks_;

  // Generators for the keys used in the in flight callback maps. Note that our
  // generation is very simple - just increment the appropriate generator when
  // a call is dispatched to cros_healthd. Since the maps are only tracking
  // callbacks which are in flight, we don't anticipate having very many stored
  // at a time, and there should never be collisions if size_t wraps back
  // around to zero. If a collision were to happen, wilco_dtc_supportd would
  // just restart.
  size_t next_get_available_routines_key_ = 0;
  size_t next_run_routine_key_ = 0;
  size_t next_get_routine_update_key_ = 0;

  // Must be the last class member.
  base::WeakPtrFactory<RoutineService> weak_ptr_factory_{this};
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_ROUTINE_SERVICE_H_
