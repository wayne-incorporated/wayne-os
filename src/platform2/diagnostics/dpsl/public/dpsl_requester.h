// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_PUBLIC_DPSL_REQUESTER_H_
#define DIAGNOSTICS_DPSL_PUBLIC_DPSL_REQUESTER_H_

#include <functional>
#include <memory>

#include "wilco_dtc_supportd.pb.h"  // NOLINT(build/include_directory)

namespace diagnostics {

class DpslThreadContext;

// Interface of the class that allows to make outgoing requests to the
// gRPC server ran by the wilco_dtc_supportd daemon (the interface is defined at
// grpc/wilco_dtc_supportd.proto).
//
// On construction, starts a gRPC client that connects to the wilco_dtc_supportd
// daemon on the specified URI. When a request is made, DPSL sends it and
// immediately returns; after the response arrives, the DPSL puts a task into
// the event loop that invokes the specified callback.
//
// Obtain an instance of this class via the Create() method.
//
// EXAMPLE USAGE:
//
//   auto thread_context = DpslThreadContext::Create(...);
//   auto requester = DpslRequester::Create(thread_context.get(), ...);
//   if (!requester) {
//     ... // Handle error
//   }
//   requester->GetProcData(
//       ...,
//       [](std::unique_ptr<grpc_api::GetProcDataResponse> response){
//         ... // custom logic
//       });
//   thread_context->RunEventLoop();
//
// NOTE ON THREADING MODEL: This class is generally thread-safe, except that it
// must be created and destroyed on the same thread. The response callbacks are
// always executed on the thread on which this class was created (even when the
// request was made from a different thread).
//
// NOTE ON REQUESTS SEQUENCE: Parallel requests are allowed: i.e., it's OK to
// start a new request before the result of the previous one arrives. DPSL
// does NOT guarantee any particular ordering for the responses arrival in that
// case.
//
// PRECONDITIONS:
// 1. An instance of DpslThreadContext must exist on the current thread during
//    the whole lifetime of this object.
class DpslRequester {
 public:
  // Specifies predefined options for the URI which should be used for the
  // created gRPC client for making requests.
  enum class GrpcClientUri {
    // A Unix domain socket at the predefined constant path. This option is
    // available only when running OUTSIDE a VM.
    // Only one client with this URI may run at a time; breaking this
    // requirement will lead to unspecified behavior.
    kLocalDomainSocket = 0,

    // A vsock URI for communicating across the VM boundary. This option is
    // available only when running INSIDE a VM.
    kVmVsock = 1,
  };

  // Request-specific callback types. These callbacks are called by DPSL when a
  // response arrives to the corresponding request.
  //
  // NOTE ON THREADING: The callbacks are always called by DPSL on the thread on
  // which the class was created.
  //
  // When the request fails, DPSL calls the callback with |response| being null.
  using SendMessageToUiCallback = std::function<void(
      std::unique_ptr<grpc_api::SendMessageToUiResponse> response)>;
  using GetProcDataCallback = std::function<void(
      std::unique_ptr<grpc_api::GetProcDataResponse> response)>;
  using GetSysfsDataCallback = std::function<void(
      std::unique_ptr<grpc_api::GetSysfsDataResponse> response)>;
  using PerformWebRequestCallback = std::function<void(
      std::unique_ptr<grpc_api::PerformWebRequestResponse> response)>;
  using GetEcTelemetryRequestCallback = std::function<void(
      std::unique_ptr<grpc_api::GetEcTelemetryResponse> response)>;
  using GetAvailableRoutinesCallback = std::function<void(
      std::unique_ptr<grpc_api::GetAvailableRoutinesResponse> response)>;
  using RunRoutineCallback = std::function<void(
      std::unique_ptr<grpc_api::RunRoutineResponse> response)>;
  using GetRoutineUpdateCallback = std::function<void(
      std::unique_ptr<grpc_api::GetRoutineUpdateResponse> response)>;
  using GetOsVersionCallback = std::function<void(
      std::unique_ptr<grpc_api::GetOsVersionResponse> response)>;
  using GetConfigurationDataCallback = std::function<void(
      std::unique_ptr<grpc_api::GetConfigurationDataResponse> response)>;
  using GetVpdFieldCallback = std::function<void(
      std::unique_ptr<grpc_api::GetVpdFieldResponse> response)>;
  using GetDriveSystemDataCallback = std::function<void(
      std::unique_ptr<grpc_api::GetDriveSystemDataResponse> response)>;
  using RequestBluetoothDataNotificationCallback = std::function<void(
      std::unique_ptr<grpc_api::RequestBluetoothDataNotificationResponse>
          response)>;
  using GetStatefulPartitionAvailableCapacityCallback = std::function<void(
      std::unique_ptr<grpc_api::GetStatefulPartitionAvailableCapacityResponse>
          response)>;

  // Factory method that returns an instance of the real implementation of this
  // interface.
  //
  // Returns a null pointer when the construction fails (for example, when the
  // specified URI is unavailable).
  //
  // |thread_context| is passed as an unowned pointer; it must outlive the
  // created DpslRequester instance.
  static std::unique_ptr<DpslRequester> Create(
      DpslThreadContext* thread_context, GrpcClientUri grpc_client_uri);

  virtual ~DpslRequester() = default;

  // Methods of the WilcoDtcSupportd gRPC interface.
  //
  // NOTE ON THREADING: These methods are allowed to be called from any thread
  // (even from ones without a DpslThreadContext instance). However, the
  // callbacks will always be called by DPSL on the thread on which the class
  // was created.

  virtual void SendMessageToUi(
      std::unique_ptr<grpc_api::SendMessageToUiRequest> request,
      SendMessageToUiCallback callback) = 0;
  virtual void GetProcData(
      std::unique_ptr<grpc_api::GetProcDataRequest> request,
      GetProcDataCallback callback) = 0;
  virtual void GetSysfsData(
      std::unique_ptr<grpc_api::GetSysfsDataRequest> request,
      GetSysfsDataCallback callback) = 0;
  virtual void PerformWebRequest(
      std::unique_ptr<grpc_api::PerformWebRequestParameter> request,
      PerformWebRequestCallback callback) = 0;
  virtual void GetEcTelemetry(
      std::unique_ptr<grpc_api::GetEcTelemetryRequest> request,
      GetEcTelemetryRequestCallback callback) = 0;
  virtual void GetAvailableRoutines(
      std::unique_ptr<grpc_api::GetAvailableRoutinesRequest> request,
      GetAvailableRoutinesCallback callback) = 0;
  virtual void RunRoutine(std::unique_ptr<grpc_api::RunRoutineRequest> request,
                          RunRoutineCallback callback) = 0;
  virtual void GetRoutineUpdate(
      std::unique_ptr<grpc_api::GetRoutineUpdateRequest> request,
      GetRoutineUpdateCallback callback) = 0;
  virtual void GetOsVersion(
      std::unique_ptr<grpc_api::GetOsVersionRequest> request,
      GetOsVersionCallback callback) = 0;
  virtual void GetConfigurationData(
      std::unique_ptr<grpc_api::GetConfigurationDataRequest> request,
      GetConfigurationDataCallback callback) = 0;
  virtual void GetVpdField(
      std::unique_ptr<grpc_api::GetVpdFieldRequest> request,
      GetVpdFieldCallback callback) = 0;
  virtual void GetDriveSystemData(
      std::unique_ptr<grpc_api::GetDriveSystemDataRequest> request,
      GetDriveSystemDataCallback callback) = 0;
  virtual void RequestBluetoothDataNotification(
      std::unique_ptr<grpc_api::RequestBluetoothDataNotificationRequest>
          request,
      RequestBluetoothDataNotificationCallback callback) = 0;
  virtual void GetStatefulPartitionAvailableCapacity(
      std::unique_ptr<grpc_api::GetStatefulPartitionAvailableCapacityRequest>
          request,
      GetStatefulPartitionAvailableCapacityCallback callback) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_PUBLIC_DPSL_REQUESTER_H_
