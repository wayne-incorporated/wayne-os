// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_INTERNAL_DPSL_REQUESTER_IMPL_H_
#define DIAGNOSTICS_DPSL_INTERNAL_DPSL_REQUESTER_IMPL_H_

#include <functional>
#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/scoped_refptr.h>
#include <base/memory/weak_ptr.h>
#include <base/sequence_checker_impl.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/grpc/async_grpc_client.h>

#include "diagnostics/dpsl/public/dpsl_requester.h"

#include "wilco_dtc_supportd.grpc.pb.h"  // NOLINT(build/include_directory)

namespace diagnostics {

// Real implementation of the DpslRequester interface.
class DpslRequesterImpl final : public DpslRequester {
 public:
  static std::string GetWilcoDtcSupportdGrpcUri(
      DpslRequester::GrpcClientUri grpc_client_uri);

  explicit DpslRequesterImpl(const std::string& wilco_dtc_supportd_grpc_uri);
  DpslRequesterImpl(const DpslRequesterImpl&) = delete;
  DpslRequesterImpl& operator=(const DpslRequesterImpl&) = delete;

  ~DpslRequesterImpl() override;

  // DpslRequester overrides:
  void SendMessageToUi(
      std::unique_ptr<grpc_api::SendMessageToUiRequest> request,
      SendMessageToUiCallback callback) override;
  void GetProcData(std::unique_ptr<grpc_api::GetProcDataRequest> request,
                   GetProcDataCallback callback) override;
  void GetSysfsData(std::unique_ptr<grpc_api::GetSysfsDataRequest> request,
                    GetSysfsDataCallback callback) override;
  void PerformWebRequest(
      std::unique_ptr<grpc_api::PerformWebRequestParameter> request,
      PerformWebRequestCallback callback) override;
  void GetEcTelemetry(std::unique_ptr<grpc_api::GetEcTelemetryRequest> request,
                      GetEcTelemetryRequestCallback callback) override;
  void GetAvailableRoutines(
      std::unique_ptr<grpc_api::GetAvailableRoutinesRequest> request,
      GetAvailableRoutinesCallback callback) override;
  void RunRoutine(std::unique_ptr<grpc_api::RunRoutineRequest> request,
                  RunRoutineCallback callback) override;
  void GetRoutineUpdate(
      std::unique_ptr<grpc_api::GetRoutineUpdateRequest> request,
      GetRoutineUpdateCallback callback) override;
  void GetOsVersion(std::unique_ptr<grpc_api::GetOsVersionRequest> request,
                    GetOsVersionCallback callback) override;
  void GetConfigurationData(
      std::unique_ptr<grpc_api::GetConfigurationDataRequest> request,
      GetConfigurationDataCallback callback) override;
  void GetVpdField(std::unique_ptr<grpc_api::GetVpdFieldRequest> request,
                   GetVpdFieldCallback callback) override;
  void GetDriveSystemData(
      std::unique_ptr<grpc_api::GetDriveSystemDataRequest> request,
      GetDriveSystemDataCallback callback) override;
  void RequestBluetoothDataNotification(
      std::unique_ptr<grpc_api::RequestBluetoothDataNotificationRequest>
          request,
      RequestBluetoothDataNotificationCallback callback) override;
  void GetStatefulPartitionAvailableCapacity(
      std::unique_ptr<grpc_api::GetStatefulPartitionAvailableCapacityRequest>
          request,
      GetStatefulPartitionAvailableCapacityCallback callback) override;

 private:
  using AsyncGrpcWilcoDtcSupportdClient =
      brillo::AsyncGrpcClient<grpc_api::WilcoDtcSupportd>;

  // Posts a task to the main thread that runs CallGrpcClientMethod() with the
  // specified arguments.
  //
  // Note: this method can be called from any thread.
  template <typename GrpcStubMethod,
            typename RequestType,
            typename ResponseType>
  void ScheduleGrpcClientMethodCall(
      const base::Location& location,
      GrpcStubMethod grpc_stub_method,
      std::unique_ptr<RequestType> request,
      std::function<void(std::unique_ptr<ResponseType>)> response_callback);

  // Runs |async_grpc_client_|'s CallRpc() method with the specified arguments.
  template <typename GrpcStubMethod,
            typename RequestType,
            typename ResponseType>
  void CallGrpcClientMethod(
      GrpcStubMethod grpc_stub_method,
      std::unique_ptr<RequestType> request,
      base::OnceCallback<void(grpc::Status, std::unique_ptr<ResponseType>)>
          response_callback);

  // Task runner of the main thread (on which this instance was created).
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  AsyncGrpcWilcoDtcSupportdClient async_grpc_client_;

  // Whether Shutdown() was already called on |async_grpc_client_|.
  bool async_grpc_client_shutting_down_ = false;

  base::SequenceCheckerImpl sequence_checker_;

  // Must be the last member.
  base::WeakPtrFactory<DpslRequesterImpl> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_INTERNAL_DPSL_REQUESTER_IMPL_H_
