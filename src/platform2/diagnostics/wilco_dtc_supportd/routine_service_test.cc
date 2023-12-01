// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/wilco_dtc_supportd/fake_diagnostics_service.h"
#include "diagnostics/wilco_dtc_supportd/routine_service.h"

namespace diagnostics {
namespace wilco {
namespace {

namespace mojo_ipc = ::ash::cros_healthd::mojom;
using ::testing::ElementsAreArray;

grpc_api::RunRoutineRequest MakeBatteryRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_BATTERY);
  request.mutable_battery_params()->set_low_mah(10);
  request.mutable_battery_params()->set_high_mah(100);
  return request;
}

grpc_api::RunRoutineRequest MakeDefaultBatteryRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_BATTERY);
  request.mutable_battery_params();
  return request;
}

grpc_api::RunRoutineRequest MakeBatterySysfsRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_BATTERY_SYSFS);
  request.mutable_battery_sysfs_params()->set_maximum_cycle_count(2);
  request.mutable_battery_sysfs_params()->set_percent_battery_wear_allowed(30);
  return request;
}

grpc_api::RunRoutineRequest MakeUrandomRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_URANDOM);
  request.mutable_urandom_params()->set_length_seconds(10);
  return request;
}

grpc_api::RunRoutineRequest MakeSmartctlCheckRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_SMARTCTL_CHECK);
  request.mutable_smartctl_check_params();
  return request;
}

grpc_api::RunRoutineRequest MakeCpuCacheRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_CPU_CACHE);
  request.mutable_cpu_params()->set_length_seconds(10);
  return request;
}

grpc_api::RunRoutineRequest MakeCpuStressRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_CPU_STRESS);
  request.mutable_cpu_params()->set_length_seconds(300);
  return request;
}

grpc_api::RunRoutineRequest MakeFloatingPointAccuracyRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_FLOATING_POINT_ACCURACY);
  request.mutable_floating_point_accuracy_params()->set_length_seconds(2);
  return request;
}

grpc_api::RunRoutineRequest MakeNvmeWearLevelRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_NVME_WEAR_LEVEL);
  request.mutable_nvme_wear_level_params()->set_wear_level_threshold(50);
  return request;
}
grpc_api::RunRoutineRequest MakeNvmeSelfTestShortRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_NVME_SHORT_SELF_TEST);
  request.mutable_nvme_short_self_test_params();
  return request;
}

grpc_api::RunRoutineRequest MakeNvmeSelfTestLongRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_NVME_LONG_SELF_TEST);
  request.mutable_nvme_long_self_test_params();
  return request;
}

grpc_api::RunRoutineRequest MakeDiskLinearReadRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_DISK_LINEAR_READ);
  request.mutable_disk_linear_read_params()->set_length_seconds(10);
  request.mutable_disk_linear_read_params()->set_file_size_mb(1024);
  return request;
}

grpc_api::RunRoutineRequest MakeDiskRandomReadRoutineRequest() {
  grpc_api::RunRoutineRequest request;
  request.set_routine(grpc_api::ROUTINE_DISK_RANDOM_READ);
  request.mutable_disk_random_read_params()->set_length_seconds(10);
  request.mutable_disk_random_read_params()->set_file_size_mb(1024);
  return request;
}

void SaveGetAvailableRoutinesResponse(
    base::OnceClosure callback,
    grpc_api::GetAvailableRoutinesResponse* response,
    const std::vector<grpc_api::DiagnosticRoutine>& returned_routines,
    grpc_api::RoutineServiceStatus service_status) {
  for (const auto& routine : returned_routines)
    response->add_routines(routine);
  response->set_service_status(service_status);
  std::move(callback).Run();
}

void SaveRunRoutineResponse(base::OnceClosure callback,
                            grpc_api::RunRoutineResponse* response,
                            int uuid,
                            grpc_api::DiagnosticRoutineStatus status,
                            grpc_api::RoutineServiceStatus service_status) {
  response->set_uuid(uuid);
  response->set_status(status);
  response->set_service_status(service_status);
  std::move(callback).Run();
}

void SaveGetRoutineUpdateResponse(
    base::OnceClosure callback,
    grpc_api::GetRoutineUpdateResponse* response,
    int uuid,
    grpc_api::DiagnosticRoutineStatus status,
    int progress_percent,
    grpc_api::DiagnosticRoutineUserMessage user_message,
    const std::string& output,
    const std::string& status_message,
    grpc_api::RoutineServiceStatus service_status) {
  response->set_uuid(uuid);
  response->set_status(status);
  response->set_progress_percent(progress_percent);
  response->set_user_message(user_message);
  response->set_output(output);
  response->set_status_message(status_message);
  response->set_service_status(service_status);
  std::move(callback).Run();
}

// Tests for the RoutineService class.
class RoutineServiceTest : public testing::Test {
 protected:
  RoutineServiceTest() = default;

  FakeDiagnosticsService* diagnostics_service() {
    return &diagnostics_service_;
  }

  grpc_api::GetAvailableRoutinesResponse ExecuteGetAvailableRoutines() {
    base::RunLoop run_loop;
    grpc_api::GetAvailableRoutinesResponse response;
    service_.GetAvailableRoutines(base::BindOnce(
        &SaveGetAvailableRoutinesResponse, run_loop.QuitClosure(), &response));
    run_loop.Run();
    return response;
  }

  grpc_api::RunRoutineResponse ExecuteRunRoutine(
      const grpc_api::RunRoutineRequest& request) {
    base::RunLoop run_loop;
    grpc_api::RunRoutineResponse response;
    service_.RunRoutine(
        request, base::BindOnce(&SaveRunRoutineResponse, run_loop.QuitClosure(),
                                &response));
    run_loop.Run();
    return response;
  }

  grpc_api::GetRoutineUpdateResponse ExecuteGetRoutineUpdate(
      const int uuid,
      const grpc_api::GetRoutineUpdateRequest::Command command,
      const bool include_output) {
    base::RunLoop run_loop;
    grpc_api::GetRoutineUpdateResponse response;
    service_.GetRoutineUpdate(
        uuid, command, include_output,
        base::BindOnce(&SaveGetRoutineUpdateResponse, run_loop.QuitClosure(),
                       &response));
    run_loop.Run();
    return response;
  }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  FakeDiagnosticsService diagnostics_service_;
  RoutineService service_{&diagnostics_service_};
};

// Test that GetAvailableRoutines returns the expected list of routines.
TEST_F(RoutineServiceTest, GetAvailableRoutines) {
  diagnostics_service()->SetGetAvailableRoutinesResponse(
      {mojo_ipc::DiagnosticRoutineEnum::kBatteryCapacity,
       mojo_ipc::DiagnosticRoutineEnum::kBatteryHealth,
       mojo_ipc::DiagnosticRoutineEnum::kSmartctlCheck,
       mojo_ipc::DiagnosticRoutineEnum::kUrandom,
       mojo_ipc::DiagnosticRoutineEnum::kCpuCache,
       mojo_ipc::DiagnosticRoutineEnum::kCpuStress,
       mojo_ipc::DiagnosticRoutineEnum::kFloatingPointAccuracy,
       mojo_ipc::DiagnosticRoutineEnum::kNvmeWearLevel,
       mojo_ipc::DiagnosticRoutineEnum::kNvmeSelfTest,
       mojo_ipc::DiagnosticRoutineEnum::kDiskRead});

  const auto reply = ExecuteGetAvailableRoutines();
  EXPECT_THAT(reply.routines(),
              ElementsAreArray(
                  {grpc_api::ROUTINE_BATTERY, grpc_api::ROUTINE_BATTERY_SYSFS,
                   grpc_api::ROUTINE_SMARTCTL_CHECK, grpc_api::ROUTINE_URANDOM,
                   grpc_api::ROUTINE_CPU_CACHE, grpc_api::ROUTINE_CPU_STRESS,
                   grpc_api::ROUTINE_FLOATING_POINT_ACCURACY,
                   grpc_api::ROUTINE_NVME_WEAR_LEVEL,
                   grpc_api::ROUTINE_NVME_SHORT_SELF_TEST,
                   grpc_api::ROUTINE_NVME_LONG_SELF_TEST,
                   grpc_api::ROUTINE_DISK_LINEAR_READ,
                   grpc_api::ROUTINE_DISK_RANDOM_READ}));
  EXPECT_EQ(reply.service_status(), grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Test that an unknown mojo routine enum is handled sanely.
TEST_F(RoutineServiceTest, GetAvailableRoutinesInvalidMojoRoutineEnum) {
  diagnostics_service()->SetGetAvailableRoutinesResponse(
      std::vector<mojo_ipc::DiagnosticRoutineEnum>{
          static_cast<mojo_ipc::DiagnosticRoutineEnum>(
              std::numeric_limits<std::underlying_type<
                  mojo_ipc::DiagnosticRoutineEnum>::type>::max()),
          mojo_ipc::DiagnosticRoutineEnum::kBatteryCapacity});

  const auto reply = ExecuteGetAvailableRoutines();
  EXPECT_THAT(reply.routines(), ElementsAreArray({grpc_api::ROUTINE_BATTERY}));
  EXPECT_EQ(reply.service_status(), grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Test that an invalid RunRoutineRequest is handled sanely.
TEST_F(RoutineServiceTest, InvalidRunRoutineRequest) {
  grpc_api::RunRoutineRequest request;
  request.set_routine(static_cast<grpc_api::DiagnosticRoutine>(
      std::numeric_limits<
          std::underlying_type<grpc_api::DiagnosticRoutine>::type>::max()));

  const auto reply = ExecuteRunRoutine(request);
  EXPECT_EQ(reply.uuid(), 0);
  EXPECT_EQ(reply.status(), grpc_api::ROUTINE_STATUS_INVALID_FIELD);
  EXPECT_EQ(reply.service_status(), grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Test that a routine reporting an invalid user message is handled sanely.
TEST_F(RoutineServiceTest, GetRoutineUpdateInvalidUserMessage) {
  diagnostics_service()->SetInteractiveUpdate(
      static_cast<mojo_ipc::DiagnosticRoutineUserMessageEnum>(
          std::numeric_limits<std::underlying_type<
              mojo_ipc::DiagnosticRoutineUserMessageEnum>::type>::max()),
      0 /* progress_percent */, "" /* output */);

  const auto update_response = ExecuteGetRoutineUpdate(
      0 /* uuid */, grpc_api::GetRoutineUpdateRequest::GET_STATUS,
      false /* include_output */);
  EXPECT_EQ(update_response.status(), grpc_api::ROUTINE_STATUS_ERROR);
  EXPECT_EQ(update_response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Test that a routine update reporting an invalid status is handled sanely.
TEST_F(RoutineServiceTest, InvalidGetRoutineUpdateStatus) {
  diagnostics_service()->SetNonInteractiveUpdate(
      static_cast<mojo_ipc::DiagnosticRoutineStatusEnum>(
          std::numeric_limits<std::underlying_type<
              mojo_ipc::DiagnosticRoutineStatusEnum>::type>::max()),
      "" /* status_message */, 0 /* progress_percent */, "" /* output */);

  const auto update_response = ExecuteGetRoutineUpdate(
      0 /* uuid */, grpc_api::GetRoutineUpdateRequest::GET_STATUS,
      false /* include_output */);
  EXPECT_EQ(update_response.status(), grpc_api::ROUTINE_STATUS_ERROR);
  EXPECT_EQ(update_response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Test that a run routine response reporting an invalid status is handled
// sanely.
TEST_F(RoutineServiceTest, InvalidRunRoutineResponseStatus) {
  diagnostics_service()->SetRunSomeRoutineResponse(
      0 /* uuid */,
      static_cast<mojo_ipc::DiagnosticRoutineStatusEnum>(
          std::numeric_limits<std::underlying_type<
              mojo_ipc::DiagnosticRoutineStatusEnum>::type>::max()));

  const auto response = ExecuteRunRoutine(MakeSmartctlCheckRoutineRequest());
  EXPECT_EQ(response.status(), grpc_api::ROUTINE_STATUS_ERROR);
  EXPECT_EQ(response.uuid(), 0);
  EXPECT_EQ(response.service_status(), grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Test that an invalid command passed to the routine service is handled sanely.
TEST_F(RoutineServiceTest, GetRoutineUpdateInvalidCommand) {
  diagnostics_service()->SetNonInteractiveUpdate(
      mojo_ipc::DiagnosticRoutineStatusEnum::kReady, "" /* status_message */,
      0 /* progress_percent */, "" /* output */);

  const auto update_response = ExecuteGetRoutineUpdate(
      0 /* uuid */,
      static_cast<grpc_api::GetRoutineUpdateRequest::Command>(
          std::numeric_limits<std::underlying_type<
              grpc_api::GetRoutineUpdateRequest::Command>::type>::max()),
      false /* include_output */);
  EXPECT_EQ(update_response.status(), grpc_api::ROUTINE_STATUS_INVALID_FIELD);
  EXPECT_EQ(update_response.progress_percent(), 0);
  EXPECT_EQ(update_response.user_message(),
            grpc_api::ROUTINE_USER_MESSAGE_UNSET);
  EXPECT_EQ(update_response.output(), "");
  EXPECT_EQ(update_response.status_message(), "");
  EXPECT_EQ(update_response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Test that the routine service doesn't attempt to rebind a valid mojo service
// pointer.
TEST_F(RoutineServiceTest, NoRebindService) {
  constexpr uint32_t kExpectedId = 55;
  diagnostics_service()->SetRunSomeRoutineResponse(
      kExpectedId, mojo_ipc::DiagnosticRoutineStatusEnum::kRunning);
  // Send the first mojo IPC to the diagnostics service. This IPC should
  // bootstrap the mojo connection. Ignore the response, because we're only
  // interested in whether or not the next request tries to bootstrap the mojo
  // connection again.
  ExecuteRunRoutine(MakeSmartctlCheckRoutineRequest());

  // Tell the service to respond with an error if a second bootstrapping is
  // requested.
  diagnostics_service()->SetMojoServiceIsAvailable(false);

  // Send another request. This shouldn't see an error, because it shouldn't try
  // to bootstrap the mojo connection a second time.
  const auto reply = ExecuteRunRoutine(MakeSmartctlCheckRoutineRequest());

  // If the bootstrap was requested a second time, we would receive a uuid of 0
  // and a status of grpc_api::FAILED_TO_START.
  EXPECT_EQ(reply.uuid(), kExpectedId);
  EXPECT_EQ(reply.status(), grpc_api::ROUTINE_STATUS_RUNNING);
  EXPECT_EQ(reply.service_status(), grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Test that the routine service handles a GetAvailableRoutines request sent
// before wilco_dtc_supportd's mojo service is established.
TEST_F(RoutineServiceTest, GetAvailableRoutinesNoService) {
  diagnostics_service()->SetMojoServiceIsAvailable(false);

  const auto reply = ExecuteGetAvailableRoutines();
  EXPECT_EQ(reply.routines_size(), 0);
  EXPECT_EQ(reply.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
}

// Test that the routine service handles a RunRoutine request sent before
// wilco_dtc_supportd's mojo service is established.
TEST_F(RoutineServiceTest, RunRoutineNoService) {
  diagnostics_service()->SetMojoServiceIsAvailable(false);

  const auto response = ExecuteRunRoutine(MakeSmartctlCheckRoutineRequest());
  EXPECT_EQ(response.status(), grpc_api::ROUTINE_STATUS_FAILED_TO_START);
  EXPECT_EQ(response.uuid(), 0);
  EXPECT_EQ(response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
}

// Test that the routine service handles a GetRoutineUpdate request sent before
// wilco_dtc_supportd's mojo service is established.
TEST_F(RoutineServiceTest, GetRoutineUpdateNoService) {
  diagnostics_service()->SetMojoServiceIsAvailable(false);

  const auto update_response = ExecuteGetRoutineUpdate(
      0 /* uuid */, grpc_api::GetRoutineUpdateRequest::GET_STATUS,
      false /* include_output */);
  EXPECT_EQ(update_response.status(), grpc_api::ROUTINE_STATUS_ERROR);
  EXPECT_EQ(update_response.progress_percent(), 0);
  EXPECT_EQ(update_response.user_message(),
            grpc_api::ROUTINE_USER_MESSAGE_UNSET);
  EXPECT_EQ(update_response.output(), "");
  EXPECT_EQ(update_response.status_message(), "");
  EXPECT_EQ(update_response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
}

// Test that the routine service can recover from an early gRPC request if
// wilco_dtc_supportd's mojo service is established later.
TEST_F(RoutineServiceTest, RecoverFromNoServiceRequest) {
  // Deal with a request sent before the mojo service is available.
  diagnostics_service()->SetMojoServiceIsAvailable(false);

  const auto unavailable_reply = ExecuteGetAvailableRoutines();
  EXPECT_EQ(unavailable_reply.routines_size(), 0);
  EXPECT_EQ(unavailable_reply.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
  base::RunLoop().RunUntilIdle();

  // Make the mojo service available, and make sure a valid response is
  // received.
  diagnostics_service()->SetMojoServiceIsAvailable(true);
  diagnostics_service()->SetGetAvailableRoutinesResponse(
      {mojo_ipc::DiagnosticRoutineEnum::kBatteryCapacity,
       mojo_ipc::DiagnosticRoutineEnum::kBatteryHealth,
       mojo_ipc::DiagnosticRoutineEnum::kSmartctlCheck,
       mojo_ipc::DiagnosticRoutineEnum::kUrandom,
       mojo_ipc::DiagnosticRoutineEnum::kCpuCache,
       mojo_ipc::DiagnosticRoutineEnum::kCpuStress,
       mojo_ipc::DiagnosticRoutineEnum::kFloatingPointAccuracy,
       mojo_ipc::DiagnosticRoutineEnum::kNvmeWearLevel,
       mojo_ipc::DiagnosticRoutineEnum::kNvmeSelfTest,
       mojo_ipc::DiagnosticRoutineEnum::kDiskRead});

  const auto reply = ExecuteGetAvailableRoutines();
  EXPECT_THAT(reply.routines(),
              ElementsAreArray(
                  {grpc_api::ROUTINE_BATTERY, grpc_api::ROUTINE_BATTERY_SYSFS,
                   grpc_api::ROUTINE_SMARTCTL_CHECK, grpc_api::ROUTINE_URANDOM,
                   grpc_api::ROUTINE_CPU_CACHE, grpc_api::ROUTINE_CPU_STRESS,
                   grpc_api::ROUTINE_FLOATING_POINT_ACCURACY,
                   grpc_api::ROUTINE_NVME_WEAR_LEVEL,
                   grpc_api::ROUTINE_NVME_SHORT_SELF_TEST,
                   grpc_api::ROUTINE_NVME_LONG_SELF_TEST,
                   grpc_api::ROUTINE_DISK_LINEAR_READ,
                   grpc_api::ROUTINE_DISK_RANDOM_READ}));
  EXPECT_EQ(reply.service_status(), grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Test that the routine service handles a GetAvailableRoutines request sent
// when cros_healthd is unresponsive.
TEST_F(RoutineServiceTest, GetAvailableRoutinesUnresponsiveService) {
  diagnostics_service()->SetMojoServiceIsResponsive(false);

  const auto reply = ExecuteGetAvailableRoutines();
  EXPECT_EQ(reply.routines_size(), 0);
  EXPECT_EQ(reply.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
}

// Test that the routine service handles a RunRoutine request sent when
// cros_healthd is unresponsive.
TEST_F(RoutineServiceTest, RunRoutineUnresponsiveService) {
  diagnostics_service()->SetMojoServiceIsResponsive(false);

  const auto response = ExecuteRunRoutine(MakeSmartctlCheckRoutineRequest());
  EXPECT_EQ(response.status(), grpc_api::ROUTINE_STATUS_FAILED_TO_START);
  EXPECT_EQ(response.uuid(), 0);
  EXPECT_EQ(response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
}

// Test that the routine service handles a GetRoutineUpdate request sent when
// cros_healthd is unresponsive.
TEST_F(RoutineServiceTest, GetRoutineUpdateUnresponsiveService) {
  diagnostics_service()->SetMojoServiceIsResponsive(false);

  constexpr int kUuid = 11;
  const auto update_response = ExecuteGetRoutineUpdate(
      kUuid, grpc_api::GetRoutineUpdateRequest::GET_STATUS,
      false /* include_output */);
  EXPECT_EQ(update_response.uuid(), kUuid);
  EXPECT_EQ(update_response.status(), grpc_api::ROUTINE_STATUS_ERROR);
  EXPECT_EQ(update_response.progress_percent(), 0);
  EXPECT_EQ(update_response.user_message(),
            grpc_api::ROUTINE_USER_MESSAGE_UNSET);
  EXPECT_EQ(update_response.output(), "");
  EXPECT_EQ(update_response.status_message(), "");
  EXPECT_EQ(update_response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
}

// Test that the routine service can recover from a dropped connection.
TEST_F(RoutineServiceTest, RecoverFromDroppedConnection) {
  // Establish a valid connection.
  diagnostics_service()->SetGetAvailableRoutinesResponse(
      {mojo_ipc::DiagnosticRoutineEnum::kBatteryCapacity,
       mojo_ipc::DiagnosticRoutineEnum::kBatteryHealth,
       mojo_ipc::DiagnosticRoutineEnum::kSmartctlCheck,
       mojo_ipc::DiagnosticRoutineEnum::kUrandom,
       mojo_ipc::DiagnosticRoutineEnum::kCpuCache,
       mojo_ipc::DiagnosticRoutineEnum::kCpuStress,
       mojo_ipc::DiagnosticRoutineEnum::kFloatingPointAccuracy,
       mojo_ipc::DiagnosticRoutineEnum::kNvmeWearLevel,
       mojo_ipc::DiagnosticRoutineEnum::kNvmeSelfTest,
       mojo_ipc::DiagnosticRoutineEnum::kDiskRead});

  const auto reply = ExecuteGetAvailableRoutines();
  EXPECT_THAT(reply.routines(),
              ElementsAreArray(
                  {grpc_api::ROUTINE_BATTERY, grpc_api::ROUTINE_BATTERY_SYSFS,
                   grpc_api::ROUTINE_SMARTCTL_CHECK, grpc_api::ROUTINE_URANDOM,
                   grpc_api::ROUTINE_CPU_CACHE, grpc_api::ROUTINE_CPU_STRESS,
                   grpc_api::ROUTINE_FLOATING_POINT_ACCURACY,
                   grpc_api::ROUTINE_NVME_WEAR_LEVEL,
                   grpc_api::ROUTINE_NVME_SHORT_SELF_TEST,
                   grpc_api::ROUTINE_NVME_LONG_SELF_TEST,
                   grpc_api::ROUTINE_DISK_LINEAR_READ,
                   grpc_api::ROUTINE_DISK_RANDOM_READ}));
  EXPECT_EQ(reply.service_status(), grpc_api::ROUTINE_SERVICE_STATUS_OK);

  // Reset the connection, make cros_healthd unresponsive, and check to see that
  // the routine service responds appropriately.
  diagnostics_service()->ResetMojoConnection();
  diagnostics_service()->SetMojoServiceIsResponsive(false);

  const auto dropped_reply = ExecuteGetAvailableRoutines();
  EXPECT_EQ(dropped_reply.routines_size(), 0);
  EXPECT_EQ(dropped_reply.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);

  // Set cros_healthd as available again, and make sure the routine service can
  // get valid responses.
  diagnostics_service()->SetMojoServiceIsResponsive(true);
  constexpr uint32_t kExpectedId = 77;
  diagnostics_service()->SetRunSomeRoutineResponse(
      kExpectedId, mojo_ipc::DiagnosticRoutineStatusEnum::kRunning);

  const auto reconnected_reply =
      ExecuteRunRoutine(MakeSmartctlCheckRoutineRequest());
  EXPECT_EQ(reconnected_reply.uuid(), kExpectedId);
  EXPECT_EQ(reconnected_reply.status(), grpc_api::ROUTINE_STATUS_RUNNING);
  EXPECT_EQ(reconnected_reply.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

// Tests for the GetRoutineUpdate() method of RoutineService when an
// interactive update is returned.
//
// This is a parameterized test with the following parameters:
// * |mojo_message| - mojo's DiagnosticRoutineUserMessageEnum returned in the
//                    routine's update.
// * |grpc_message| - gRPC's DiagnosticRoutineUserMessage expected to be
//                    returned by the routine service.
class GetInteractiveUpdateTest
    : public RoutineServiceTest,
      public testing::WithParamInterface<
          std::tuple<mojo_ipc::DiagnosticRoutineUserMessageEnum,
                     grpc_api::DiagnosticRoutineUserMessage>> {
 protected:
  // Accessors to individual test parameters from the test parameter tuple
  // returned by gtest's GetParam():

  mojo_ipc::DiagnosticRoutineUserMessageEnum mojo_message() const {
    return std::get<0>(GetParam());
  }

  grpc_api::DiagnosticRoutineUserMessage grpc_message() const {
    return std::get<1>(GetParam());
  }
};

// Test that after a routine has started, we can access its interactive data.
TEST_P(GetInteractiveUpdateTest, AccessInteractiveRunningRoutine) {
  constexpr uint32_t kExpectedProgressPercent = 17;
  constexpr char kExpectedOutput[] = "Expected output.";
  diagnostics_service()->SetInteractiveUpdate(
      mojo_message(), kExpectedProgressPercent, kExpectedOutput);

  const auto update_response = ExecuteGetRoutineUpdate(
      0 /* uuid */, grpc_api::GetRoutineUpdateRequest::GET_STATUS,
      true /* include_output */);
  EXPECT_EQ(update_response.user_message(), grpc_message());
  EXPECT_EQ(update_response.progress_percent(), kExpectedProgressPercent);
  EXPECT_EQ(update_response.output(), kExpectedOutput);
  EXPECT_EQ(update_response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    GetInteractiveUpdateTest,
    testing::Values(std::make_tuple(
        mojo_ipc::DiagnosticRoutineUserMessageEnum::kUnplugACPower,
        grpc_api::ROUTINE_USER_MESSAGE_UNPLUG_AC_POWER)));

// Tests for the GetRoutineUpdate() method of RoutineService when a
// noninteractive update is returned.
//
// This is a parameterized test with the following parameters:
// * |mojo_status| - mojo's DiagnosticRoutineStatusEnum returned in the
//                   routine's update.
// * |grpc_status| - gRPC's DiagnosticRoutineStatus expected to be
//                   returned by the routine service.
class GetNonInteractiveUpdateTest
    : public RoutineServiceTest,
      public testing::WithParamInterface<
          std::tuple<mojo_ipc::DiagnosticRoutineStatusEnum,
                     grpc_api::DiagnosticRoutineStatus>> {
 protected:
  // Accessors to individual test parameters from the test parameter tuple
  // returned by gtest's GetParam():

  mojo_ipc::DiagnosticRoutineStatusEnum mojo_status() const {
    return std::get<0>(GetParam());
  }

  grpc_api::DiagnosticRoutineStatus grpc_status() const {
    return std::get<1>(GetParam());
  }
};

// Test that after a routine has started, we can access its noninteractive data.
TEST_P(GetNonInteractiveUpdateTest, AccessNonInteractiveRunningRoutine) {
  constexpr char kExpectedStatusMessage[] = "Expected status message.";
  constexpr uint32_t kExpectedProgressPercent = 18;
  constexpr char kExpectedOutput[] = "Expected output.";
  diagnostics_service()->SetNonInteractiveUpdate(
      mojo_status(), kExpectedStatusMessage, kExpectedProgressPercent,
      kExpectedOutput);

  const auto update_response = ExecuteGetRoutineUpdate(
      0 /* uuid */, grpc_api::GetRoutineUpdateRequest::GET_STATUS,
      true /* include_output */);
  EXPECT_EQ(update_response.status(), grpc_status());
  EXPECT_EQ(update_response.status_message(), kExpectedStatusMessage);
  EXPECT_EQ(update_response.progress_percent(), kExpectedProgressPercent);
  EXPECT_EQ(update_response.output(), kExpectedOutput);
  EXPECT_EQ(update_response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    GetNonInteractiveUpdateTest,
    testing::Values(
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kReady,
                        grpc_api::ROUTINE_STATUS_READY),
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kRunning,
                        grpc_api::ROUTINE_STATUS_RUNNING),
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kWaiting,
                        grpc_api::ROUTINE_STATUS_WAITING),
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kPassed,
                        grpc_api::ROUTINE_STATUS_PASSED),
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kFailed,
                        grpc_api::ROUTINE_STATUS_FAILED),
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kError,
                        grpc_api::ROUTINE_STATUS_ERROR),
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kCancelled,
                        grpc_api::ROUTINE_STATUS_CANCELLED),
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kFailedToStart,
                        grpc_api::ROUTINE_STATUS_FAILED_TO_START),
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kRemoved,
                        grpc_api::ROUTINE_STATUS_REMOVED),
        std::make_tuple(mojo_ipc::DiagnosticRoutineStatusEnum::kCancelling,
                        grpc_api::ROUTINE_STATUS_CANCELLING)));

// Tests for the GetRoutineUpdate() method of RoutineService with different
// commands.
//
// This is a parameterized test with the following parameters:
// * |command| - gRPC's GetRoutineUpdateRequest::Command included in the
//               GetRoutineUpdateRequest.
class GetRoutineUpdateCommandTest
    : public RoutineServiceTest,
      public testing::WithParamInterface<
          grpc_api::GetRoutineUpdateRequest::Command> {
 protected:
  // Accessors to the test parameter returned by gtest's GetParam():

  grpc_api::GetRoutineUpdateRequest::Command command() const {
    return GetParam();
  }
};

// Test that we can send the given command.
TEST_P(GetRoutineUpdateCommandTest, SendCommand) {
  constexpr char kExpectedStatusMessage[] = "Expected status message.";
  constexpr uint32_t kExpectedProgressPercent = 19;
  constexpr char kExpectedOutput[] = "Expected output.";
  constexpr mojo_ipc::DiagnosticRoutineStatusEnum kMojoStatus =
      mojo_ipc::DiagnosticRoutineStatusEnum::kRunning;
  constexpr grpc_api::DiagnosticRoutineStatus kExpectedStatus =
      grpc_api::ROUTINE_STATUS_RUNNING;
  diagnostics_service()->SetNonInteractiveUpdate(
      kMojoStatus, kExpectedStatusMessage, kExpectedProgressPercent,
      kExpectedOutput);

  const auto update_response = ExecuteGetRoutineUpdate(
      0 /* uuid */, command(), true /* include_output */);
  EXPECT_EQ(update_response.status(), kExpectedStatus);
  EXPECT_EQ(update_response.status_message(), kExpectedStatusMessage);
  EXPECT_EQ(update_response.progress_percent(), kExpectedProgressPercent);
  EXPECT_EQ(update_response.output(), kExpectedOutput);
  EXPECT_EQ(update_response.service_status(),
            grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    GetRoutineUpdateCommandTest,
    testing::Values(grpc_api::GetRoutineUpdateRequest::RESUME,
                    grpc_api::GetRoutineUpdateRequest::CANCEL,
                    grpc_api::GetRoutineUpdateRequest::REMOVE,
                    grpc_api::GetRoutineUpdateRequest::GET_STATUS));

// Tests for the RunRoutine() method of RoutineService with different requests.
//
// This is a parameterized test with the following parameters:
// * |request| - gRPC's RunRoutineRequest to be requested.
class RunRoutineTest
    : public RoutineServiceTest,
      public testing::WithParamInterface<grpc_api::RunRoutineRequest> {
 public:
  RunRoutineTest() = default;
  RunRoutineTest(const RunRoutineTest&) = delete;
  RunRoutineTest& operator=(const RunRoutineTest&) = delete;

  // Accessors to the test parameter returned by gtest's GetParam():

  grpc_api::RunRoutineRequest request() const { return GetParam(); }
};

// Test that we can request that the given routine is run.
TEST_P(RunRoutineTest, RunRoutine) {
  constexpr uint32_t kExpectedId = 77;
  diagnostics_service()->SetRunSomeRoutineResponse(
      kExpectedId, mojo_ipc::DiagnosticRoutineStatusEnum::kRunning);

  const auto reply = ExecuteRunRoutine(request());
  EXPECT_EQ(reply.uuid(), kExpectedId);
  EXPECT_EQ(reply.status(), grpc_api::ROUTINE_STATUS_RUNNING);
  EXPECT_EQ(reply.service_status(), grpc_api::ROUTINE_SERVICE_STATUS_OK);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    RunRoutineTest,
    testing::Values(MakeBatteryRoutineRequest(),
                    MakeDefaultBatteryRoutineRequest(),
                    MakeBatterySysfsRoutineRequest(),
                    MakeUrandomRoutineRequest(),
                    MakeSmartctlCheckRoutineRequest(),
                    MakeCpuCacheRoutineRequest(),
                    MakeCpuStressRoutineRequest(),
                    MakeFloatingPointAccuracyRoutineRequest(),
                    MakeNvmeWearLevelRoutineRequest(),
                    MakeNvmeSelfTestShortRoutineRequest(),
                    MakeNvmeSelfTestLongRoutineRequest(),
                    MakeDiskLinearReadRoutineRequest(),
                    MakeDiskRandomReadRoutineRequest()));

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
