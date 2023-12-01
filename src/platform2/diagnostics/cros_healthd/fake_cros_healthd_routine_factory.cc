// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fake_cros_healthd_routine_factory.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <gtest/gtest.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/mojom/public/nullable_primitives.mojom.h"

#include <base/check.h>

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// When any of a FakeDiagnosticRoutine's |num_expected_start_calls_|,
// |num_expected_resume_calls_| or |num_expected_cancel_calls_| is this value,
// then calls to the corresponding function will not be tracked.
constexpr int kNumCallsNotTracked = -1;

class FakeDiagnosticRoutine : public DiagnosticRoutine {
 public:
  FakeDiagnosticRoutine(mojom::DiagnosticRoutineStatusEnum status,
                        uint32_t progress_percent,
                        const std::string& output,
                        int num_expected_start_calls,
                        int num_expected_resume_calls,
                        int num_expected_cancel_calls);
  // DiagnosticRoutine overrides:
  ~FakeDiagnosticRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(mojom::RoutineUpdate* response,
                            bool include_output) override;
  mojom::DiagnosticRoutineStatusEnum GetStatus() override;
  void RegisterStatusChangedCallback(StatusChangedCallback callback) override;

 private:
  // Value returned by GetStatus().
  const mojom::DiagnosticRoutineStatusEnum status_;
  // Values used in PopulateStatusUpdate(). Common to both interactive and
  // noninteractive routines.
  const uint32_t progress_percent_;
  const std::string output_;
  // Number of times that Start() is expected to be called throughout the life
  // of this routine.
  const int num_expected_start_calls_;
  // Number of times that Resume() is expected to be called throughout the life
  // of this routine.
  const int num_expected_resume_calls_;
  // Number of times that Cancel() is expected to be called throughout the life
  // of this routine.
  const int num_expected_cancel_calls_;
  // Number of times that Start() was called throughout the life of this
  // routine.
  int num_actual_start_calls_ = 0;
  // Number of times that Resume() was called throughout the life of this
  // routine.
  int num_actual_resume_calls_ = 0;
  // Number of times that Cancel() was called throughout the life of this
  // routine.
  int num_actual_cancel_calls_ = 0;
};

FakeDiagnosticRoutine::FakeDiagnosticRoutine(
    mojom::DiagnosticRoutineStatusEnum status,
    uint32_t progress_percent,
    const std::string& output,
    int num_expected_start_calls,
    int num_expected_resume_calls,
    int num_expected_cancel_calls)
    : status_(status),
      progress_percent_(progress_percent),
      output_(output),
      num_expected_start_calls_(num_expected_start_calls),
      num_expected_resume_calls_(num_expected_resume_calls),
      num_expected_cancel_calls_(num_expected_cancel_calls) {}

FakeDiagnosticRoutine::~FakeDiagnosticRoutine() {
  if (num_expected_start_calls_ != kNumCallsNotTracked)
    EXPECT_EQ(num_expected_start_calls_, num_actual_start_calls_);
  if (num_expected_resume_calls_ != kNumCallsNotTracked)
    EXPECT_EQ(num_expected_resume_calls_, num_actual_resume_calls_);
  if (num_expected_cancel_calls_ != kNumCallsNotTracked)
    EXPECT_EQ(num_expected_cancel_calls_, num_actual_cancel_calls_);
}

void FakeDiagnosticRoutine::Start() {
  num_actual_start_calls_++;
}

void FakeDiagnosticRoutine::Resume() {
  num_actual_resume_calls_++;
}

void FakeDiagnosticRoutine::Cancel() {
  num_actual_cancel_calls_++;
}

void FakeDiagnosticRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                                 bool include_output) {
  DCHECK(response);

  response->progress_percent = progress_percent_;
  response->output = CreateReadOnlySharedMemoryRegionMojoHandle(output_);
}

mojom::DiagnosticRoutineStatusEnum FakeDiagnosticRoutine::GetStatus() {
  return status_;
}

void FakeDiagnosticRoutine::RegisterStatusChangedCallback(
    StatusChangedCallback callback) {
  // Not implemented since the status of this fake object never changes.
}

class FakeNonInteractiveDiagnosticRoutine final : public FakeDiagnosticRoutine {
 public:
  FakeNonInteractiveDiagnosticRoutine(mojom::DiagnosticRoutineStatusEnum status,
                                      const std::string& status_message,
                                      uint32_t progress_percent,
                                      const std::string& output,
                                      int num_expected_start_calls,
                                      int num_expected_resume_calls,
                                      int num_expected_cancel_calls);
  FakeNonInteractiveDiagnosticRoutine(
      const FakeNonInteractiveDiagnosticRoutine&) = delete;
  FakeNonInteractiveDiagnosticRoutine& operator=(
      const FakeNonInteractiveDiagnosticRoutine&) = delete;
  ~FakeNonInteractiveDiagnosticRoutine() override;

  // FakeDiagnosticRoutine overrides:
  void PopulateStatusUpdate(mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  // Used to populate the noninteractive_routine_update for calls to
  // PopulateStatusUpdate.
  const std::string status_message_;
};

FakeNonInteractiveDiagnosticRoutine::FakeNonInteractiveDiagnosticRoutine(
    mojom::DiagnosticRoutineStatusEnum status,
    const std::string& status_message,
    uint32_t progress_percent,
    const std::string& output,
    int num_expected_start_calls,
    int num_expected_resume_calls,
    int num_expected_cancel_calls)
    : FakeDiagnosticRoutine(status,
                            progress_percent,
                            output,
                            num_expected_start_calls,
                            num_expected_resume_calls,
                            num_expected_cancel_calls),
      status_message_(status_message) {}

FakeNonInteractiveDiagnosticRoutine::~FakeNonInteractiveDiagnosticRoutine() =
    default;

void FakeNonInteractiveDiagnosticRoutine::PopulateStatusUpdate(
    mojom::RoutineUpdate* response, bool include_output) {
  FakeDiagnosticRoutine::PopulateStatusUpdate(response, include_output);
  auto update = mojom::NonInteractiveRoutineUpdate::New();
  update->status = GetStatus();
  update->status_message = status_message_;
  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(std::move(update));
}

}  // namespace

FakeCrosHealthdRoutineFactory::FakeCrosHealthdRoutineFactory()
    : num_expected_start_calls_(kNumCallsNotTracked),
      num_expected_resume_calls_(kNumCallsNotTracked),
      num_expected_cancel_calls_(kNumCallsNotTracked) {}
FakeCrosHealthdRoutineFactory::~FakeCrosHealthdRoutineFactory() = default;

void FakeCrosHealthdRoutineFactory::SetRoutineExpectations(
    int num_expected_start_calls,
    int num_expected_resume_calls,
    int num_expected_cancel_calls) {
  num_expected_start_calls_ = num_expected_start_calls;
  num_expected_resume_calls_ = num_expected_resume_calls;
  num_expected_cancel_calls_ = num_expected_cancel_calls;
}

void FakeCrosHealthdRoutineFactory::SetNonInteractiveStatus(
    mojom::DiagnosticRoutineStatusEnum status,
    const std::string& status_message,
    uint32_t progress_percent,
    const std::string& output) {
  next_routine_ = std::make_unique<FakeNonInteractiveDiagnosticRoutine>(
      status, status_message, progress_percent, output,
      num_expected_start_calls_, num_expected_resume_calls_,
      num_expected_cancel_calls_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeUrandomRoutine(
    mojom::NullableUint32Ptr length_seconds) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeBatteryCapacityRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeBatteryHealthRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeSmartctlCheckRoutine(
    org::chromium::debugdProxyInterface* debugd_proxy,
    mojom::NullableUint32Ptr percentage_used_threshold) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeAcPowerRoutine(
    mojom::AcPowerStatusEnum expected_status,
    const std::optional<std::string>& expected_power_type) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeCpuCacheRoutine(
    const std::optional<base::TimeDelta>& exec_duration) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeCpuStressRoutine(
    const std::optional<base::TimeDelta>& exec_duration) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeFloatingPointAccuracyRoutine(
    const std::optional<base::TimeDelta>& exec_duration) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeNvmeWearLevelRoutine(
    org::chromium::debugdProxyInterface* debugd_proxy,
    ash::cros_healthd::mojom::NullableUint32Ptr wear_level_threshold) {
  DCHECK(debugd_proxy);
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeNvmeSelfTestRoutine(
    org::chromium::debugdProxyInterface* debugd_proxy,
    mojom::NvmeSelfTestTypeEnum nvme_self_test_type) {
  DCHECK(debugd_proxy);
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakePrimeSearchRoutine(
    const std::optional<base::TimeDelta>& exec_duration) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeBatteryDischargeRoutine(
    base::TimeDelta exec_duration, uint32_t maximum_discharge_percent_allowed) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeBatteryChargeRoutine(
    base::TimeDelta exec_duration, uint32_t minimum_charge_percent_required) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeMemoryRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeLanConnectivityRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeSignalStrengthRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeGatewayCanBePingedRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeHasSecureWiFiConnectionRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeDnsResolverPresentRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeDnsLatencyRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeDnsResolutionRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeCaptivePortalRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeHttpFirewallRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeHttpsFirewallRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeHttpsLatencyRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeVideoConferencingRoutine(
    const std::optional<std::string>& stun_server_hostname) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeArcHttpRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeArcPingRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeArcDnsResolutionRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeSensitiveSensorRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeFingerprintRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeFingerprintAliveRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakePrivacyScreenRoutine(bool target_state) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeEmmcLifetimeRoutine(
    org::chromium::debugdProxyInterface* debugd_proxy) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeLedLitUpRoutine(
    ash::cros_healthd::mojom::LedName name,
    ash::cros_healthd::mojom::LedColor color,
    mojo::PendingRemote<ash::cros_healthd::mojom::LedLitUpRoutineReplier>
        replier) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeAudioSetVolumeRoutine(uint64_t node_id,
                                                         uint8_t volume,
                                                         bool mute_on) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeAudioSetGainRoutine(uint64_t node_id,
                                                       uint8_t gain) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeBluetoothPowerRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeBluetoothDiscoveryRoutine() {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeBluetoothScanningRoutine(
    const std::optional<base::TimeDelta>& exec_duration) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakeBluetoothPairingRoutine(
    const std::string& peripheral_id) {
  return std::move(next_routine_);
}

std::unique_ptr<DiagnosticRoutine>
FakeCrosHealthdRoutineFactory::MakePowerButtonRoutine(
    uint32_t timeout_seconds) {
  return std::move(next_routine_);
}

}  // namespace diagnostics
