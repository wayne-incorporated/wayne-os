// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_health_tool/diag/diag.h"

#include <stdlib.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <utility>

#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <brillo/flag_helper.h>
#include <mojo/service_constants.h>

#include "diagnostics/cros_health_tool/diag/diag_actions.h"
#include "diagnostics/cros_health_tool/diag/observers/routine_observer.h"
#include "diagnostics/cros_health_tool/mojo_util.h"
#include "diagnostics/cros_health_tool/output_util.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_exception.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

const struct {
  const char* readable_name;
  mojom::LedName name;
} kLedNameSwitches[] = {{"battery", mojom::LedName::kBattery},
                        {"power", mojom::LedName::kPower},
                        {"adapter", mojom::LedName::kAdapter},
                        {"left", mojom::LedName::kLeft},
                        {"right", mojom::LedName::kRight}};

const struct {
  const char* readable_color;
  mojom::LedColor color;
} kLedColorSwitches[] = {
    {"red", mojom::LedColor::kRed},     {"green", mojom::LedColor::kGreen},
    {"blue", mojom::LedColor::kBlue},   {"yellow", mojom::LedColor::kYellow},
    {"white", mojom::LedColor::kWhite}, {"amber", mojom::LedColor::kAmber}};

mojom::LedName LedNameFromString(const std::string& str) {
  for (const auto& item : kLedNameSwitches) {
    if (str == item.readable_name) {
      return item.name;
    }
  }
  return mojom::LedName::kUnmappedEnumField;
}

mojom::LedColor LedColorFromString(const std::string& str) {
  for (const auto& item : kLedColorSwitches) {
    if (str == item.readable_color) {
      return item.color;
    }
  }
  return mojom::LedColor::kUnmappedEnumField;
}

void FormatJsonOutput(bool single_line_json, const base::Value::Dict& output) {
  if (single_line_json) {
    std::cout << "Output: ";
    OutputSingleLineJson(output);
    return;
  }
  std::cout << "Output: " << std::endl;
  OutputJson(output);
}

int RunV2Routine(mojom::RoutineArgumentPtr argument, bool single_line_json) {
  mojo::Remote<ash::cros_healthd::mojom::CrosHealthdRoutinesService>
      cros_healthd_routines_service_;
  RequestMojoServiceWithDisconnectHandler(
      chromeos::mojo_services::kCrosHealthdRoutines,
      cros_healthd_routines_service_);

  base::RunLoop run_loop;
  mojo::Remote<mojom::RoutineControl> routine_control;
  mojo::PendingReceiver<mojom::RoutineControl> pending_receiver =
      routine_control.BindNewPipeAndPassReceiver();
  routine_control.set_disconnect_with_reason_handler(
      base::BindOnce(
          [](base::OnceCallback<void(const base::Value::Dict&)>
                 format_output_callback,
             uint32_t error, const std::string& message) {
            base::Value::Dict output;
            SetJsonDictValue("error", error, &output);
            SetJsonDictValue("message", message, &output);
            std::cout << "Status: Error" << std::endl;
            std::move(format_output_callback).Run(output);
          },
          base::BindOnce(&FormatJsonOutput, single_line_json))
          .Then(run_loop.QuitClosure()));
  cros_healthd_routines_service_->CreateRoutine(std::move(argument),
                                                std::move(pending_receiver));
  RoutineObserver observer = RoutineObserver(run_loop.QuitClosure());
  observer.SetFormatOutputCallback(
      base::BindOnce(&FormatJsonOutput, single_line_json));
  routine_control->AddObserver(observer.BindNewPipdAndPassRemote());
  routine_control->Start();
  run_loop.Run();
  return EXIT_SUCCESS;
}

int CheckV2RoutineSupportStatus(mojom::RoutineArgumentPtr argument) {
  mojo::Remote<ash::cros_healthd::mojom::CrosHealthdRoutinesService>
      cros_healthd_routines_service_;
  RequestMojoServiceWithDisconnectHandler(
      chromeos::mojo_services::kCrosHealthdRoutines,
      cros_healthd_routines_service_);

  base::RunLoop run_loop;
  cros_healthd_routines_service_->IsRoutineSupported(
      std::move(argument),
      base::BindOnce(&OutputSupportStatus).Then(run_loop.QuitClosure()));
  run_loop.Run();

  return EXIT_SUCCESS;
}

#define COMMON_V2_ROUTINE_FLAGS(description)                              \
  DEFINE_bool(single_line_json, false,                                    \
              "Whether to print JSON objects in a single line.");         \
  DEFINE_bool(check_supported, false,                                     \
              "Check the support status of the routine. It won't run the" \
              " routine.");                                               \
  brillo::FlagHelper::Init(argc, argv, description);

#define COMMON_V2_ROUTINE_MAIN(routine)                             \
  if (FLAGS_check_supported) {                                      \
    return CheckV2RoutineSupportStatus(                             \
        mojom::RoutineArgument::New##routine(std::move(argument))); \
  }                                                                 \
  return RunV2Routine(                                              \
      mojom::RoutineArgument::New##routine(std::move(argument)),    \
      FLAGS_single_line_json);

// Template of RoutineMain.
//
// int RoutineMain(int argc, char** argv) {
//   // Step1: Define the exclusive flags.
//   DEFINE_xxx(...);
//
//   // Step2: Define the common flags and the routine description.
//   COMMON_V2_ROUTINE_FLAGS("...");
//
//   // Step3: Create the routine argument and configure it.
//   auto argument = mojom::${routine}RoutineArgument::New();
//   ...
//
//   // Step4: Put the common part at the end.
//   COMMON_V2_ROUTINE_MAIN(${routine});
// }

int AudioDriverMain(int argc, char** argv) {
  COMMON_V2_ROUTINE_FLAGS("Audio driver routine");

  auto argument = mojom::AudioDriverRoutineArgument::New();

  COMMON_V2_ROUTINE_MAIN(AudioDriver);
}

int MemoryV2Main(int argc, char** argv) {
  DEFINE_uint32(max_testing_mem_kib, std::numeric_limits<uint32_t>::max(),
                "Number of kib to run the memory test for.");
  COMMON_V2_ROUTINE_FLAGS("Memory v2 routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  auto argument = mojom::MemoryRoutineArgument::New();
  if (command_line->HasSwitch("max_testing_mem_kib")) {
    argument->max_testing_mem_kib = FLAGS_max_testing_mem_kib;
  }

  COMMON_V2_ROUTINE_MAIN(Memory);
}

int CpuStressV2Main(int argc, char** argv) {
  DEFINE_uint32(length_seconds, 10, "Number of seconds to run.");
  COMMON_V2_ROUTINE_FLAGS("Cpu stress v2 routine")

  auto argument = mojom::CpuStressRoutineArgument::New();
  argument->exec_duration = base::Seconds(FLAGS_length_seconds);

  COMMON_V2_ROUTINE_MAIN(CpuStress);
}

int UfsLifetimeMain(int argc, char** argv) {
  COMMON_V2_ROUTINE_FLAGS("Ufs lifetime routine");

  auto argument = mojom::UfsLifetimeRoutineArgument::New();

  COMMON_V2_ROUTINE_MAIN(UfsLifetime);
}

int CpuCacheV2Main(int argc, char** argv) {
  DEFINE_uint32(length_seconds, 10,
                "Number of seconds to run the routine for.");
  COMMON_V2_ROUTINE_FLAGS("Cpu cache V2 routine");

  auto argument = mojom::CpuCacheRoutineArgument::New();
  argument->exec_duration = base::Seconds(FLAGS_length_seconds);

  COMMON_V2_ROUTINE_MAIN(CpuCache);
}

int DiskReadV2Main(int argc, char** argv) {
  DEFINE_string(type, "linear",
                "Type of how disk reading is performed: [linear, random].");
  DEFINE_uint32(length_seconds, 10,
                "Number of seconds to run the routine for.");
  DEFINE_uint32(file_size_mib, 1, "Test file size in megabytes (MiB).");
  COMMON_V2_ROUTINE_FLAGS("Disk read V2 routine");

  auto argument = mojom::DiskReadRoutineArgument::New();
  if (FLAGS_type == "linear") {
    argument->type = mojom::DiskReadTypeEnum::kLinearRead;
  } else if (FLAGS_type == "random") {
    argument->type = mojom::DiskReadTypeEnum::kRandomRead;
  }
  argument->disk_read_duration = base::Seconds(FLAGS_length_seconds);
  argument->file_size_mib = FLAGS_file_size_mib;

  COMMON_V2_ROUTINE_MAIN(DiskRead);
}

int PrimeSearchV2Main(int argc, char** argv) {
  DEFINE_uint32(length_seconds, 60,
                "Number of seconds to run the routine for.");
  COMMON_V2_ROUTINE_FLAGS("Prime search V2 routine")
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  auto argument = mojom::PrimeSearchRoutineArgument::New();
  if (command_line->HasSwitch("length_seconds")) {
    argument->exec_duration = base::Seconds(FLAGS_length_seconds);
  }

  COMMON_V2_ROUTINE_MAIN(PrimeSearch);
}

int VolumeButtonMain(int argc, char** argv) {
  DEFINE_string(button_type, "", "The volume button to test: [up, down].");
  DEFINE_uint32(length_seconds, 10,
                "Number of seconds to listen for the power button events. "
                "Range: [1, 600].");
  COMMON_V2_ROUTINE_FLAGS("Volume button routine");

  auto argument = mojom::VolumeButtonRoutineArgument::New();

  if (FLAGS_button_type == "up") {
    argument->type = mojom::VolumeButtonRoutineArgument::ButtonType::kVolumeUp;
  } else if (FLAGS_button_type == "down") {
    argument->type =
        mojom::VolumeButtonRoutineArgument::ButtonType::kVolumeDown;
  } else {
    std::cout << "Unknown volume button type: " << FLAGS_button_type
              << std::endl;
    return EXIT_FAILURE;
  }

  argument->timeout = base::Seconds(FLAGS_length_seconds);

  COMMON_V2_ROUTINE_MAIN(VolumeButton);
}

#define COMMON_LEGACY_ROUTINE_FLAGS                                            \
  DEFINE_uint32(force_cancel_at_percent, std::numeric_limits<uint32_t>::max(), \
                "If specified, will attempt to cancel the routine when its "   \
                "progress exceeds the flag's value.\nValid range: [0, 100]");

#define COMMON_LEGACY_ROUTINE(routine)                                      \
  COMMON_LEGACY_ROUTINE_FLAGS                                               \
  brillo::FlagHelper::Init(argc, argv, #routine);                           \
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess(); \
  DiagActions actions;                                                      \
  if (command_line->HasSwitch("force_cancel_at_percent"))                   \
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);            \
  auto result = actions.ActionRun##routine();                               \
  return result ? EXIT_SUCCESS : EXIT_FAILURE;

int BatteryCapacityMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(BatteryCapacityRoutine)
}

int BatteryHealthMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(BatteryHealthRoutine)
}

int UrandomMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(length_seconds, 0, "Number of seconds to run.");
  brillo::FlagHelper::Init(argc, argv, "Urandom routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunUrandomRoutine(
      command_line->HasSwitch("length_seconds")
          ? std::optional<uint32_t>(FLAGS_length_seconds)
          : std::nullopt);
  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int SmartctlCheckMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(percentage_used_threshold, 255,
                "Threshold number in percentage which routine examines "
                "percentage used against.");
  brillo::FlagHelper::Init(argc, argv, "Smartctl check routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunSmartctlCheckRoutine(
      command_line->HasSwitch("percentage_used_threshold")
          ? std::optional<uint32_t>(FLAGS_percentage_used_threshold)
          : std::nullopt);
  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int AcPowerMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_bool(ac_power_is_connected, true,
              "Whether or not the routine expects the power supply to be"
              "connected.");
  DEFINE_string(expected_power_type, "",
                "Optional type of power supply expected for the routine.");
  brillo::FlagHelper::Init(argc, argv, "Ac power routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunAcPowerRoutine(
      FLAGS_ac_power_is_connected ? mojom::AcPowerStatusEnum::kConnected
                                  : mojom::AcPowerStatusEnum::kDisconnected,
      (command_line->HasSwitch("expected_power_type"))
          ? std::optional<std::string>{FLAGS_expected_power_type}
          : std::nullopt);
  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int CpuCacheMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(length_seconds, 0, "Number of seconds to run.");
  brillo::FlagHelper::Init(argc, argv, "Cpu cache routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunCpuCacheRoutine(
      command_line->HasSwitch("length_seconds")
          ? std::optional<uint32_t>(FLAGS_length_seconds)
          : std::nullopt);
  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int CpuStressMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(length_seconds, 0, "Number of seconds to run.");
  brillo::FlagHelper::Init(argc, argv, "Cpu stress routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunCpuStressRoutine(
      command_line->HasSwitch("length_seconds")
          ? std::optional<uint32_t>(FLAGS_length_seconds)
          : std::nullopt);
  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int FloatingPointAccuracyMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(length_seconds, 0, "Number of seconds to run.");
  brillo::FlagHelper::Init(argc, argv, "Floating point accuracy routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunFloatingPointAccuracyRoutine(
      command_line->HasSwitch("length_seconds")
          ? std::optional<uint32_t>(FLAGS_length_seconds)
          : std::nullopt);
  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int NvmeWearLevelMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(wear_level_threshold, 0,
                "Threshold number in percentage which routine examines "
                "wear level of NVMe against. If not specified, device "
                "threshold set in cros-config will be used instead.");
  brillo::FlagHelper::Init(argc, argv, "Nvme wear level routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunNvmeWearLevelRoutine(
      command_line->HasSwitch("wear_level_threshold")
          ? std::optional<std::uint32_t>{FLAGS_wear_level_threshold}
          : std::nullopt);
  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int NvmeSelfTestMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_bool(nvme_self_test_long, false,
              "Long-time period self-test of NVMe would be performed with "
              "this flag being set.");
  brillo::FlagHelper::Init(argc, argv, "Nvme self test routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunNvmeSelfTestRoutine(
      FLAGS_nvme_self_test_long ? mojom::NvmeSelfTestTypeEnum::kLongSelfTest
                                : mojom::NvmeSelfTestTypeEnum::kShortSelfTest);
  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int DiskReadMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(length_seconds, 10,
                "Number of seconds to run the routine for.");
  DEFINE_int32(file_size_mb, 1024,
               "Size (MB) of the test file for disk_read routine to pass.");
  DEFINE_string(disk_read_routine_type, "linear",
                "Disk read routine type for the disk_read routine. Options are:"
                "\n\tlinear - linear read.\n\trandom - random read.");
  brillo::FlagHelper::Init(argc, argv, "Disk read routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  mojom::DiskReadRoutineTypeEnum type;
  if (FLAGS_disk_read_routine_type == "linear") {
    type = mojom::DiskReadRoutineTypeEnum::kLinearRead;
  } else if (FLAGS_disk_read_routine_type == "random") {
    type = mojom::DiskReadRoutineTypeEnum::kRandomRead;
  } else {
    std::cout << "Unknown disk_read_routine_type: "
              << FLAGS_disk_read_routine_type << std::endl;
    return EXIT_FAILURE;
  }

  auto result = actions.ActionRunDiskReadRoutine(type, FLAGS_length_seconds,
                                                 FLAGS_file_size_mb);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int PrimeSearchMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(length_seconds, 0, "Number of seconds to run.");
  brillo::FlagHelper::Init(argc, argv, "Prime search routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunPrimeSearchRoutine(
      command_line->HasSwitch("length_seconds")
          ? std::optional<uint32_t>(FLAGS_length_seconds)
          : std::nullopt);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int BatteryDischargeMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(length_seconds, 10,
                "Number of seconds to run the routine for.");
  DEFINE_uint32(maximum_discharge_percent_allowed, 100,
                "Upper bound for the battery discharge routine.");
  brillo::FlagHelper::Init(argc, argv, "Battery discharge routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunBatteryDischargeRoutine(
      FLAGS_length_seconds, FLAGS_maximum_discharge_percent_allowed);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int BatteryChargeMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(length_seconds, 10,
                "Number of seconds to run the routine for.");
  DEFINE_uint32(minimum_charge_percent_required, 0,
                "Lower bound for the battery charge routine.");
  brillo::FlagHelper::Init(argc, argv, "Battery charge routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunBatteryChargeRoutine(
      FLAGS_length_seconds, FLAGS_minimum_charge_percent_required);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int LanConnectivityMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(LanConnectivityRoutine)
}

int SignalStrengthMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(SignalStrengthRoutine)
}

int MemoryMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(max_testing_mem_kib, std::numeric_limits<uint32_t>::max(),
                "Number of kib to run the memory test for.");
  brillo::FlagHelper::Init(argc, argv, "Memory routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunMemoryRoutine(
      command_line->HasSwitch("max_testing_mem_kib")
          ? std::optional<uint32_t>(FLAGS_max_testing_mem_kib)
          : std::nullopt);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int GatewayCanBePingedMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(GatewayCanBePingedRoutine)
}

int HasSecureWiFiConnectionMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(HasSecureWiFiConnectionRoutine)
}

int DnsResolverPresentMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(DnsResolverPresentRoutine)
}

int DnsLatencyMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(DnsLatencyRoutine)
}

int DnsResolutionMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(DnsResolutionRoutine)
}

int CaptivePortalMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(CaptivePortalRoutine)
}

int HttpFirewallMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(HttpFirewallRoutine)
}

int HttpsFirewallMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(HttpsFirewallRoutine)
}

int HttpsLatencyMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(HttpsLatencyRoutine)
}

int VideoConferencingMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_string(stun_server_hostname, "",
                "Optional custom STUN server hostname.");
  brillo::FlagHelper::Init(argc, argv, "Video conferencing routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunVideoConferencingRoutine(
      (FLAGS_stun_server_hostname == "")
          ? std::nullopt
          : std::optional<std::string>{FLAGS_stun_server_hostname});

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int ArcHttpMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(ArcHttpRoutine)
}

int ArcPingMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(ArcPingRoutine)
}

int ArcDnsResolutionMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(ArcDnsResolutionRoutine)
}

int SensitiveSensorMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(SensitiveSensorRoutine)
}

int FingerprintMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(FingerprintRoutine)
}

int FingerprintAliveMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(FingerprintAliveRoutine)
}

int PrivacyScreenMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_string(set_privacy_screen, "on", "Privacy screen target state.");
  brillo::FlagHelper::Init(argc, argv, "Privacy screen routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  bool target_state;
  if (FLAGS_set_privacy_screen == "on") {
    target_state = true;
  } else if (FLAGS_set_privacy_screen == "off") {
    target_state = false;
  } else {
    std::cout << "Invalid privacy screen target state: "
              << FLAGS_set_privacy_screen << ". Should be on/off." << std::endl;
    return EXIT_FAILURE;
  }

  auto result = actions.ActionRunPrivacyScreenRoutine(target_state);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int LedLitUpMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_string(led_name, "",
                "The target LED name. Options are:"
                "\n\tbattery, power, adapter, left, right.");
  DEFINE_string(led_color, "",
                "The target color. Options are:"
                "\n\tred, green, blue, yellow, white, amber.");
  brillo::FlagHelper::Init(argc, argv, "Led lit up routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  mojom::LedName name = LedNameFromString(FLAGS_led_name);
  if (name == mojom::LedName::kUnmappedEnumField) {
    std::cout << "Unknown led_name: " << FLAGS_led_name << std::endl;
    return EXIT_FAILURE;
  }
  mojom::LedColor color = LedColorFromString(FLAGS_led_color);
  if (color == mojom::LedColor::kUnmappedEnumField) {
    std::cout << "Unknown led_color: " << FLAGS_led_color << std::endl;
    return EXIT_FAILURE;
  }

  auto result = actions.ActionRunLedRoutine(name, color);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int EmmcLifetimeMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(EmmcLifetimeRoutine)
}

int AudioSetVolumeMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint64(node_id, 0, "Target node id.");
  DEFINE_uint32(volume, 100, "Target volume. [0-100]");
  DEFINE_bool(mute_on, true, "Mute audio output device or not.");
  brillo::FlagHelper::Init(argc, argv, "Audio set volume routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunAudioSetVolumeRoutine(
      FLAGS_node_id, FLAGS_volume, FLAGS_mute_on);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int AudioSetGainMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint64(node_id, 0, "Target node id.");
  DEFINE_uint32(gain, 100, "Target gain. [0-100]");
  brillo::FlagHelper::Init(argc, argv, "Audio set gain routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunAudioSetGainRoutine(FLAGS_node_id, FLAGS_gain);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int BluetoothPowerMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(BluetoothPowerRoutine)
}

int BluetoothDiscoveryMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(BluetoothDiscoveryRoutine)
}

int BluetoothScanningMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_uint32(length_seconds, 10,
                "Number of seconds to run the routine for.");
  brillo::FlagHelper::Init(argc, argv, "Bluetooth scanning routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  auto result = actions.ActionRunBluetoothScanningRoutine(
      command_line->HasSwitch("length_seconds")
          ? std::optional<uint32_t>(FLAGS_length_seconds)
          : std::nullopt);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int BluetoothPairingMain(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE_FLAGS
  DEFINE_string(peripheral_id, "", "ID of Bluetooth peripheral device.");

  brillo::FlagHelper::Init(argc, argv, "Bluetooth pairing routine");
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();

  DiagActions actions;
  if (command_line->HasSwitch("force_cancel_at_percent"))
    actions.ForceCancelAtPercent(FLAGS_force_cancel_at_percent);

  if (FLAGS_peripheral_id.empty()) {
    std::cout << "Invalid empty peripheral_id" << std::endl;
    return EXIT_FAILURE;
  }

  auto result = actions.ActionRunBluetoothPairingRoutine(FLAGS_peripheral_id);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int PowerButtonMain(int argc, char** argv) {
  DEFINE_uint32(length_seconds, 0,
                "Number of seconds to listen for the power button events. "
                "Range: [1, 600].");

  brillo::FlagHelper::Init(argc, argv, "Power button routine");

  DiagActions actions;

  auto result = actions.ActionRunPowerButtonRoutine(FLAGS_length_seconds);

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

int AudioDriverV1Main(int argc, char** argv) {
  COMMON_LEGACY_ROUTINE(AudioDriverRoutine)
}

const std::map<std::string, int (*)(int, char**)> routine_to_fp_mapping{
    // V2 routines.
    {"audio_driver", AudioDriverMain},
    {"memory_v2", MemoryV2Main},
    {"cpu_stress_v2", CpuStressV2Main},
    {"ufs_lifetime", UfsLifetimeMain},
    {"cpu_cache_v2", CpuCacheV2Main},
    {"disk_read_v2", DiskReadV2Main},
    {"prime_search_v2", PrimeSearchV2Main},
    {"volume_button", VolumeButtonMain},
    // V1 routines.
    {"battery_capacity", BatteryCapacityMain},
    {"battery_health", BatteryHealthMain},
    {"urandom", UrandomMain},
    {"smartctl_check", SmartctlCheckMain},
    {"smartctl_check_with_percentage_used", SmartctlCheckMain},
    {"ac_power", AcPowerMain},
    {"cpu_cache", CpuCacheMain},
    {"cpu_stress", CpuStressMain},
    {"floating_point_accuracy", FloatingPointAccuracyMain},
    {"nvme_wear_level", NvmeWearLevelMain},
    {"nvme_self_test", NvmeSelfTestMain},
    {"disk_read", DiskReadMain},
    {"prime_search", PrimeSearchMain},
    {"battery_discharge", BatteryDischargeMain},
    {"battery_charge", BatteryChargeMain},
    {"lan_connectivity", LanConnectivityMain},
    {"signal_strength", SignalStrengthMain},
    {"memory", MemoryMain},
    {"gateway_can_be_pinged", GatewayCanBePingedMain},
    {"has_secure_wifi_connection", HasSecureWiFiConnectionMain},
    {"dns_resolver_present", DnsResolverPresentMain},
    {"dns_latency", DnsLatencyMain},
    {"dns_resolution", DnsResolutionMain},
    {"captive_portal", CaptivePortalMain},
    {"http_firewall", HttpFirewallMain},
    {"https_firewall", HttpsFirewallMain},
    {"https_latency", HttpsLatencyMain},
    {"video_conferencing", VideoConferencingMain},
    {"arc_http", ArcHttpMain},
    {"arc_ping", ArcPingMain},
    {"arc_dns_resolution", ArcDnsResolutionMain},
    {"sensitive_sensor", SensitiveSensorMain},
    {"fingerprint", FingerprintMain},
    {"fingerprint_alive", FingerprintAliveMain},
    {"privacy_screen", PrivacyScreenMain},
    {"led_lit_up", LedLitUpMain},
    {"emmc_lifetime", EmmcLifetimeMain},
    {"audio_set_volume", AudioSetVolumeMain},
    {"audio_set_gain", AudioSetGainMain},
    {"bluetooth_power", BluetoothPowerMain},
    {"bluetooth_discovery", BluetoothDiscoveryMain},
    {"bluetooth_scanning", BluetoothScanningMain},
    {"bluetooth_pairing", BluetoothPairingMain},
    {"power_button", PowerButtonMain},
    {"audio_driver_v1", AudioDriverV1Main},
};

void PrintHelp() {
  std::stringstream ss;
  ss << "[";
  const char* sep = "";
  for (const auto& [routine, unused_tmp] : routine_to_fp_mapping) {
    ss << sep << routine;
    sep = ", ";
  }
  ss << "]";

  std::cout << "cros-health-tool diag" << std::endl;
  std::cout << "    subtools: $routine, get_routines" << std::endl;
  std::cout << "    Usage: cros-health-tool diag $routine" << std::endl;
  std::cout << "    Usage: cros-health-tool diag $routine --help" << std::endl;
  std::cout << "    Usage: cros-health-tool diag get_routines" << std::endl;
  std::cout << "$routine: " << ss.str() << std::endl;
}

}  // namespace

int diag_main(int argc, char** argv) {
  if (argc < 2) {
    PrintHelp();
    return EXIT_SUCCESS;
  }

  std::string subtool = argv[1];
  if (subtool == "help" || subtool == "--help" || subtool == "-h") {
    PrintHelp();
    return EXIT_SUCCESS;
  } else if (subtool == "--crosh_help") {
    std::cout << "Usage: [list|routine]" << std::endl;
    return EXIT_SUCCESS;
  }

  // We should deprecate this.
  if (subtool == "get_routines") {
    DiagActions actions;
    return actions.ActionGetRoutines() ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  std::string routine = argv[1];
  auto it = routine_to_fp_mapping.find(routine);
  if (it != routine_to_fp_mapping.end()) {
    return it->second(argc, argv);
  }

  std::cout << "Unknown routine: " << routine << std::endl;
  return EXIT_FAILURE;
}

}  // namespace diagnostics
