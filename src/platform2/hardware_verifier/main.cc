/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <sysexits.h>

#include <cstdlib>
#include <iostream>
#include <memory>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "hardware_verifier/cli.h"
#include "hardware_verifier/daemon.h"
#include "hardware_verifier/observer.h"

namespace {

enum ExitStatus {
  kSuccess = EXIT_SUCCESS,  // 0

  // The verification report shows the device is not complicant.
  kVerifiedFail = 1,

  // The verification process is skipped.
  kSkippedVerification = 2,

  kUnknownError = 10,

  // Some of the argument is invalid.
  kInvalidArgument = 11,

  // EX__BASE (64) to EX__MAX (78) defined in sysexits.h are reserved.
};

// Translate the error code from |hardware_verifier::CLI::Run()| to
// the corresponding return code.
ExitStatus ConvertCLIVerificationResultToExitStatus(
    const hardware_verifier::CLIVerificationResult& verification_result) {
  using hardware_verifier::CLIVerificationResult;
  switch (verification_result) {
    case CLIVerificationResult::kPass:
      return ExitStatus::kSuccess;
    case CLIVerificationResult::kFail:
      return ExitStatus::kVerifiedFail;
    case CLIVerificationResult::kSkippedVerification:
      return ExitStatus::kSkippedVerification;
    case CLIVerificationResult::kInvalidHwVerificationSpecFile:
    case CLIVerificationResult::kInvalidProbeResultFile:
      return ExitStatus::kInvalidArgument;
    default:
      return ExitStatus::kUnknownError;
  }
}

int SafeConvertVerbosityFlagToLogLevel(int verbosity_flag) {
  if (verbosity_flag < 0 || 5 < verbosity_flag) {
    LOG(ERROR) << "The verbosity value (" << verbosity_flag
               << ") is out of range.";
    exit(EX_USAGE);
  }
  // We would like to print |VLOG(K)| messages if the verbosity level is `K`.
  // Since the corresponding log level is `-K`, we can resolve the correct
  // log level by simply taking a negative sign.
  return -verbosity_flag;
}

hardware_verifier::CLIOutputFormat SafeConvertOutputFormatFlagToEnum(
    const std::string& output_format_flag) {
  if (output_format_flag == "proto") {
    return hardware_verifier::CLIOutputFormat::kProtoBin;
  }
  if (output_format_flag == "text") {
    return hardware_verifier::CLIOutputFormat::kText;
  }
  LOG(ERROR) << "The output format (" << output_format_flag << ") is invalid.";
  exit(EX_USAGE);
}

}  // namespace

int main(int argc, char* argv[]) {
  // Required by dbus in libchrome.
  base::AtExitManager at_exit_manager;

  DEFINE_int32(verbosity, 0,
               "Verbosity level, range from 0 to 5.  The greater number is "
               "set, the more detail messages will be printed.");
  DEFINE_string(probe_result_file, "",
                "File path to the probe result in prototxt format, empty to "
                "get directly from |runtime_probe| D-Bus service.");
  DEFINE_string(hw_verification_spec_file, "",
                "File path to the hardware verification spec in prototxt "
                "format, empty to use the default one.");
  DEFINE_bool(dbus, false, "Run in the daemon mode to respond D-Bus call.");
  DEFINE_string(output_format, "proto",
                "Format of the output verification report, can be either "
                "\"proto\" for protobuf binary format or \"text\" for human "
                "readable text format.  Only be available in normal mode.");
  DEFINE_bool(send_to_uma, false, "Send data to UMA.");
  DEFINE_bool(pii, false,
              "Output result including PII data like UUID and generic device "
              "info.  Only be available in normal mode.");
  brillo::FlagHelper::Init(argc, argv, "ChromeOS Hardware Verifier Tool");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  base::CommandLine::Init(argc, argv);
  auto* cl = base::CommandLine::ForCurrentProcess();

  // Validate the non-trivial flags and convert them to the proper value types.
  const auto log_level = SafeConvertVerbosityFlagToLogLevel(FLAGS_verbosity);
  logging::SetMinLogLevel(log_level);

  auto observer = hardware_verifier::Observer::GetInstance();
  if (FLAGS_send_to_uma) {
    observer->SetMetricsLibrary(std::make_unique<MetricsLibrary>());
  }

  if (FLAGS_dbus) {
    if (cl->HasSwitch("output_format")) {
      LOG(ERROR) << "--output_format is only available in normal mode.";
      exit(EX_USAGE);
    }
    if (cl->HasSwitch("pii")) {
      LOG(ERROR) << "--pii is only available in normal mode.";
      exit(EX_USAGE);
    }
  }

  const auto output_format =
      SafeConvertOutputFormatFlagToEnum(FLAGS_output_format);

  int exit_status;
  if (FLAGS_dbus) {
    hardware_verifier::Daemon daemon;
    exit_status = daemon.Run();
  } else {
    observer->StartTimer(hardware_verifier::kMetricTimeToFinish);
    hardware_verifier::CLI cli;
    const auto cli_result =
        cli.Run(FLAGS_probe_result_file, FLAGS_hw_verification_spec_file,
                output_format, FLAGS_pii);

    exit_status = ConvertCLIVerificationResultToExitStatus(cli_result);
    observer->StopTimer(hardware_verifier::kMetricTimeToFinish);
  }

  return exit_status;
}
