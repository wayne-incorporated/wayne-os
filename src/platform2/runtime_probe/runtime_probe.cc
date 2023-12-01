// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <optional>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "runtime_probe/avl_probe_config_loader.h"
#include "runtime_probe/daemon.h"
#include "runtime_probe/generic_probe_config_loader.h"
#include "runtime_probe/probe_config.h"
#include "runtime_probe/probe_config_loader.h"
#include "runtime_probe/probe_function.h"
#include "runtime_probe/system/context_helper_impl.h"
#include "runtime_probe/system/context_runtime_impl.h"

namespace {
enum ExitStatus {
  kSuccess = EXIT_SUCCESS,  // 0
  kUnknownError = 1,
  kFailedToParseProbeStatementFromArg = 2,
  kArgumentError = 3,
  kFailedToLoadProbeConfig = 11,
  kFailToParseProbeArgFromConfig = 12,
};

int RunAsHelper() {
  // This can help to verify the logging is working while generating seccomp
  // policy.
  DLOG(INFO) << "Starting Runtime Probe helper.";

  const auto* command_line = base::CommandLine::ForCurrentProcess();
  const auto args = command_line->GetArgs();

  for (size_t i = 0; i < args.size(); ++i) {
    DVLOG(1) << "Got arguments, index " << i << " = " << args[i];
  }

  if (args.size() != 1) {
    LOG(ERROR) << "Helper only consumes a single probe statement";
    return kFailedToParseProbeStatementFromArg;
  }

  auto val = base::JSONReader::Read(args[0]);
  if (!val || !val->is_dict()) {
    LOG(ERROR) << "Failed to parse the probe statement to JSON";
    return kFailedToParseProbeStatementFromArg;
  }

  runtime_probe::ContextHelperImpl context;

  auto probe_function = runtime_probe::ProbeFunction::FromValue(*val);
  if (probe_function == nullptr) {
    LOG(ERROR) << "Failed to convert a probe statement to probe function";
    return kFailedToParseProbeStatementFromArg;
  }

  std::string output;
  int ret = probe_function->EvalInHelper(&output);
  if (ret)
    return ret;

  std::cout << output << std::flush;
  return ExitStatus::kSuccess;
}

int RunAsDaemon() {
  LOG(INFO) << "Starting Runtime Probe. Running in daemon mode";
  runtime_probe::ContextRuntimeImpl context;
  runtime_probe::Daemon daemon;
  return daemon.Run();
}

// Invoke as a command line tool. Device can load arbitrary probe config
// iff cros_debug == 1
int RunningInCli(const std::string& config_file_path, bool to_stdout) {
  LOG(INFO) << "Starting Runtime Probe. Running in CLI mode";

  // Required by dbus in libchrome.
  base::AtExitManager at_exit_manager;
  runtime_probe::ContextRuntimeImpl context;

  std::unique_ptr<runtime_probe::ProbeConfigLoader> config_loader;
  if (config_file_path.empty()) {
    config_loader = std::make_unique<runtime_probe::AvlProbeConfigLoader>();
  } else {
    config_loader = std::make_unique<runtime_probe::GenericProbeConfigLoader>(
        base::FilePath{config_file_path});
  }

  auto probe_config = config_loader->Load();
  if (!probe_config) {
    LOG(ERROR) << "Failed to load probe config";
    return ExitStatus::kFailedToLoadProbeConfig;
  }

  LOG(INFO) << "Load probe config from: " << probe_config->path()
            << " (checksum: " << probe_config->checksum() << ")";

  const auto probe_result = probe_config->Eval();
  if (to_stdout) {
    LOG(INFO) << "Dumping probe results to stdout";
    std::cout << probe_result;
  } else {
    LOG(INFO) << probe_result;
  }

  return ExitStatus::kSuccess;
}

}  // namespace

int main(int argc, char* argv[]) {
  // Don't output any log until we know in which mode we are.
  brillo::InitLog(0);

  DEFINE_string(config_file_path, "",
                "File path to probe config, empty to use default one");
  DEFINE_bool(dbus, false, "Run in the mode to respond D-Bus call");
  DEFINE_bool(helper, false, "Run in the mode to execute probe function");
  DEFINE_bool(to_stdout, false, "Output probe result to stdout");
  DEFINE_int32(log_level, 0,
               "Logging level - 0: LOG(INFO), 1: LOG(WARNING), 2: LOG(ERROR), "
               "-1: VLOG(1), -2: VLOG(2), ...");
  brillo::FlagHelper::Init(argc, argv, "ChromeOS runtime probe tool");

  logging::SetMinLogLevel(FLAGS_log_level);
  if (FLAGS_helper) {
    // Don't log to syslog in helper. Notes that log to syslog request
    // additional syscall.
    brillo::SetLogFlags(brillo::kLogToStderr);
  } else {
    brillo::SetLogFlags(brillo::kLogToSyslog | brillo::kLogToStderr);
  }

  if (FLAGS_helper && FLAGS_dbus) {
    LOG(ERROR) << "--helper conflicts with --dbus";
    return ExitStatus::kArgumentError;
  }
  if ((FLAGS_helper || FLAGS_dbus) &&
      (FLAGS_to_stdout || FLAGS_config_file_path != "")) {
    LOG(WARNING) << "--to_stdout and --config_file_path are not supported in "
                    "helper mode and dbus mode.";
  }

  if (FLAGS_helper)
    return RunAsHelper();
  if (FLAGS_dbus)
    return RunAsDaemon();
  return RunningInCli(FLAGS_config_file_path, FLAGS_to_stdout);
}
