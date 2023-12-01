// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is a small setuid-root program that runs a few commands on behalf of
// the powerd process.

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <cctype>
#include <cstdarg>
#include <cstdlib>
#include <string>

#include <base/check.h>
#include <base/logging.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/flag_helper.h>
#include <brillo/userdb_utils.h>
#include <libec/set_force_lid_open_command.h>

// Maximum number of arguments supported for internally-defined commands.
const size_t kMaxArgs = 64;

// Value for the PATH environment variable. This is both used to search for
// binaries that are executed by this program and inherited by those binaries.
const char kPathEnvironment[] = "/usr/sbin:/usr/bin:/sbin:/bin";

// Runs a command with the supplied arguments.  The argument list must be
// NULL-terminated.  This method calls exec() without forking, so it will never
// return.
void RunCommand(const char* command, const char* arg, ...) {
  char* argv[kMaxArgs + 1];
  size_t num_args = 1;
  argv[0] = const_cast<char*>(command);

  va_list list;
  va_start(list, arg);
  while (arg) {
    num_args++;
    CHECK(num_args <= kMaxArgs) << "Too many arguments";
    argv[num_args - 1] = const_cast<char*>(arg);
    arg = va_arg(list, char*);
  }
  va_end(list);
  argv[num_args] = nullptr;

  // initctl commands appear to fail if the real UID isn't set correctly.
  PCHECK(setuid(0) == 0) << "setuid() failed";
  PCHECK(clearenv() == 0) << "clearenv() failed";
  PCHECK(setenv("POWERD_SETUID_HELPER", "1", 1) == 0) << "setenv() failed";
  PCHECK(setenv("PATH", kPathEnvironment, 1) == 0) << "setenv() failed";
  PCHECK(execvp(command, argv) != -1) << "execv() failed";
}

int main(int argc, char* argv[]) {
  DEFINE_string(action, "",
                "Action to perform.  Must be one of \"eventlog_add\", "
                "\"reboot\", \"set_force_lid_open\", "
                "\"set_cellular_transmit_power\" \"set_wifi_transmit_power\", "
                "\"shut_down\", and \"suspend\".");
  DEFINE_bool(force_lid_open, false,
              "Whether lid should be forced open or not for "
              "\"set_force_lid_open\" action.");
  DEFINE_string(eventlog_code, "",
                "Hexadecimal byte, e.g. \"0xa7\", "
                "describing the event being logged.");
  DEFINE_string(shutdown_reason, "",
                "Optional shutdown or reboot reason starting with a "
                "lowercase letter and consisting only of lowercase letters and "
                "dashes.");
  DEFINE_uint64(suspend_wakeup_count, 0,
                "Pass --wakeup_count <INT> to "
                "powerd_suspend for the \"suspend\" action.");
  DEFINE_bool(suspend_wakeup_count_valid, false,
              "Should --suspend_wakeup_count be honored?");
  DEFINE_bool(suspend_to_idle, false,
              "Should the system suspend to idle (freeze)?");
  DEFINE_bool(suspend_to_disk, false,
              "Should the system suspend to disk (hibernate)?");
  DEFINE_bool(wifi_transmit_power_tablet, false,
              "Set wifi transmit power mode to tablet mode");
  DEFINE_string(wifi_transmit_power_domain, "",
                "Regulatory domain for wifi transmit power");
  DEFINE_string(wifi_transmit_power_source, "",
                "The change source for wifi transmit power");
  DEFINE_bool(cellular_transmit_power_low, false,
              "Set cellular transmit power mode to low");
  DEFINE_int64(cellular_transmit_power_gpio, -1,
               "GPIO pin to write to for changing cellular transmit power");

  CHECK(brillo::FlagHelper::Init(argc, argv, "powerd setuid helper",
                                 brillo::FlagHelper::InitFuncType::kReturn));

  if (FLAGS_action == "eventlog_add") {
    CHECK(FLAGS_eventlog_code.size() == 4 && FLAGS_eventlog_code[0] == '0' &&
          FLAGS_eventlog_code[1] == 'x' && isxdigit(FLAGS_eventlog_code[2]) &&
          isxdigit(FLAGS_eventlog_code[3]))
        << "Invalid event code";
    RunCommand("elogtool", "add", FLAGS_eventlog_code.c_str(), nullptr);
  } else if (FLAGS_action == "reboot" || FLAGS_action == "shut_down") {
    std::string reason_arg;
    if (!FLAGS_shutdown_reason.empty()) {
      for (size_t i = 0; i < FLAGS_shutdown_reason.size(); ++i) {
        char ch = FLAGS_shutdown_reason[i];
        CHECK((ch >= 'a' && ch <= 'z') || (i > 0 && ch == '-'))
            << "Invalid shutdown reason";
      }
      reason_arg = "SHUTDOWN_REASON=" + FLAGS_shutdown_reason;
    }
    std::string runlevel_arg =
        std::string("RUNLEVEL=") + (FLAGS_action == "reboot" ? "6" : "0");
    RunCommand("initctl", "emit", "--no-wait", "runlevel", runlevel_arg.c_str(),
               (reason_arg.empty() ? nullptr : reason_arg.c_str()), nullptr);
  } else if (FLAGS_action == "set_force_lid_open") {
    base::ScopedFD ec_fd = base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));
    ec::SetForceLidOpenCommand cmd(FLAGS_force_lid_open);
    if (!cmd.Run(ec_fd.get())) {
      // This is expected if system does not have a cros_ec
      LOG(WARNING) << "Failed to set force_lid_open to "
                   << FLAGS_force_lid_open;
    }
  } else if (FLAGS_action == "set_cellular_transmit_power") {
    std::string mode = FLAGS_cellular_transmit_power_low ? "--low" : "";
    std::string target =
        "--gpio=" + base::NumberToString(FLAGS_cellular_transmit_power_gpio);
    RunCommand("set_cellular_transmit_power", mode.c_str(), target.c_str(),
               nullptr);
  } else if (FLAGS_action == "set_wifi_transmit_power") {
    const std::string tablet =
        FLAGS_wifi_transmit_power_tablet ? "--tablet" : "--notablet";
    const std::string domain = "--domain=" + FLAGS_wifi_transmit_power_domain;
    const std::string source = "--source=" + FLAGS_wifi_transmit_power_source;
    RunCommand("set_wifi_transmit_power", tablet.c_str(), domain.c_str(),
               source.c_str(), nullptr);
  } else if (FLAGS_action == "suspend") {
    std::string suspend_flavor = FLAGS_suspend_to_disk
                                     ? std::string("--suspend_to_disk")
                                     : FLAGS_suspend_to_idle
                                           ? std::string("--suspend_to_idle")
                                           : std::string("--nosuspend_to_idle");
    std::string wakeup_flag;
    if (FLAGS_suspend_wakeup_count_valid) {
      wakeup_flag =
          "--wakeup_count=" + base::NumberToString(FLAGS_suspend_wakeup_count);
    }
    RunCommand("powerd_suspend", suspend_flavor.c_str(),
               wakeup_flag.empty() ? nullptr : wakeup_flag.c_str(), nullptr);
  } else {
    LOG(ERROR) << "Unknown action \"" << FLAGS_action << "\"";
    return 1;
  }

  return 0;
}
