// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A daemon for performing crypto operations for Easy Unlock.

#include <memory>

#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/memory/ref_counted.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>

#include "easy-unlock/dbus_adaptor.h"
#include "easy-unlock/easy_unlock_service.h"

namespace {

namespace switches {

// Command line switch to run this daemon in foreground.
const char kForeground[] = "foreground";

// Command line switch to show the help message and exit.
const char kHelp[] = "help";

// Command line switch to set the logging level:
//   0 = LOG(INFO), 1 = LOG(WARNING), 2 = LOG(ERROR)
const char kLogLevel[] = "log-level";

// Help message to show when the --help command line switch is specified.
const char kHelpMessage[] =
    "Chrome OS EasyUnlock Daemon\n"
    "\n"
    "Available Switches:\n"
    "  --foreground\n"
    "    Do not daemonize; run in foreground.\n"
    "  --log-level=N\n"
    "    Logging level:\n"
    "      0: LOG(INFO), 1: LOG(WARNING), 2: LOG(ERROR)\n"
    "      -1: VLOG(1), -2: VLOG(2), etc\n"
    "  --help\n"
    "    Show this help.\n"
    "\n";

}  // namespace switches

int GetLogLevel(const std::string& log_level_value) {
  int log_level = 0;
  if (!base::StringToInt(log_level_value, &log_level)) {
    LOG(WARNING) << "Invalid log level '" << log_level_value << "'";
  } else if (log_level >= logging::LOGGING_NUM_SEVERITIES) {
    log_level = logging::LOGGING_NUM_SEVERITIES;
  }
  return log_level;
}

// Always logs to syslog and stderr when running in the foreground.
void SetupLogging(bool foreground, int log_level) {
  int log_flags = brillo::kLogToSyslog;
  if (foreground)
    log_flags |= brillo::kLogToStderr;

  brillo::InitLog(log_flags);
  logging::SetMinLogLevel(log_level);
}

}  // namespace

namespace easy_unlock {

class Daemon : public brillo::DBusServiceDaemon {
 public:
  explicit Daemon(std::unique_ptr<easy_unlock::Service> service_impl)
      : brillo::DBusServiceDaemon(kEasyUnlockServiceName),
        service_impl_(std::move(service_impl)) {}
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  ~Daemon() override {}

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    adaptor_.reset(new DBusAdaptor(bus_, service_impl_.get()));
    adaptor_->Register(sequencer->GetHandler("Register dbus methods", true));
  }

 private:
  std::unique_ptr<easy_unlock::Service> service_impl_;
  std::unique_ptr<easy_unlock::DBusAdaptor> adaptor_;
};

}  // namespace easy_unlock

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  if (cl->HasSwitch(switches::kHelp)) {
    LOG(INFO) << switches::kHelpMessage;
    return 0;
  }

  bool foreground = cl->HasSwitch(switches::kForeground);
  int log_level =
      cl->HasSwitch(switches::kLogLevel)
          ? GetLogLevel(cl->GetSwitchValueASCII(switches::kLogLevel))
          : 0;

  SetupLogging(foreground, log_level);

  if (!foreground)
    PLOG_IF(FATAL, ::daemon(0, 0) == 1) << "Failed to create daemon";

  easy_unlock::Daemon daemon(easy_unlock::Service::Create());
  LOG(INFO) << "Starting EasyUnlock dbus service.";
  return daemon.Run();
}
