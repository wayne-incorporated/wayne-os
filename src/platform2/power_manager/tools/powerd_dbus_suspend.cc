// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is meant for debugging use to manually trigger a proper
// suspend, exercising the full path through the power manager.
// The actual work to suspend the system is done by powerd_suspend.
// This tool will block and only exit after it has received a D-Bus
// resume signal from powerd.

#include <unistd.h>

#include <memory>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>
#include <brillo/file_utils.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

#include "power_manager/common/util.h"
#include "power_manager/proto_bindings/suspend.pb.h"

namespace {

// The sysfs entry that controls RTC wake alarms.  To set an alarm, write
// into this file the time of the alarm in seconds since the epoch.
const char kRtcWakeAlarmPath[] = "/sys/class/rtc/rtc0/wakealarm";

// Location of disable_dark_resume preference file. Writing 1 to this file
// disables dark resume.
const char kDisableDarkResumePath[] =
    "/var/lib/power_manager/disable_dark_resume";

std::string WakeupTypeToString(power_manager::SuspendDone::WakeupType type) {
  switch (type) {
    case power_manager::SuspendDone_WakeupType_INPUT:
      return "input";
    case power_manager::SuspendDone_WakeupType_OTHER:
      return "other";
    case power_manager::SuspendDone_WakeupType_NOT_APPLICABLE:
      return "not applicable";
    case power_manager::SuspendDone_WakeupType_UNKNOWN:
      return "not applicable";
  }
}

// Exits when powerd announces that the suspend attempt has completed.
void OnSuspendDone(base::RunLoop* run_loop,
                   bool print_wakeup_type,
                   dbus::Signal* signal) {
  if (print_wakeup_type) {
    power_manager::SuspendDone info;
    dbus::MessageReader reader(signal);
    CHECK(reader.PopArrayOfBytesAsProto(&info));
    LOG(INFO) << "Wakeup type: " << WakeupTypeToString(info.wakeup_type());
  }

  run_loop->Quit();
}

// Exits when powerd announces that the hibernate resume preparation is
// complete.
void OnHibernateResumeReady(base::RunLoop* run_loop, dbus::Signal* signal) {
  run_loop->Quit();
}

// Handles the result of an attempt to connect to a D-Bus signal.
void OnDBusSignalConnected(const std::string& interface,
                           const std::string& signal,
                           bool success) {
  CHECK(success) << "Unable to connect to " << interface << "." << signal;
}

// Invoked if a SuspendDone signal announcing resume isn't received before
// FLAGS_timeout.
void OnTimeout() {
  LOG(FATAL) << "Did not receive a " << power_manager::kSuspendDoneSignal
             << " signal within the timeout.";
}

class DarkResumeConfigurator {
 public:
  explicit DarkResumeConfigurator(bool disable) {
    // Store previous setting of dark resume.
    dark_resume_pref_exist_before_ =
        base::PathExists(base::FilePath(kDisableDarkResumePath));
    if (dark_resume_pref_exist_before_) {
      if (!base::ReadFileToString(base::FilePath(kDisableDarkResumePath),
                                  &prev_dark_resume_pref_state_)) {
        PLOG(ERROR) << "Failed to read previous dark resume state from "
                    << kDisableDarkResumePath;
        exit(1);
      }
    }

    if (!SetDarkResumeState(disable ? "1" : "0"))
      exit(1);
  }
  ~DarkResumeConfigurator() {
    // Restore dark resume state.
    if (!dark_resume_pref_exist_before_) {
      if (!base::DeleteFile(base::FilePath(kDisableDarkResumePath)))
        PLOG(ERROR) << "Failed to restore dark resume state.";
    } else if (!SetDarkResumeState(prev_dark_resume_pref_state_)) {
      PLOG(ERROR) << "Failed to restore dark resume state.";
    }
  }

 private:
  bool SetDarkResumeState(std::string state) {
    auto dark_resume_pref_path = base::FilePath(kDisableDarkResumePath);

    if (!base::CreateDirectory(dark_resume_pref_path.DirName())) {
      PLOG(ERROR) << "Failed to create parent directories for "
                  << kDisableDarkResumePath;
      return false;
    }

    if (!brillo::WriteStringToFile(dark_resume_pref_path, state)) {
      PLOG(ERROR) << "Failed to write " << state << " to "
                  << kDisableDarkResumePath;
      return false;
    }
    return true;
  }

  // Whether |kDisableDarkResumePath| exist before the script start.
  bool dark_resume_pref_exist_before_ = false;
  // Used to Store the original preference in |kDisableDarkResumePath| if the
  // file exist(dark_resume_pref_exist_before_) before the start of the script.
  std::string prev_dark_resume_pref_state_;
};

}  // namespace

int main(int argc, char* argv[]) {
  DEFINE_int32(delay, 1,
               "Delay before suspending in seconds. Useful if "
               "running interactively to ensure that typing this command "
               "isn't recognized as user activity that cancels the suspend "
               "request.");
  DEFINE_int32(timeout, 0, "How long to wait for a resume signal in seconds.");
  DEFINE_uint64(wakeup_count, -1ULL,
                "Wakeup count to pass to powerd or -1ULL if "
                "unset.");
  DEFINE_int32(wakeup_timeout, 0,
               "Sets an RTC alarm immediately that fires after the given "
               "interval. This ensures that device resumes while testing "
               "remotely.");
  DEFINE_int32(suspend_for_sec, 0,
               "Ask powerd to suspend the device for this many seconds. powerd "
               "then sets an alarm just before going to suspend.");
  DEFINE_uint32(
      flavor, 0,
      "Perform a specific flavor of suspend. 0 represents the default, "
      "dealer's choice, which is almost always suspend-to-RAM. "
      "1 is suspend-to-RAM, 2 is suspend-to-disk.");
  DEFINE_bool(print_wakeup_type, false, "Print wakeup type of last resume.");
  DEFINE_bool(disable_dark_resume, true,
              "whether or not to disable dark resume before suspend. Resets to "
              "previous preference on resume. Defaults to True.");

  brillo::FlagHelper::Init(argc, argv,
                           "Instruct powerd to suspend the system.");
  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));
  CHECK(bus->Connect());
  dbus::ObjectProxy* powerd_proxy = bus->GetObjectProxy(
      power_manager::kPowerManagerServiceName,
      dbus::ObjectPath(power_manager::kPowerManagerServicePath));

  if (FLAGS_delay)
    sleep(FLAGS_delay);

  // Set an RTC alarm to wake up the system.
  if (FLAGS_wakeup_timeout > 0) {
    std::string alarm_string = "+" + base::NumberToString(FLAGS_wakeup_timeout);
    // Write 0 first to clear any existing RTC alarm.
    CHECK(power_manager::util::WriteFileFully(base::FilePath(kRtcWakeAlarmPath),
                                              "0", 1));
    CHECK(power_manager::util::WriteFileFully(base::FilePath(kRtcWakeAlarmPath),
                                              alarm_string.c_str(),
                                              alarm_string.length()));
  }

  // Enables/Disables dark resume for this script run based on
  // |FLAGS_disable_dark_resume|. Restores the original preference on exit.
  DarkResumeConfigurator dark_resume_configurator(FLAGS_disable_dark_resume);
  base::RunLoop run_loop;
  powerd_proxy->ConnectToSignal(
      power_manager::kPowerManagerInterface, power_manager::kSuspendDoneSignal,
      base::BindRepeating(&OnSuspendDone, &run_loop, FLAGS_print_wakeup_type),
      base::BindOnce(&OnDBusSignalConnected));

  powerd_proxy->ConnectToSignal(
      power_manager::kPowerManagerInterface,
      power_manager::kHibernateResumeReadySignal,
      base::BindRepeating(&OnHibernateResumeReady, &run_loop),
      base::BindOnce(&OnDBusSignalConnected));

  // Send a suspend request.
  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               power_manager::kRequestSuspendMethod);
  // The arguments are positional, so all earlier arguments must be supplied
  // if a later argument is.
  if (FLAGS_wakeup_count || FLAGS_suspend_for_sec || FLAGS_flavor) {
    dbus::MessageWriter writer(&method_call);
    writer.AppendUint64(FLAGS_wakeup_count);
  }
  // Pass suspend_for_sec to the daemon.
  if (FLAGS_suspend_for_sec || FLAGS_flavor) {
    dbus::MessageWriter writer(&method_call);
    writer.AppendInt32(FLAGS_suspend_for_sec);
  }
  // Pass flavor to the daemon.
  if (FLAGS_flavor) {
    dbus::MessageWriter writer(&method_call);
    writer.AppendUint32(FLAGS_flavor);
  }
  std::unique_ptr<dbus::Response> response(powerd_proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT));
  CHECK(response) << power_manager::kRequestSuspendMethod << " failed";

  // Schedule a task to fire after the timeout.
  if (FLAGS_timeout) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE, base::BindOnce(&OnTimeout), base::Seconds(FLAGS_timeout));
  }

  run_loop.Run();

  return 0;
}
