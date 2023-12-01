// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This program can be used to send a message to powerd to configure the
// power management policy.  This is the same mechanism used by Chrome; in
// fact, it will overwrite any policy set by Chrome.  To revert to powerd's
// default policy, run it without any arguments.

#include <memory>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

#include "power_manager/proto_bindings/policy.pb.h"

namespace {

const int kMsInSec = 1000;

// Given a command-line flag containing a duration in seconds, a
// PowerManagementPolicy::Delays* |submessage|, and the name of a milliseconds
// field in |submessage|, sets the field if the flag is greater than or equal to
// 0.
#define SET_DELAY_FIELD(flag, submessage, field) \
  if (flag >= 0) {                               \
    submessage->set_##field(flag* kMsInSec);     \
  }

// Given |name| (a string) and |proto| (a PowerManagementPolicy), sets |proto|'s
// |name| bool field to true if |FLAGS_<name>| is positive or to false if it's
// zero, leaving it unset if it's negative.
#define SET_BOOL_FIELD(name, proto)      \
  if (FLAGS_##name >= 0) {               \
    proto.set_##name(FLAGS_##name != 0); \
  }

// Given |name| (a string), |proto| (a PowerManagementPolicy), and |min| (a
// double), sets |proto|'s |name| double field to |FLAGS_<name>| if
// |FLAGS_<name>| is >= |min|, leaving it unset otherwise.
#define SET_DOUBLE_FIELD(name, proto, min) \
  if (FLAGS_##name >= min) {               \
    proto.set_##name(FLAGS_##name);        \
  }

// Given a string from a flag describing an action, returns the
// corresponding value from power_manager::PowerManagementPolicy_Action.
power_manager::PowerManagementPolicy_Action GetAction(
    const std::string& action) {
  if (action == "suspend")
    return power_manager::PowerManagementPolicy_Action_SUSPEND;
  else if (action == "stop_session")
    return power_manager::PowerManagementPolicy_Action_STOP_SESSION;
  else if (action == "shut_down")
    return power_manager::PowerManagementPolicy_Action_SHUT_DOWN;
  else if (action == "do_nothing")
    return power_manager::PowerManagementPolicy_Action_DO_NOTHING;
  else
    LOG(FATAL) << "Invalid action \"" << action << "\"";
  return power_manager::PowerManagementPolicy_Action_DO_NOTHING;
}

}  // namespace

int main(int argc, char* argv[]) {
  // These mirror the fields from the PowerManagementPolicy protocol buffer.
  DEFINE_string(ac_idle_action, "",
                "Action to perform when idle on AC power (one of "
                "suspend, stop_session, shut_down, do_nothing)");
  DEFINE_string(battery_idle_action, "",
                "Action to perform when idle on battery power (one of "
                "suspend, stop_session, shut_down, do_nothing)");
  DEFINE_string(lid_closed_action, "",
                "Action to perform when lid is closed (one of "
                "suspend, stop_session, shut_down, do_nothing)");
  DEFINE_int32(ac_screen_dim_delay, -1,
               "Delay before dimming screen on AC power, in seconds");
  DEFINE_int32(ac_screen_off_delay, -1,
               "Delay before turning screen off on AC power, in seconds");
  DEFINE_int32(ac_screen_lock_delay, -1,
               "Delay before locking screen on AC power, in seconds");
  DEFINE_int32(ac_idle_warning_delay, -1,
               "Delay before idle action warning on AC power, in seconds");
  DEFINE_int32(ac_idle_delay, -1,
               "Delay before idle action on AC power, in seconds");
  DEFINE_int32(battery_screen_dim_delay, -1,
               "Delay before dimming screen on battery power, in seconds");
  DEFINE_int32(battery_screen_off_delay, -1,
               "Delay before turning screen off on battery power, in seconds");
  DEFINE_int32(battery_screen_lock_delay, -1,
               "Delay before locking screen on battery power, in seconds");
  DEFINE_int32(battery_idle_warning_delay, -1,
               "Delay before idle action warning on battery power, in seconds");
  DEFINE_int32(battery_idle_delay, -1,
               "Delay before idle action on battery power, in seconds");
  DEFINE_int32(dim_wake_lock, -1,
               "Report dim wake lock (1 is true, 0 is false, -1 is unset");
  DEFINE_int32(screen_wake_lock, -1,
               "Report screen wake lock (1 is true, 0 is false, -1 is unset");
  DEFINE_int32(system_wake_lock, -1,
               "Report system wake lock (1 is true, 0 is false, -1 is unset");
  DEFINE_int32(use_audio_activity, -1,
               "Honor audio activity (1 is true, 0 is false, -1 is unset");
  DEFINE_int32(use_video_activity, -1,
               "Honor video activity (1 is true, 0 is false, -1 is unset");
  DEFINE_int32(wait_for_initial_user_activity, -1,
               "Wait for initial user activity before enforcing delays "
               "(1 is true, 0 is false, -1 is unset");
  DEFINE_int32(force_nonzero_brightness_for_user_activity, -1,
               "Force panel backlight to non-zero brightness for user activity "
               "(1 is true, 0 is false, -1 is unset");
  DEFINE_double(ac_brightness_percent, -1.0,
                "Brightness percent to use while on AC power (less than 0.0 "
                "means unset)");
  DEFINE_double(battery_brightness_percent, -1.0,
                "Brightness percent to use while on battery power (less than "
                "0.0 means unset)");
  DEFINE_double(presentation_screen_dim_delay_factor, 0.0,
                "Factor by which the screen-dim delay is scaled while "
                "presenting (less than 1.0 means unset)");
  DEFINE_double(user_activity_screen_dim_delay_factor, 0.0,
                "Factor by which the screen-dim delay is scaled if user "
                "activity is observed while the screen is dimmed or soon after "
                "it's been turned off (less than 1.0 means unset)");

  brillo::FlagHelper::Init(
      argc, argv,
      "Configures powerd's power management policy.\n\n"
      "When called without any arguments, uses default settings.");
  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  power_manager::PowerManagementPolicy policy;

  if (!FLAGS_ac_idle_action.empty())
    policy.set_ac_idle_action(GetAction(FLAGS_ac_idle_action));
  if (!FLAGS_battery_idle_action.empty())
    policy.set_battery_idle_action(GetAction(FLAGS_battery_idle_action));
  if (!FLAGS_lid_closed_action.empty())
    policy.set_lid_closed_action(GetAction(FLAGS_lid_closed_action));

  power_manager::PowerManagementPolicy::Delays* delays =
      policy.mutable_ac_delays();
  SET_DELAY_FIELD(FLAGS_ac_screen_dim_delay, delays, screen_dim_ms);
  SET_DELAY_FIELD(FLAGS_ac_screen_off_delay, delays, screen_off_ms);
  SET_DELAY_FIELD(FLAGS_ac_screen_lock_delay, delays, screen_lock_ms);
  SET_DELAY_FIELD(FLAGS_ac_idle_warning_delay, delays, idle_warning_ms);
  SET_DELAY_FIELD(FLAGS_ac_idle_delay, delays, idle_ms);

  delays = policy.mutable_battery_delays();
  SET_DELAY_FIELD(FLAGS_battery_screen_dim_delay, delays, screen_dim_ms);
  SET_DELAY_FIELD(FLAGS_battery_screen_off_delay, delays, screen_off_ms);
  SET_DELAY_FIELD(FLAGS_battery_screen_lock_delay, delays, screen_lock_ms);
  SET_DELAY_FIELD(FLAGS_battery_idle_warning_delay, delays, idle_warning_ms);
  SET_DELAY_FIELD(FLAGS_battery_idle_delay, delays, idle_ms);

  SET_BOOL_FIELD(use_audio_activity, policy);
  SET_BOOL_FIELD(use_video_activity, policy);
  SET_BOOL_FIELD(wait_for_initial_user_activity, policy);
  SET_BOOL_FIELD(force_nonzero_brightness_for_user_activity, policy);
  SET_BOOL_FIELD(dim_wake_lock, policy);
  SET_BOOL_FIELD(screen_wake_lock, policy);
  SET_BOOL_FIELD(system_wake_lock, policy);

  SET_DOUBLE_FIELD(ac_brightness_percent, policy, 0.0);
  SET_DOUBLE_FIELD(battery_brightness_percent, policy, 0.0);
  SET_DOUBLE_FIELD(presentation_screen_dim_delay_factor, policy, 1.0);
  SET_DOUBLE_FIELD(user_activity_screen_dim_delay_factor, policy, 1.0);

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));
  CHECK(bus->Connect());
  dbus::ObjectProxy* proxy = bus->GetObjectProxy(
      power_manager::kPowerManagerServiceName,
      dbus::ObjectPath(power_manager::kPowerManagerServicePath));

  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               power_manager::kSetPolicyMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendProtoAsArrayOfBytes(policy);
  std::unique_ptr<dbus::Response> response(proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT));
  CHECK(response.get());

  return 0;
}
