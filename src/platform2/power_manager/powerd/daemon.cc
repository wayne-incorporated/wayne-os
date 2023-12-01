// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/daemon.h"

#include <fcntl.h>
#include <inttypes.h>

#include <algorithm>
#include <cmath>
#include <map>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/format_macros.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/task/sequenced_task_runner.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/mojo/service_constants.h>
#include <chromeos/ec/ec_commands.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <libec/ec_command.h>
#include <libec/charge_control_set_command.h>
#include <libec/charge_current_limit_set_command.h>

#include "power_manager/common/activity_logger.h"
#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/metrics_sender.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/tracing.h"
#include "power_manager/common/util.h"
#include "power_manager/powerd/daemon_delegate.h"
#include "power_manager/powerd/metrics_collector.h"
#include "power_manager/powerd/policy/backlight_controller.h"
#include "power_manager/powerd/policy/input_device_controller.h"
#include "power_manager/powerd/policy/shutdown_from_suspend.h"
#include "power_manager/powerd/policy/state_controller.h"
#include "power_manager/powerd/policy/thermal_event_handler.h"
#include "power_manager/powerd/system/acpi_wakeup_helper_interface.h"
#include "power_manager/powerd/system/ambient_light_sensor_manager_interface.h"
#if USE_IIOSERVICE
#include <mojo_service_manager/lib/connect.h>
#endif  // USE_IIOSERVICE
#include "power_manager/powerd/system/ambient_light_sensor_watcher_interface.h"
#include "power_manager/powerd/system/ambient_light_sensor_watcher_mojo.h"
#include "power_manager/powerd/system/arc_timer_manager.h"
#include "power_manager/powerd/system/audio_client_interface.h"
#include "power_manager/powerd/system/backlight_interface.h"
#include "power_manager/powerd/system/charge_controller_helper_interface.h"
#include "power_manager/powerd/system/cros_ec_device_event.h"
#include "power_manager/powerd/system/cros_ec_helper_interface.h"
#include "power_manager/powerd/system/dark_resume_interface.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/powerd/system/display/display_power_setter.h"
#include "power_manager/powerd/system/display/display_watcher.h"
#include "power_manager/powerd/system/external_ambient_light_sensor_factory_interface.h"
#include "power_manager/powerd/system/input_watcher_interface.h"
#include "power_manager/powerd/system/lockfile_checker.h"
#include "power_manager/powerd/system/peripheral_battery_watcher.h"
#include "power_manager/powerd/system/power_supply.h"
#include "power_manager/powerd/system/smart_discharge_configurator.h"
#include "power_manager/powerd/system/suspend_configurator.h"
#include "power_manager/powerd/system/suspend_freezer.h"
#include "power_manager/powerd/system/thermal/thermal_device.h"
#include "power_manager/powerd/system/udev.h"
#include "power_manager/powerd/system/usb_backlight.h"
#include "power_manager/powerd/system/user_proximity_watcher_interface.h"
#include "power_manager/powerd/system/wake_on_dp_configurator.h"
#include "power_manager/powerd/system/wakeup_source_identifier.h"
#include "power_manager/proto_bindings/idle.pb.h"
#include "power_manager/proto_bindings/policy.pb.h"
#include "power_manager/proto_bindings/user_charging_event.pb.h"

namespace power_manager {
namespace {

// Default values for |*_path_| members (which can be overridden for tests).
const char kDefaultSuspendedStatePath[] =
    "/var/lib/power_manager/powerd_suspended";
const char kDefaultHibernatedStatePath[] =
    "/var/lib/power_manager/powerd_hibernated";
const char kDefaultWakeupCountPath[] = "/sys/power/wakeup_count";
const char kDefaultOobeCompletedPath[] = "/home/chronos/.oobe_completed";

// Directory checked for lockfiles indicating that powerd shouldn't suspend or
// shut down the system (typically due to a firmware update).
const char kPowerOverrideLockfileDir[] = "/run/lock/power_override";

// Basename appended to |run_dir| (see Daemon's c'tor) to produce
// |suspend_announced_path_|.
const char kSuspendAnnouncedFile[] = "suspend_announced";

// Strings for states that powerd cares about from the session manager's
// SessionStateChanged signal. This value is defined in the session_manager
// codebase.
const char kSessionStarted[] = "started";

// After noticing that power management is overridden while suspending, wait up
// to this long for the lockfile(s) to be removed before reporting a suspend
// failure. The event loop is blocked during this period.
constexpr base::TimeDelta kSuspendLockfileTimeout = base::Milliseconds(500);

// Interval between successive polls during kSuspendLockfileTimeout.
constexpr base::TimeDelta kSuspendLockfilePollInterval =
    base::Milliseconds(100);

// Interval between attempts to retry shutting the system down while power
// management is overridden, in seconds.
constexpr base::TimeDelta kShutdownLockfileRetryInterval = base::Seconds(5);

// Maximum amount of time to wait for responses to D-Bus method calls to other
// processes.
constexpr base::TimeDelta kSessionManagerDBusTimeout = base::Seconds(3);
constexpr base::TimeDelta kTpmManagerdDBusTimeout = base::Minutes(2);
constexpr base::TimeDelta kResourceManagerDBusTimeout = base::Seconds(3);
constexpr base::TimeDelta kPrivacyScreenServiceDBusTimeoutMs = base::Seconds(3);

// Interval between log messages while user, audio, or video activity is
// ongoing, in seconds.
const int kLogOngoingActivitySec = 180;

// Time after the last report from Chrome of video or user activity at which
// point a message is logged about the activity having stopped. Chrome reports
// these every five seconds, but longer delays here reduce the amount of log
// spam due to sporadic activity.
const int kLogVideoActivityStoppedDelaySec = 20;
const int kLogUserActivityStoppedDelaySec = 20;

// Delay to wait before logging that hovering has stopped. This is ideally
// smaller than kKeyboardBacklightKeepOnMsPref; otherwise the backlight can be
// turned off before the hover-off event that triggered it is logged.
const int64_t kLogHoveringStoppedDelaySec = 20;

// Domain for D-Bus error messages.
const char kErrorDomain[] = "powerd";

// Type for D-Bus error messages.
const char kInternalError[] = "internal_error";

// Cros Config path to search in for the PSU type.
const char kHardwareProperties[] = "/hardware-properties";

// Cros Config property to fetch to see if the system has a battery (not
// counting back-up power supplies for short power outages).
const char kPSUType[] = "psu-type";

// PSU Type for Cros Config that refers to a system that is designed to run off
// the battery as a primary use case.
const char kBattery[] = "battery";

// When we're making sync calls to the Adaptive Charging ML Service, use a
// shorter timeout.
const int kAdaptiveChargingSyncDBusTimeoutMs = 3000;

#if USE_IIOSERVICE
constexpr base::TimeDelta kReconnectServiceManagerDelay = base::Seconds(1);
#endif  // USE_IIOSERVICE

// MCU type for Prism in CrOS config
const char kPrismRgbController[] = "prism_rgb_controller";

// Passes |method_call| to |handler| and passes the response to
// |response_sender|. If |handler| returns NULL, an empty response is
// created and sent.
void HandleSynchronousDBusMethodCall(
    base::OnceCallback<std::unique_ptr<dbus::Response>(dbus::MethodCall*)>
        handler,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  std::unique_ptr<dbus::Response> response =
      std::move(handler).Run(method_call);
  if (!response)
    response = dbus::Response::FromMethodCall(method_call);
  std::move(response_sender).Run(std::move(response));
}

// Creates a new "invalid args" reply to |method_call|.
std::unique_ptr<dbus::Response> CreateInvalidArgsError(
    dbus::MethodCall* method_call, std::string message) {
  return std::unique_ptr<dbus::Response>(dbus::ErrorResponse::FromMethodCall(
      method_call, DBUS_ERROR_INVALID_ARGS, message));
}

std::string PrivacyScreenStateToString(
    const privacy_screen::PrivacyScreenSetting_PrivacyScreenState& state) {
  switch (state) {
    case privacy_screen::PrivacyScreenSetting_PrivacyScreenState_DISABLED:
      return "disabled";
    case privacy_screen::PrivacyScreenSetting_PrivacyScreenState_ENABLED:
      return "enabled";
    case privacy_screen::PrivacyScreenSetting_PrivacyScreenState_NOT_SUPPORTED:
      return "not supported";
    default:
      NOTREACHED() << "Unhandled privacy screen state "
                   << static_cast<int>(state);
      return base::StringPrintf("unknown (%d)", static_cast<int>(state));
  }
}

}  // namespace

// static
constexpr char Daemon::kAlreadyRanFileName[];

// Performs actions requested by |state_controller_|.  The reason that
// this is a nested class of Daemon rather than just being implemented as
// part of Daemon is to avoid method naming conflicts.
class Daemon::StateControllerDelegate
    : public policy::StateController::Delegate {
 public:
  explicit StateControllerDelegate(Daemon* daemon) : daemon_(daemon) {}
  StateControllerDelegate(const StateControllerDelegate&) = delete;
  StateControllerDelegate& operator=(const StateControllerDelegate&) = delete;

  ~StateControllerDelegate() override { daemon_ = nullptr; }

  // Overridden from policy::StateController::Delegate:
  bool IsUsbInputDeviceConnected() override {
    return daemon_->input_watcher_->IsUSBInputDeviceConnected();
  }

  bool IsOobeCompleted() override {
    return base::PathExists(base::FilePath(daemon_->oobe_completed_path_));
  }

  bool IsHdmiAudioActive() override {
    return daemon_->audio_client_ ? daemon_->audio_client_->GetHdmiActive()
                                  : false;
  }

  bool IsHeadphoneJackPlugged() override {
    return daemon_->audio_client_
               ? daemon_->audio_client_->GetHeadphoneJackPlugged()
               : false;
  }

  void DimScreen() override { daemon_->SetBacklightsDimmedForInactivity(true); }

  void UndimScreen() override {
    daemon_->SetBacklightsDimmedForInactivity(false);
  }

  void TurnScreenOff() override {
    daemon_->SetBacklightsOffForInactivity(true);
  }

  void TurnScreenOn() override {
    daemon_->SetBacklightsOffForInactivity(false);
  }

  void LockScreen() override {
    dbus::MethodCall method_call(login_manager::kSessionManagerInterface,
                                 login_manager::kSessionManagerLockScreen);
    daemon_->dbus_wrapper_->CallMethodSync(daemon_->session_manager_dbus_proxy_,
                                           &method_call,
                                           kSessionManagerDBusTimeout);
  }

  void Suspend(policy::StateController::ActionReason reason) override {
    SuspendImminent::Reason suspend_reason = SuspendImminent_Reason_OTHER;
    switch (reason) {
      case policy::StateController::ActionReason::IDLE:
        suspend_reason = SuspendImminent_Reason_IDLE;
        break;
      case policy::StateController::ActionReason::LID_CLOSED:
        suspend_reason = SuspendImminent_Reason_LID_CLOSED;
        break;
    }
    daemon_->Suspend(suspend_reason, false, 0, base::TimeDelta(),
                     SuspendFlavor::SUSPEND_DEFAULT);
  }

  void StopSession() override {
    // This session manager method takes a string argument, although it
    // doesn't currently do anything with it.
    dbus::MethodCall method_call(login_manager::kSessionManagerInterface,
                                 login_manager::kSessionManagerStopSession);
    dbus::MessageWriter writer(&method_call);
    writer.AppendString("");
    daemon_->dbus_wrapper_->CallMethodSync(daemon_->session_manager_dbus_proxy_,
                                           &method_call,
                                           kSessionManagerDBusTimeout);
  }

  void ShutDown() override {
    daemon_->ShutDown(ShutdownMode::POWER_OFF,
                      ShutdownReason::STATE_TRANSITION);
  }

  void ReportUserActivityMetrics() override {
    daemon_->metrics_collector_->GenerateUserActivityMetrics();
  }

  void ReportDimEventMetrics(metrics::DimEvent sample) override {
    daemon_->metrics_collector_->GenerateDimEventMetrics(sample);
  }

  void ReportLockEventMetrics(metrics::LockEvent sample) override {
    daemon_->metrics_collector_->GenerateLockEventMetrics(sample);
  }

  void ReportHpsEventDurationMetrics(const std::string& event_name,
                                     base::TimeDelta duration) override {
    daemon_->metrics_collector_->GenerateHpsEventDurationMetrics(event_name,
                                                                 duration);
  }

 private:
  Daemon* daemon_;  // weak
};

Daemon::Daemon(DaemonDelegate* delegate, const base::FilePath& run_dir)
    : delegate_(delegate),
      state_controller_delegate_(new StateControllerDelegate(this)),
      state_controller_(new policy::StateController),
      input_event_handler_(new policy::InputEventHandler),
      input_device_controller_(new policy::InputDeviceController),
      shutdown_from_suspend_(std::make_unique<policy::ShutdownFromSuspend>()),
      suspender_(new policy::Suspender),
      bluetooth_controller_(std::make_unique<policy::BluetoothController>()),
      wifi_controller_(std::make_unique<policy::WifiController>()),
      cellular_controller_(std::make_unique<policy::CellularController>()),
      metrics_collector_(new metrics::MetricsCollector),
      arc_timer_manager_(std::make_unique<system::ArcTimerManager>()),
      wakeup_count_path_(kDefaultWakeupCountPath),
      oobe_completed_path_(kDefaultOobeCompletedPath),
      cros_ec_path_(ec::kCrosEcPath),
      run_dir_(run_dir),
      suspended_state_path_(kDefaultSuspendedStatePath),
      hibernated_state_path_(kDefaultHibernatedStatePath),
      suspend_announced_path_(run_dir.Append(kSuspendAnnouncedFile)),
      already_ran_path_(run_dir.Append(Daemon::kAlreadyRanFileName)),
      video_activity_logger_(new PeriodicActivityLogger(
          "Video activity",
          base::Seconds(kLogVideoActivityStoppedDelaySec),
          base::Seconds(kLogOngoingActivitySec))),
      user_activity_logger_(new PeriodicActivityLogger(
          "User activity",
          base::Seconds(kLogUserActivityStoppedDelaySec),
          base::Seconds(kLogOngoingActivitySec))),
      audio_activity_logger_(
          new StartStopActivityLogger("Audio activity",
                                      base::TimeDelta(),
                                      base::Seconds(kLogOngoingActivitySec))),
      hovering_logger_(new StartStopActivityLogger(
          "Hovering",
          base::Seconds(kLogHoveringStoppedDelaySec),
          base::TimeDelta())),
      weak_ptr_factory_(this) {}

Daemon::~Daemon() {
  if (dbus_wrapper_)
    dbus_wrapper_->RemoveObserver(this);
  if (audio_client_)
    audio_client_->RemoveObserver(this);
  if (power_supply_)
    power_supply_->RemoveObserver(this);

  battery_saver_controller_.RemoveObserver(this);
}

void Daemon::Init() {
  // Check if this is the first run of powerd after boot.
  first_run_after_boot_ = !base::PathExists(already_ran_path_);
  if (first_run_after_boot_) {
    if (base::WriteFile(already_ran_path_, "", 0) != 0)
      PLOG(ERROR) << "Couldn't create " << already_ran_path_.value();
  }

  prefs_ = delegate_->CreatePrefs();
  InitTracing();
  InitDBus();

  factory_mode_ = BoolPrefIsTrue(kFactoryModePref);
  if (factory_mode_)
    LOG(INFO) << "Factory mode enabled; most functionality will be disabled";

  platform_features_ = delegate_->CreatePlatformFeatures(dbus_wrapper_.get());
  metrics_sender_ = delegate_->CreateMetricsSender();
  udev_ = delegate_->CreateUdev();
  input_watcher_ = delegate_->CreateInputWatcher(prefs_.get(), udev_.get());
  suspend_configurator_ =
      delegate_->CreateSuspendConfigurator(platform_features_, prefs_.get());
  suspend_freezer_ = delegate_->CreateSuspendFreezer(prefs_.get());
  wakeup_source_identifier_ =
      std::make_unique<system::WakeupSourceIdentifier>(udev_.get());

  const TabletMode tablet_mode = input_watcher_->GetTabletMode();
  if (tablet_mode == TabletMode::ON)
    LOG(INFO) << "Tablet mode enabled at startup";
  const LidState lid_state = input_watcher_->QueryLidState();
  if (lid_state == LidState::CLOSED)
    LOG(INFO) << "Lid closed at startup";

#if USE_IIOSERVICE
  sensor_service_handler_ = delegate_->CreateSensorServiceHandler();
  if (!disable_mojo_for_testing_)
    ConnectToMojoServiceManager();
#endif  // USE_IIOSERVICE

  if (BoolPrefIsTrue(kExternalAmbientLightSensorPref)) {
#if USE_IIOSERVICE
    ambient_light_sensor_watcher_ = delegate_->CreateAmbientLightSensorWatcher(
        sensor_service_handler_.get());
    external_ambient_light_sensor_factory_ =
        delegate_->CreateExternalAmbientLightSensorFactory(
            static_cast<system::AmbientLightSensorWatcherMojo*>(
                ambient_light_sensor_watcher_.get()));
#else   // !USE_IIOSERVICE
    ambient_light_sensor_watcher_ =
        delegate_->CreateAmbientLightSensorWatcher(udev_.get());
    external_ambient_light_sensor_factory_ =
        delegate_->CreateExternalAmbientLightSensorFactory();
#endif  // USE_IIOSERVICE
  }
  display_watcher_ = delegate_->CreateDisplayWatcher(udev_.get());
  display_power_setter_ =
      delegate_->CreateDisplayPowerSetter(dbus_wrapper_.get());

  ec_command_factory_ = delegate_->CreateEcCommandFactory();

  // Ignore the ALS and backlights in factory mode.
  if (!factory_mode_) {
    light_sensor_manager_ = delegate_->CreateAmbientLightSensorManager(
        prefs_.get(), sensor_service_handler_.get());

    if (BoolPrefIsTrue(kExternalDisplayOnlyPref)) {
      display_backlight_controller_ =
          delegate_->CreateExternalBacklightController(
              prefs_.get(), ambient_light_sensor_watcher_.get(),
              external_ambient_light_sensor_factory_.get(),
              display_watcher_.get(), display_power_setter_.get(),
              dbus_wrapper_.get());
    } else {
      display_backlight_ = delegate_->CreateInternalBacklight(
          base::FilePath(kInternalBacklightPath), kInternalBacklightPattern);
      if (!display_backlight_) {
        LOG(ERROR) << "Failed to initialize display backlight under "
                   << kInternalBacklightPath << " using pattern "
                   << kInternalBacklightPattern;
      } else {
        display_backlight_controller_ =
            delegate_->CreateInternalBacklightController(
                display_backlight_.get(), prefs_.get(),
                light_sensor_manager_->GetSensorForInternalBacklight(),
                display_power_setter_.get(), dbus_wrapper_.get(), lid_state);
      }
    }
    if (display_backlight_controller_)
      all_backlight_controllers_.push_back(display_backlight_controller_.get());

    if (BoolPrefIsTrue(kHasKeyboardBacklightPref)) {
      auto config = std::make_unique<brillo::CrosConfig>();
      std::string value;

      if (config->GetString("/keyboard", "mcutype", &value) &&
          value == kPrismRgbController) {
        LOG(INFO) << "Attempting to create RGB keyboard backlight";
        keyboard_backlight_ =
            std::make_unique<system::UsbBacklight>(udev_.get());
      } else {
        LOG(INFO) << "Attempting to create EcKeyboardBacklight";
        ec_usb_endpoint_ = delegate_->CreateEcUsbEndpoint();
        keyboard_backlight_ =
            delegate_->CreateEcKeyboardBacklight(ec_usb_endpoint_.get());
        // All devices should receive a valid instance of EC keyboard backlight
        // controller in keyboard_backlight_. If EC doesn't support kblight
        // command (i.e. EC_CMD_PWM_GET_KEYBOARD_BACKLIGHT) for some reason, we
        // fall back to the previous method below.
        if (keyboard_backlight_ == nullptr) {
          LOG(INFO) << "Attempting to create PluggableInternalBacklight";
          keyboard_backlight_ = delegate_->CreatePluggableInternalBacklight(
              udev_.get(), kKeyboardBacklightUdevSubsystem,
              base::FilePath(kKeyboardBacklightPath),
              kKeyboardBacklightPattern);
        }
      }
      keyboard_backlight_controller_ =
          delegate_->CreateKeyboardBacklightController(
              keyboard_backlight_.get(), prefs_.get(),
              light_sensor_manager_->GetSensorForKeyboardBacklight(),
              dbus_wrapper_.get(), lid_state, tablet_mode);
      all_backlight_controllers_.push_back(
          keyboard_backlight_controller_.get());
    }
  }

  machine_quirks_ = delegate_->CreateMachineQuirks(prefs_.get());
  machine_quirks_->ApplyQuirksToPrefs();
  prefs_->GetBool(kManualEventlogAddPref, &log_suspend_manually_);
  prefs_->GetBool(kSuspendToIdlePref, &suspend_to_idle_);

  battery_percentage_converter_ =
      BatteryPercentageConverter::CreateFromPrefs(prefs_.get());

  power_supply_ = delegate_->CreatePowerSupply(
      base::FilePath(kPowerStatusPath), cros_ec_path_,
      ec_command_factory_.get(), prefs_.get(), udev_.get(), dbus_wrapper_.get(),
      battery_percentage_converter_.get());
  power_supply_->AddObserver(this);
  if (!power_supply_->RefreshImmediately())
    LOG(ERROR) << "Initial power supply refresh failed; brace for weirdness";
  const system::PowerStatus power_status = power_supply_->GetPowerStatus();

  metrics_collector_->Init(prefs_.get(), display_backlight_controller_.get(),
                           keyboard_backlight_controller_.get(), power_status,
                           first_run_after_boot_);

  // Only create the Adaptive Charging Controller for battery powered systems.
  std::string psu_type;
  prefs_->GetExternalString(kHardwareProperties, kPSUType, &psu_type);
  if (psu_type == kBattery) {
    adaptive_charging_controller_ = delegate_->CreateAdaptiveChargingController(
        this, display_backlight_controller_.get(), input_watcher_.get(),
        power_supply_.get(), dbus_wrapper_.get(), platform_features_,
        prefs_.get());
  }

  dark_resume_ = delegate_->CreateDarkResume(prefs_.get(),
                                             wakeup_source_identifier_.get());

  shutdown_from_suspend_->Init(prefs_.get(), power_supply_.get(),
                               suspend_configurator_.get());

  suspender_->Init(this, dbus_wrapper_.get(), dark_resume_.get(),
                   display_watcher_.get(), wakeup_source_identifier_.get(),
                   shutdown_from_suspend_.get(),
                   adaptive_charging_controller_.get(), prefs_.get(),
                   suspend_configurator_.get());

  input_event_handler_->Init(input_watcher_.get(), this, display_watcher_.get(),
                             dbus_wrapper_.get(), prefs_.get());

  acpi_wakeup_helper_ = delegate_->CreateAcpiWakeupHelper();
  ec_helper_ = delegate_->CreateCrosEcHelper();
  input_device_controller_->Init(display_backlight_controller_.get(),
                                 udev_.get(), acpi_wakeup_helper_.get(),
                                 ec_helper_.get(), lid_state, tablet_mode,
                                 DisplayMode::NORMAL, prefs_.get());

  battery_saver_controller_.Init(*dbus_wrapper_);
  battery_saver_controller_.AddObserver(this);

  const PowerSource power_source =
      power_status.line_power_on ? PowerSource::AC : PowerSource::BATTERY;
  state_controller_->Init(state_controller_delegate_.get(), prefs_.get(),
                          dbus_wrapper_.get(), power_source, lid_state);

  if (BoolPrefIsTrue(kUseCrasPref)) {
    audio_client_ = delegate_->CreateAudioClient(dbus_wrapper_.get(), run_dir_);
    audio_client_->AddObserver(this);
  }

  bluetooth_controller_->Init(udev_.get(), platform_features_,
                              dbus_wrapper_.get());
  wifi_controller_->Init(this, prefs_.get(), udev_.get(), tablet_mode);
  cellular_controller_->Init(this, prefs_.get(), dbus_wrapper_.get());
  peripheral_battery_watcher_ = delegate_->CreatePeripheralBatteryWatcher(
      dbus_wrapper_.get(), udev_.get());
  power_override_lockfile_checker_ = delegate_->CreateLockfileChecker(
      base::FilePath(kPowerOverrideLockfileDir), {});

  user_proximity_watcher_ = delegate_->CreateUserProximityWatcher(
      prefs_.get(), udev_.get(), tablet_mode);
  user_proximity_handler_ = std::make_unique<policy::UserProximityHandler>();
  user_proximity_handler_->Init(user_proximity_watcher_.get(),
                                wifi_controller_.get(),
                                cellular_controller_.get(), prefs_.get());

  arc_timer_manager_->Init(dbus_wrapper_.get());

  if (BoolPrefIsTrue(kHasChargeControllerPref)) {
    charge_controller_helper_ = delegate_->CreateChargeControllerHelper();
    charge_controller_ = std::make_unique<policy::ChargeController>(),
    charge_controller_->Init(charge_controller_helper_.get(),
                             battery_percentage_converter_.get());
  }

  // Asynchronously undo the previous force-lid-open request to the EC (if there
  // was one).
  if (!factory_mode_ && BoolPrefIsTrue(kUseLidPref))
    RunSetuidHelper("set_force_lid_open", "--noforce_lid_open", false);

  thermal_devices_ = delegate_->CreateThermalDevices();
  std::vector<system::ThermalDeviceInterface*> weak_thermal_device;
  for (const auto& thermal_device : thermal_devices_) {
    weak_thermal_device.push_back(thermal_device.get());
  }
  thermal_event_handler_ = std::make_unique<policy::ThermalEventHandler>(
      weak_thermal_device, dbus_wrapper_.get());
  thermal_event_handler_->Init();

  // This needs to happen *after* all D-Bus methods are exported:
  // https://crbug.com/331431
  CHECK(dbus_wrapper_->PublishService()) << "Failed to publish D-Bus service";

  // configure wake on dp only if the preference is set.
  bool wake_on_dp = false;
  if (prefs_->GetBool(kWakeOnDpPref, &wake_on_dp))
    system::ConfigureWakeOnDp(wake_on_dp);

  // Configure wake for the EC.
  if (acpi_wakeup_helper_->IsSupported()) {
    acpi_wakeup_helper_->SetWakeupEnabled("CREC", true);
  }

  // Configure Smart Discharge in EC.
  int64_t to_zero_hr = -1, cutoff_ua = -1, hibernate_ua = -1;
  prefs_->GetInt64(kSmartDischargeToZeroHrPref, &to_zero_hr);
  prefs_->GetInt64(kCutoffPowerUaPref, &cutoff_ua);
  prefs_->GetInt64(kHibernatePowerUaPref, &hibernate_ua);
  system::ConfigureSmartDischarge(to_zero_hr, cutoff_ua, hibernate_ua);

  // Enable EC to send WLC event.
  // Kernel will create udev events on WLC status change.
  system::EnableCrosEcDeviceEvent(EC_DEVICE_EVENT_WLC, true);

  // Call this last to ensure that all of our members are already initialized.
  OnPowerStatusUpdate();
}

bool Daemon::TriggerRetryShutdownTimerForTesting() {
  if (!retry_shutdown_for_lockfile_timer_.IsRunning())
    return false;

  retry_shutdown_for_lockfile_timer_.user_task().Run();
  return true;
}

#if USE_IIOSERVICE
void Daemon::ConnectToMojoServiceManager() {
  TRACE_EVENT("power", "Daemon::ConnectToMojoServiceManager");
  DCHECK(!service_manager_.is_bound());

  auto service_manager_remote =
      chromeos::mojo_service_manager::ConnectToMojoServiceManager();

  if (!service_manager_remote) {
    LOG(ERROR) << "Failed to connect to Mojo Service Manager. Retry in: "
               << kReconnectServiceManagerDelay;
    ReconnectToMojoServiceManagerWithDelay();
    return;
  }

  service_manager_.Bind(std::move(service_manager_remote));
  service_manager_.set_disconnect_with_reason_handler(base::BindOnce(
      &Daemon::OnServiceManagerDisconnect, base::Unretained(this)));

  RequestIioSensor();
}

void Daemon::ReconnectToMojoServiceManagerWithDelay() {
  TRACE_EVENT("power", "Daemon::ReconnectToMojoServiceManagerWithDelay");
  base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Daemon::ConnectToMojoServiceManager,
                     base::Unretained(this)),
      kReconnectServiceManagerDelay);
}

void Daemon::RequestIioSensor() {
  TRACE_EVENT("power", "Daemon::RequestIioSensor");
  if (!service_manager_.is_bound())
    return;

  mojo::PendingRemote<cros::mojom::SensorService> sensor_service_remote;

  service_manager_->Request(
      chromeos::mojo_services::kIioSensor, std::nullopt,
      sensor_service_remote.InitWithNewPipeAndPassReceiver().PassPipe());
  // There might be race conditions when reconnecting iioservice and Mojo
  // Service Manager, and this function might be called more than once. But it's
  // fine as SensorServiceHandler::SetUpChannel will ignore the duplicated mojo
  // pipes.
  sensor_service_handler_->SetUpChannel(
      std::move(sensor_service_remote),
      base::BindOnce(&Daemon::OnIioSensorDisconnect, base::Unretained(this)));
}

void Daemon::OnServiceManagerDisconnect(uint32_t custom_reason,
                                        const std::string& message) {
  auto error = static_cast<chromeos::mojo_service_manager::mojom::ErrorCode>(
      custom_reason);
  LOG(ERROR) << "ServiceManagerDisconnected, error: " << error
             << ", message: " << message;
  service_manager_.reset();
  sensor_service_handler_->ResetSensorService(false);

  ReconnectToMojoServiceManagerWithDelay();
}

void Daemon::OnIioSensorDisconnect(base::TimeDelta delay) {
  TRACE_EVENT("power", "Daemon::OnIioSensorDisconnect");
  DCHECK(service_manager_.is_bound());

  base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Daemon::RequestIioSensor, base::Unretained(this)), delay);
}
#endif  // USE_IIOSERVICE

bool Daemon::BoolPrefIsTrue(const std::string& name) const {
  bool value = false;
  return prefs_->GetBool(name, &value) && value;
}

bool Daemon::SuspendAndShutdownAreBlocked(std::string* details_out) {
  const std::vector<base::FilePath> paths =
      power_override_lockfile_checker_->GetValidLockfiles();
  *details_out = util::JoinPaths(paths, ", ");
  return !paths.empty();
}

int Daemon::RunSetuidHelper(const std::string& action,
                            const std::string& additional_args,
                            bool wait_for_completion) {
  std::string command = kSetuidHelperPath + std::string(" --action=" + action);
  if (!additional_args.empty())
    command += " " + additional_args;
  if (wait_for_completion) {
    return delegate_->Run(command.c_str());
  } else {
    delegate_->Launch(command.c_str());
    return 0;
  }
}

void Daemon::HandleLidClosed() {
  LOG(INFO) << "Lid closed";
  // It is important that we notify InputDeviceController first so that it can
  // inhibit input devices quickly. StateController will issue a blocking call
  // to Chrome which can take longer than a second.
  input_device_controller_->SetLidState(LidState::CLOSED);
  state_controller_->HandleLidStateChange(LidState::CLOSED);
  for (auto controller : all_backlight_controllers_)
    controller->HandleLidStateChange(LidState::CLOSED);

  dbus_wrapper_->EmitBareSignal(kLidClosedSignal);
}

void Daemon::HandleLidOpened() {
  LOG(INFO) << "Lid opened";
  suspender_->HandleLidOpened();
  state_controller_->HandleLidStateChange(LidState::OPEN);
  input_device_controller_->SetLidState(LidState::OPEN);
  for (auto controller : all_backlight_controllers_)
    controller->HandleLidStateChange(LidState::OPEN);

  dbus_wrapper_->EmitBareSignal(kLidOpenedSignal);
}

void Daemon::HandlePowerButtonEvent(ButtonState state) {
  // Don't log spammy repeat events if we see them.
  if (state != ButtonState::REPEAT)
    LOG(INFO) << "Power button " << ButtonStateToString(state);
  metrics_collector_->HandlePowerButtonEvent(state);
  if (state == ButtonState::DOWN) {
    delegate_->Launch("sync");
    for (auto controller : all_backlight_controllers_)
      controller->HandlePowerButtonPress();
  }
}

void Daemon::HandleHoverStateChange(bool hovering) {
  if (hovering)
    hovering_logger_->OnActivityStarted();
  else
    hovering_logger_->OnActivityStopped();

  for (auto controller : all_backlight_controllers_)
    controller->HandleHoverStateChange(hovering);
}

void Daemon::HandleTabletModeChange(TabletMode mode) {
  DCHECK_NE(mode, TabletMode::UNSUPPORTED);
  LOG(INFO) << "Tablet mode " << TabletModeToString(mode);
  state_controller_->HandleTabletModeChange(mode);
  input_device_controller_->SetTabletMode(mode);
  for (auto controller : all_backlight_controllers_)
    controller->HandleTabletModeChange(mode);
  user_proximity_watcher_->HandleTabletModeChange(mode);
  wifi_controller_->HandleTabletModeChange(mode);
  cellular_controller_->HandleTabletModeChange(mode);
}

void Daemon::ShutDownForPowerButtonWithNoDisplay() {
  LOG(INFO) << "Shutting down due to power button press while no display is "
            << "connected";
  metrics_collector_->HandlePowerButtonEvent(ButtonState::DOWN);
  ShutDown(ShutdownMode::POWER_OFF, ShutdownReason::USER_REQUEST);
}

void Daemon::HandleMissingPowerButtonAcknowledgment() {
  LOG(INFO) << "Didn't receive power button acknowledgment from Chrome";
}

void Daemon::ReportPowerButtonAcknowledgmentDelay(base::TimeDelta delay) {
  metrics_collector_->SendPowerButtonAcknowledgmentDelayMetric(delay);
}

int Daemon::GetInitialSuspendId() {
  // Take powerd's PID modulo 2**15 (/proc/sys/kernel/pid_max is currently
  // 2**15, but just in case...) and multiply it by 2**16, leaving it able to
  // fit in a signed 32-bit int. This allows for 2**16 suspend attempts and
  // suspend delays per powerd run before wrapping or intruding on another
  // run's ID range (neither of which should be particularly problematic, but
  // doing this reduces the chances of a confused client that's using stale
  // IDs from a previous powerd run being able to conflict with the new run's
  // IDs).
  return (delegate_->GetPid() % 32768) * 65536 + 1;
}

int Daemon::GetInitialDarkSuspendId() {
  // We use the upper half of the suspend ID space for dark suspend attempts.
  // Assuming that we will go through dark suspend IDs faster than the regular
  // suspend IDs, we should never have a collision between the suspend ID and
  // the dark suspend ID until the dark suspend IDs wrap around.
  return GetInitialSuspendId() + 32768;
}

bool Daemon::IsLidClosedForSuspend() {
  return input_watcher_->QueryLidState() == LidState::CLOSED;
}

bool Daemon::ReadSuspendWakeupCount(uint64_t* wakeup_count) {
  DCHECK(wakeup_count);
  LOG(INFO) << "Reading wakeup count from " << wakeup_count_path_.value();
  if (!util::ReadUint64File(wakeup_count_path_, wakeup_count)) {
    return false;
  }
  LOG(INFO) << "Read wakeup count " << *wakeup_count;
  return true;
}

void Daemon::SetSuspendAnnounced(bool announced) {
  if (announced) {
    if (base::WriteFile(suspend_announced_path_, nullptr, 0) < 0)
      PLOG(ERROR) << "Couldn't create " << suspend_announced_path_.value();
  } else {
    if (!base::DeleteFile(suspend_announced_path_))
      PLOG(ERROR) << "Couldn't delete " << suspend_announced_path_.value();
  }
}

bool Daemon::GetSuspendAnnounced() {
  return base::PathExists(suspend_announced_path_);
}

void Daemon::PrepareToSuspend() {
  // Before announcing the suspend request, notify the backlight controller so
  // it can turn the backlight off and tell the kernel to resume the current
  // level after resuming.  This must occur before Chrome is told that the
  // system is going to suspend (Chrome turns the display back on while leaving
  // the backlight off).
  SetBacklightsSuspended(true);

  power_supply_->SetSuspended(true);
  metrics_collector_->PrepareForSuspend();
}

void Daemon::SuspendAudio() {
  if (audio_client_)
    audio_client_->SetSuspended(true);
}

void Daemon::ResumeAudio() {
  if (audio_client_)
    audio_client_->SetSuspended(false);
}

policy::Suspender::Delegate::SuspendResult Daemon::DoSuspend(
    uint64_t wakeup_count,
    bool wakeup_count_valid,
    base::TimeDelta duration,
    bool to_hibernate) {
  // If power management is overridden by a lockfile, spin for a bit to wait for
  // the process to finish: http://crosbug.com/p/38947
  base::TimeDelta elapsed;
  std::string details;
  while (SuspendAndShutdownAreBlocked(&details)) {
    if (elapsed >= kSuspendLockfileTimeout) {
      LOG(INFO) << "Aborting suspend attempt for lockfile(s): " << details;
      return policy::Suspender::Delegate::SuspendResult::FAILURE;
    }
    elapsed += kSuspendLockfilePollInterval;
    base::PlatformThread::Sleep(kSuspendLockfilePollInterval);
  }

  // Touch a file that crash-reporter can inspect later to determine
  // whether the system was suspended or hibernated while an unclean
  // shutdown occurred. If the file already exists, assume that
  // crash-reporter hasn't seen it yet and avoid unlinking it after
  // resume.
  base::FilePath suspended_state_path = suspended_state_path_;
  if (to_hibernate)
    suspended_state_path = hibernated_state_path_;

  created_suspended_state_file_ = false;
  if (!base::PathExists(suspended_state_path)) {
    if (base::WriteFile(suspended_state_path, nullptr, 0) == 0)
      created_suspended_state_file_ = true;
    else
      PLOG(ERROR) << "Unable to create " << suspended_state_path.value();
  }

  // This command is run synchronously to ensure that it finishes before the
  // system is suspended.
  // TODO(b/192353448): Create a eventlog code for hibernate.
  if (log_suspend_manually_) {
    RunSetuidHelper("eventlog_add", "--eventlog_code=0xa7", true);
  }

  std::vector<std::string> args;
  if (wakeup_count_valid) {
    args.push_back("--suspend_wakeup_count_valid");
    args.push_back(
        base::StringPrintf("--suspend_wakeup_count=%" PRIu64, wakeup_count));
  }

  if (to_hibernate) {
    args.push_back("--suspend_to_disk");

  } else if (suspend_to_idle_) {
    args.push_back("--suspend_to_idle");
  }

  suspend_configurator_->PrepareForSuspend(duration);

  // Sync filesystems since outstanding operations can significantly delay
  // freeze, causing it to time out.
  sync();

  system::FreezeResult freeze_result =
      suspend_freezer_->FreezeUserspace(wakeup_count, wakeup_count_valid);
  if (freeze_result == system::FreezeResult::FAILURE) {
    // The kernel may succeed in freezing the rest of userspace, but even if it
    // doesn't, it will provide better logging, detailed stack traces, for our
    // crash reports.
    LOG(ERROR) << "Failed to freeze userspace processes. Attempting suspend "
               << "anyways";
  } else if (freeze_result == system::FreezeResult::CANCELED) {
    if (!suspend_freezer_->ThawUserspace())
      LOG(ERROR) << "Failed to thaw userspace after canceled suspend";

    return policy::Suspender::Delegate::SuspendResult::CANCELED;
  }

  const int exit_code =
      RunSetuidHelper("suspend", base::JoinString(args, " "), true);
  LOG(INFO) << "powerd_suspend returned " << exit_code;

  // TODO(b/192353448): Create a eventlog code for hibernate.
  if (log_suspend_manually_)
    RunSetuidHelper("eventlog_add", "--eventlog_code=0xa8", false);

  if (created_suspended_state_file_) {
    if (!base::DeleteFile(base::FilePath(suspended_state_path)))
      PLOG(ERROR) << "Failed to delete " << suspended_state_path.value();
  }

  bool thaw_userspace_succ = suspend_freezer_->ThawUserspace();
  bool undo_prep_suspend_succ = suspend_configurator_->UndoPrepareForSuspend();
  if (!(thaw_userspace_succ && undo_prep_suspend_succ))
    return policy::Suspender::Delegate::SuspendResult::FAILURE;

  // These exit codes are defined in powerd/powerd_suspend.
  switch (exit_code) {
    case 0:
      return policy::Suspender::Delegate::SuspendResult::SUCCESS;
    case 1:
      return policy::Suspender::Delegate::SuspendResult::FAILURE;
    case 2:  // Wakeup event received before write to wakeup_count.
    case 3:  // Wakeup event received after write to wakeup_count.
      return policy::Suspender::Delegate::SuspendResult::CANCELED;
    default:
      LOG(ERROR) << "Treating unexpected exit code " << exit_code
                 << " as suspend failure";
      return policy::Suspender::Delegate::SuspendResult::FAILURE;
  }
}

void Daemon::UndoPrepareToSuspend(bool success,
                                  int num_suspend_attempts,
                                  bool hibernated) {
  LidState lid_state = input_watcher_->QueryLidState();

  // Update the lid state first so that resume does not turn the internal
  // backlight on if the lid is still closed on resume.
  for (auto controller : all_backlight_controllers_)
    controller->HandleLidStateChange(lid_state);

  // Let State controller know about resume with the latest lid state.
  state_controller_->HandleResume(lid_state);

  // Resume the backlight right after announcing resume. This might be where we
  // turn on the display, so we want to do this as early as possible. This
  // happens when we idle suspend (and the requested power state in Chrome is
  // off for the displays).
  SetBacklightsSuspended(false);

  power_supply_->SetSuspended(false);

  if (success)
    metrics_collector_->HandleResume(num_suspend_attempts, hibernated);
  else if (num_suspend_attempts > 0)
    metrics_collector_->HandleCanceledSuspendRequest(num_suspend_attempts,
                                                     hibernated);
}

void Daemon::ApplyQuirksBeforeSuspend() {
  bluetooth_controller_->ApplyAutosuspendQuirk();
}

void Daemon::UnapplyQuirksAfterSuspend() {
  bluetooth_controller_->UnapplyAutosuspendQuirk();
}

void Daemon::GenerateDarkResumeMetrics(
    const std::vector<policy::Suspender::DarkResumeInfo>&
        dark_resume_wake_durations,
    base::TimeDelta suspend_duration) {
  metrics_collector_->GenerateDarkResumeMetrics(dark_resume_wake_durations,
                                                suspend_duration);
}

void Daemon::ShutDownForFailedSuspend(bool hibernate) {
  ShutDown(ShutdownMode::POWER_OFF, hibernate ? ShutdownReason::HIBERNATE_FAILED
                                              : ShutdownReason::SUSPEND_FAILED);
}

void Daemon::ShutDownFromSuspend() {
  ShutDown(ShutdownMode::POWER_OFF, ShutdownReason::SHUTDOWN_FROM_SUSPEND);
}

void Daemon::SetWifiTransmitPower(RadioTransmitPower power,
                                  WifiRegDomain domain,
                                  TriggerSource source) {
  const std::string power_arg = (power == RadioTransmitPower::LOW)
                                    ? "--wifi_transmit_power_tablet"
                                    : "--nowifi_transmit_power_tablet";
  std::string domain_arg = "--wifi_transmit_power_domain=none";
  switch (domain) {
    case WifiRegDomain::FCC:
      domain_arg = "--wifi_transmit_power_domain=fcc";
      break;
    case WifiRegDomain::EU:
      domain_arg = "--wifi_transmit_power_domain=eu";
      break;
    case WifiRegDomain::REST_OF_WORLD:
      domain_arg = "--wifi_transmit_power_domain=rest-of-world";
      break;
    default:
      break;
  }

  std::string source_arg = "--wifi_transmit_power_source=unknown";
  switch (source) {
    case TriggerSource::INIT:
      source_arg = "--wifi_transmit_power_source=init";
      break;
    case TriggerSource::TABLET_MODE:
      source_arg = "--wifi_transmit_power_source=tablet_mode";
      break;
    case TriggerSource::REG_DOMAIN:
      source_arg = "--wifi_transmit_power_source=reg_domain";
      break;
    case TriggerSource::UDEV_EVENT:
      source_arg = "--wifi_transmit_power_source=udev_event";
      break;
    case TriggerSource::PROXIMITY:
      source_arg = "--wifi_transmit_power_source=proximity";
      break;
    default:
      break;
  }

  const std::string args = base::StringPrintf(
      "%s %s %s", power_arg.c_str(), domain_arg.c_str(), source_arg.c_str());
  LOG(INFO) << ((power == RadioTransmitPower::LOW) ? "Enabling" : "Disabling")
            << " tablet mode wifi transmit power";
  RunSetuidHelper("set_wifi_transmit_power", args, false);
}

void Daemon::SetCellularTransmitPower(RadioTransmitPower power,
                                      int64_t dpr_gpio_number) {
  const bool is_power_low = (power == RadioTransmitPower::LOW);
  const std::string args = base::StringPrintf(
      "--cellular_transmit_power_low=%s "
      "--cellular_transmit_power_gpio=%" PRId64,
      is_power_low ? "true" : "false", dpr_gpio_number);
  LOG(INFO) << "Setting cellular transmit power "
            << (is_power_low ? "low" : "high");
  RunSetuidHelper("set_cellular_transmit_power", args, false);
}

bool Daemon::RunEcCommand(ec::EcCommandInterface& cmd) {
  base::ScopedFD ec_fd =
      base::ScopedFD(open(cros_ec_path_.value().c_str(), O_RDWR));

  if (!ec_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << cros_ec_path_;
    return false;
  }

  if (!cmd.Run(ec_fd.get())) {
    return false;
  }

  return true;
}

bool Daemon::SetBatterySustain(int lower, int upper) {
  auto cmd = ec_command_factory_->ChargeControlSetCommand(CHARGE_CONTROL_NORMAL,
                                                          lower, upper);

  bool success = RunEcCommand(*cmd);
  if (!success) {
    // This is expected if the EC doesn't support battery sustainer.
    LOG(INFO) << "Setting battery sustain with lower = " << lower
              << "% and upper = " << upper << "%  failed";
  }

  return success;
}

bool Daemon::SetBatteryChargeLimit(uint32_t limit_mA) {
  auto cmd = ec_command_factory_->ChargeCurrentLimitSetCommand(limit_mA);

  bool success = RunEcCommand(*cmd);
  if (!success) {
    // This is expected if the EC doesn't support setting a charge current
    // limit.
    LOG(INFO) << "Setting charge limit = " << limit_mA << "mA failed";
  }

  return success;
}

void Daemon::GetAdaptiveChargingPrediction(
    const assist_ranker::RankerExample& proto, bool async) {
  brillo::ErrorPtr error;
  std::vector<uint8_t> serialized(proto.ByteSizeLong());

  if (!proto.SerializeToArray(serialized.data(), serialized.size())) {
    error = brillo::Error::Create(FROM_HERE, kErrorDomain, kInternalError,
                                  "Failed to serialize RankerExample");
    adaptive_charging_controller_->OnPredictionFail(error.get());
    return;
  }

  if (async) {
    adaptive_charging_ml_proxy_->RequestAdaptiveChargingDecisionAsync(
        serialized,
        base::BindRepeating(
            &policy::AdaptiveChargingControllerInterface::OnPredictionResponse,
            base::Unretained(adaptive_charging_controller_.get())),
        base::BindRepeating(
            &policy::AdaptiveChargingControllerInterface::OnPredictionFail,
            base::Unretained(adaptive_charging_controller_.get())));
    return;
  }

  bool inference_done;
  std::vector<double> result;
  if (!adaptive_charging_ml_proxy_->RequestAdaptiveChargingDecision(
          serialized, &inference_done, &result, &error,
          kAdaptiveChargingSyncDBusTimeoutMs)) {
    adaptive_charging_controller_->OnPredictionFail(error.get());
    return;
  }

  if (!inference_done) {
    error = brillo::Error::Create(
        FROM_HERE, brillo::errors::dbus::kDomain, DBUS_ERROR_FAILED,
        "Adaptive Charging ML Proxy failed to finish inference");

    adaptive_charging_controller_->OnPredictionFail(error.get());
    return;
  }

  adaptive_charging_controller_->OnPredictionResponse(inference_done, result);
}

void Daemon::GenerateAdaptiveChargingUnplugMetrics(
    const metrics::AdaptiveChargingState state,
    const base::TimeTicks& target_time,
    const base::TimeTicks& hold_start_time,
    const base::TimeTicks& hold_end_time,
    const base::TimeTicks& charge_finished_time,
    const base::TimeDelta& time_spent_slow_charging,
    double display_battery_percentage) {
  metrics_collector_->GenerateAdaptiveChargingUnplugMetrics(
      state, target_time, hold_start_time, hold_end_time, charge_finished_time,
      time_spent_slow_charging, display_battery_percentage);
}

void Daemon::OnAudioStateChange(bool active) {
  if (active)
    audio_activity_logger_->OnActivityStarted();
  else
    audio_activity_logger_->OnActivityStopped();
  state_controller_->HandleAudioStateChange(active);
}

void Daemon::OnDBusNameOwnerChanged(const std::string& name,
                                    const std::string& old_owner,
                                    const std::string& new_owner) {
  if (name == login_manager::kSessionManagerServiceName && !new_owner.empty()) {
    LOG(INFO) << "D-Bus " << name << " ownership changed to " << new_owner;
    HandleSessionManagerAvailableOrRestarted(true);
  } else if (name == chromeos::kDisplayServiceName && !new_owner.empty()) {
    LOG(INFO) << "D-Bus " << name << " ownership changed to " << new_owner;
    HandleDisplayServiceAvailableOrRestarted(true);
  } else if (name == privacy_screen::kPrivacyScreenServiceName &&
             !new_owner.empty()) {
    LOG(INFO) << "D-Bus " << name << " ownership changed to " << new_owner;
    HandlePrivacyScreenServiceAvailableOrRestarted(true);
  }
  suspender_->HandleDBusNameOwnerChanged(name, old_owner, new_owner);
}

void Daemon::OnPowerStatusUpdate() {
  TRACE_EVENT("power", "OnPowerStatusUpdate");
  const system::PowerStatus status = power_supply_->GetPowerStatus();
  if (status.battery_is_present)
    LOG(INFO) << system::GetPowerStatusBatteryDebugString(status);

  metrics_collector_->HandlePowerStatusUpdate(status);

  const PowerSource power_source =
      status.line_power_on ? PowerSource::AC : PowerSource::BATTERY;
  for (auto controller : all_backlight_controllers_)
    controller->HandlePowerSourceChange(power_source);
  state_controller_->HandlePowerSourceChange(power_source);
  thermal_event_handler_->HandlePowerSourceChange(power_source);

  if (status.battery_below_shutdown_threshold) {
    LOG(INFO) << "Shutting down due to low battery ("
              << base::StringPrintf("%0.2f", status.battery_percentage) << "%, "
              << util::TimeDeltaToString(status.battery_time_to_empty)
              << " until empty, "
              << base::StringPrintf("%0.3f",
                                    status.observed_battery_charge_rate)
              << "A observed charge rate)";
    ShutDown(ShutdownMode::POWER_OFF, ShutdownReason::LOW_BATTERY);
  }
}

void Daemon::OnBatterySaverStateChanged(const BatterySaverModeState& state) {
  TRACE_EVENT("power", "OnBatterySaverStateChanged");

  // TODO(sxm): Collect metrics somewhere around here.

  for (auto controller : all_backlight_controllers_)
    controller->HandleBatterySaverModeChange(state);
}

void Daemon::InitDBus() {
  dbus_wrapper_ = delegate_->CreateDBusWrapper();
  dbus_wrapper_->AddObserver(this);

  dbus::ObjectProxy* display_service_proxy = dbus_wrapper_->GetObjectProxy(
      chromeos::kDisplayServiceName, chromeos::kDisplayServicePath);
  dbus_wrapper_->RegisterForServiceAvailability(
      display_service_proxy,
      base::BindRepeating(&Daemon::HandleDisplayServiceAvailableOrRestarted,
                          weak_ptr_factory_.GetWeakPtr()));

  session_manager_dbus_proxy_ =
      dbus_wrapper_->GetObjectProxy(login_manager::kSessionManagerServiceName,
                                    login_manager::kSessionManagerServicePath);
  resource_manager_dbus_proxy_ = dbus_wrapper_->GetObjectProxy(
      resource_manager::kResourceManagerServiceName,
      resource_manager::kResourceManagerServicePath);
  dbus_wrapper_->RegisterForServiceAvailability(
      session_manager_dbus_proxy_,
      base::BindRepeating(&Daemon::HandleSessionManagerAvailableOrRestarted,
                          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper_->RegisterForSignal(
      session_manager_dbus_proxy_, login_manager::kSessionManagerInterface,
      login_manager::kSessionStateChangedSignal,
      base::BindRepeating(&Daemon::HandleSessionStateChangedSignal,
                          weak_ptr_factory_.GetWeakPtr()));

  privacy_screen_service_dbus_proxy_ =
      dbus_wrapper_->GetObjectProxy(privacy_screen::kPrivacyScreenServiceName,
                                    privacy_screen::kPrivacyScreenServicePath);
  dbus_wrapper_->RegisterForServiceAvailability(
      privacy_screen_service_dbus_proxy_,
      base::BindRepeating(
          &Daemon::HandlePrivacyScreenServiceAvailableOrRestarted,
          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper_->RegisterForSignal(
      privacy_screen_service_dbus_proxy_,
      privacy_screen::kPrivacyScreenServiceInterface,
      privacy_screen::kPrivacyScreenServicePrivacyScreenSettingChangedSignal,
      base::BindRepeating(&Daemon::HandlePrivacyScreenSettingChangedSignal,
                          weak_ptr_factory_.GetWeakPtr()));

  // Export Daemon's D-Bus method calls.
  typedef std::unique_ptr<dbus::Response> (Daemon::*DaemonMethod)(
      dbus::MethodCall*);
  const std::map<const char*, DaemonMethod> kDaemonMethods = {
      {kRequestShutdownMethod, &Daemon::HandleRequestShutdownMethod},
      {kRequestRestartMethod, &Daemon::HandleRequestRestartMethod},
      {kRequestSuspendMethod, &Daemon::HandleRequestSuspendMethod},
      {kHandleVideoActivityMethod, &Daemon::HandleVideoActivityMethod},
      {kHandleUserActivityMethod, &Daemon::HandleUserActivityMethod},
      {kHandleWakeNotificationMethod, &Daemon::HandleWakeNotificationMethod},
      {kSetIsProjectingMethod, &Daemon::HandleSetIsProjectingMethod},
      {kSetPolicyMethod, &Daemon::HandleSetPolicyMethod},
      {kSetBacklightsForcedOffMethod,
       &Daemon::HandleSetBacklightsForcedOffMethod},
      {kGetBacklightsForcedOffMethod,
       &Daemon::HandleGetBacklightsForcedOffMethod},
      {kChangeWifiRegDomainMethod, &Daemon::HandleChangeWifiRegDomainMethod},
      {kGetTabletModeMethod, &Daemon::HandleGetTabletModeMethod},
  };
  for (const auto& it : kDaemonMethods) {
    dbus_wrapper_->ExportMethod(
        it.first, base::BindRepeating(
                      &HandleSynchronousDBusMethodCall,
                      base::BindRepeating(it.second, base::Unretained(this))));
  }

  const scoped_refptr<dbus::Bus>& bus = dbus_wrapper_->GetBus();

  // We don't need to wait for this DBus proxy to init, since calls to it will
  // block if it's not currently available.
  // Also, create this before returning due to |bus| == NULL, since we mock out
  // the adaptive_charging_ml_proxy_ for testing.
  adaptive_charging_ml_proxy_ = delegate_->CreateAdaptiveChargingProxy(bus);

  // There's no underlying dbus::Bus object when we're being tested.
  if (!bus)
    return;

  int64_t tpm_threshold = 0;
  prefs_->GetInt64(kTpmCounterSuspendThresholdPref, &tpm_threshold);
  if (tpm_threshold > 0) {
    tpm_manager_proxy_ = std::make_unique<org::chromium::TpmManagerProxy>(bus);
    tpm_manager_proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(
        base::BindRepeating(&Daemon::HandleTpmManagerdAvailable,
                            weak_ptr_factory_.GetWeakPtr()));

    int64_t tpm_status_sec = 0;
    prefs_->GetInt64(kTpmStatusIntervalSecPref, &tpm_status_sec);
    tpm_status_interval_ = base::Seconds(tpm_status_sec);
  }
}

void Daemon::HandleDisplayServiceAvailableOrRestarted(bool available) {
  if (!available) {
    LOG(ERROR) << "Failed waiting for DisplayService to become available";
    return;
  }
  for (auto controller : all_backlight_controllers_)
    controller->HandleDisplayServiceStart();

  // When running in the factory, we avoid initializing any backlight
  // controllers, but we need to still tell Chrome to initially turn displays on
  // so it will restore the correct display power state when returning from VT2:
  // http://b/78436034
  if (factory_mode_) {
    DCHECK(all_backlight_controllers_.empty());
    display_power_setter_->SetDisplayPower(chromeos::DISPLAY_POWER_ALL_ON,
                                           base::TimeDelta());
  }
}

void Daemon::HandleSessionManagerAvailableOrRestarted(bool available) {
  if (!available) {
    LOG(ERROR) << "Failed waiting for session manager to become available";
    return;
  }

  dbus::MethodCall method_call(
      login_manager::kSessionManagerInterface,
      login_manager::kSessionManagerRetrieveSessionState);
  std::unique_ptr<dbus::Response> response = dbus_wrapper_->CallMethodSync(
      session_manager_dbus_proxy_, &method_call, kSessionManagerDBusTimeout);
  if (!response)
    return;

  std::string state;
  dbus::MessageReader reader(response.get());
  if (!reader.PopString(&state)) {
    LOG(ERROR) << "Unable to read "
               << login_manager::kSessionManagerRetrieveSessionState << " args";
    return;
  }
  OnSessionStateChange(state);
}

void Daemon::HandlePrivacyScreenServiceAvailableOrRestarted(bool available) {
  if (!available) {
    LOG(ERROR)
        << "Failed waiting for privacy screen service to become available";
    return;
  }
  dbus::MethodCall method_call(
      privacy_screen::kPrivacyScreenServiceInterface,
      privacy_screen::kPrivacyScreenServiceGetPrivacyScreenSettingMethod);
  dbus_wrapper_->CallMethodAsync(
      privacy_screen_service_dbus_proxy_, &method_call,
      kPrivacyScreenServiceDBusTimeoutMs,
      base::BindRepeating(&Daemon::HandleGetPrivacyScreenSettingResponse,
                          weak_ptr_factory_.GetWeakPtr()));
}

void Daemon::HandleTpmManagerdAvailable(bool available) {
  if (!available) {
    LOG(ERROR) << "Failed waiting for tpm_manager to become available";
    return;
  }
  if (!tpm_manager_proxy_)
    return;

  RequestTpmStatus();
  if (tpm_status_interval_ > base::Seconds(0)) {
    tpm_status_timer_.Start(FROM_HERE, tpm_status_interval_, this,
                            &Daemon::RequestTpmStatus);
  }
}

void Daemon::HandleSessionStateChangedSignal(dbus::Signal* signal) {
  dbus::MessageReader reader(signal);
  std::string state;
  if (reader.PopString(&state)) {
    OnSessionStateChange(state);
  } else {
    LOG(ERROR) << "Unable to read " << login_manager::kSessionStateChangedSignal
               << " args";
  }
}

void Daemon::HandlePrivacyScreenSettingChangedSignal(dbus::Signal* signal) {
  dbus::MessageReader reader(signal);
  privacy_screen::PrivacyScreenSetting setting;
  if (reader.PopArrayOfBytesAsProto(&setting)) {
    OnPrivacyScreenStateChange(setting.state());
  } else {
    LOG(ERROR) << "Unable to read "
               << privacy_screen::
                      kPrivacyScreenServicePrivacyScreenSettingChangedSignal
               << " args";
  }
}

void Daemon::HandleGetPrivacyScreenSettingResponse(dbus::Response* response) {
  if (!response) {
    LOG(ERROR)
        << "D-Bus method call to "
        << privacy_screen::kPrivacyScreenServiceGetPrivacyScreenSettingMethod
        << " failed";
    return;
  }
  dbus::MessageReader reader(response);
  privacy_screen::PrivacyScreenSetting setting;
  if (reader.PopArrayOfBytesAsProto(&setting)) {
    OnPrivacyScreenStateChange(setting.state());
  } else {
    LOG(ERROR)
        << "Unable to read "
        << privacy_screen::kPrivacyScreenServiceGetPrivacyScreenSettingMethod
        << " args";
  }
}

void Daemon::HandleGetDictionaryAttackInfoFailed(brillo::Error* err) {
  LOG(ERROR) << "GetDictionaryAttackInfo call failed";
  return;
}

void Daemon::HandleGetDictionaryAttackInfoSuccess(
    const tpm_manager::GetDictionaryAttackInfoReply& reply) {
  if (reply.status() != tpm_manager::STATUS_SUCCESS) {
    LOG(ERROR) << "GetDictionaryAttackInfo response contains error status code "
               << reply.status();
    return;
  }

  const int da_count = reply.dictionary_attack_counter();
  LOG(INFO) << "Received GetDictionaryAttackInfo response with dictionary "
               "attack count "
            << da_count;
  state_controller_->HandleTpmStatus(da_count);
}

std::unique_ptr<dbus::Response> Daemon::HandleRequestShutdownMethod(
    dbus::MethodCall* method_call) {
  // Both arguments are optional.
  dbus::MessageReader reader(method_call);
  int32_t arg = 0;
  ShutdownReason reason = ShutdownReason::OTHER_REQUEST_TO_POWERD;
  if (reader.PopInt32(&arg)) {
    switch (static_cast<RequestShutdownReason>(arg)) {
      case REQUEST_SHUTDOWN_FOR_USER:
        reason = ShutdownReason::USER_REQUEST;
        break;
      case REQUEST_SHUTDOWN_OTHER:
        reason = ShutdownReason::OTHER_REQUEST_TO_POWERD;
        break;
      default:
        LOG(WARNING) << "Got unknown shutdown reason " << arg;
    }
  }

  std::string description;
  reader.PopString(&description);

  LOG(INFO) << "Got " << kRequestShutdownMethod << " message from "
            << method_call->GetSender() << " with reason "
            << ShutdownReasonToString(reason) << " (" << description << ")";

  ShutDown(ShutdownMode::POWER_OFF, reason);
  return nullptr;
}

std::unique_ptr<dbus::Response> Daemon::HandleRequestRestartMethod(
    dbus::MethodCall* method_call) {
  // Both arguments are optional.
  dbus::MessageReader reader(method_call);
  int32_t arg = 0;
  ShutdownReason reason = ShutdownReason::OTHER_REQUEST_TO_POWERD;
  if (reader.PopInt32(&arg)) {
    switch (static_cast<RequestRestartReason>(arg)) {
      case REQUEST_RESTART_FOR_USER:
        reason = ShutdownReason::USER_REQUEST;
        break;
      case REQUEST_RESTART_FOR_UPDATE:
        reason = ShutdownReason::SYSTEM_UPDATE;
        break;
      case REQUEST_RESTART_OTHER:
      case REQUEST_RESTART_SCHEDULED_REBOOT_POLICY:
      case REQUEST_RESTART_REMOTE_ACTION_REBOOT:
      case REQUEST_RESTART_API:
        reason = ShutdownReason::OTHER_REQUEST_TO_POWERD;
        break;
      default:
        LOG(WARNING) << "Got unknown restart reason " << arg;
    }
  }

  std::string description;
  reader.PopString(&description);

  LOG(INFO) << "Got " << kRequestRestartMethod << " message from "
            << method_call->GetSender() << " with reason "
            << ShutdownReasonToString(reason) << " (" << description << ")";

  ShutDown(ShutdownMode::REBOOT, reason);
  return nullptr;
}

std::unique_ptr<dbus::Response> Daemon::HandleRequestSuspendMethod(
    dbus::MethodCall* method_call) {
  // Read an optional uint64_t argument specifying the wakeup count that is
  // expected.
  dbus::MessageReader reader(method_call);
  uint64_t external_wakeup_count = -1ULL;
  bool got_external_wakeup_count = reader.PopUint64(&external_wakeup_count);
  // Use -1 as a "no external wakeup count" value. Optional parameters like
  // this are discouraged in new designs because to add additional parameters,
  // all optional parameters before it must be supplied. Null values like
  // -1 are then needed as a way to say "I'm giving you this parameter, but
  // pretend like I'm not."
  if (external_wakeup_count == -1ULL)
    got_external_wakeup_count = false;
  LOG(INFO) << "Got " << kRequestSuspendMethod << " message"
            << (got_external_wakeup_count
                    ? base::StringPrintf(" with external wakeup count %" PRIu64,
                                         external_wakeup_count)
                          .c_str()
                    : "")
            << " from " << method_call->GetSender();
  // Read an optional int32_t argument specifying the wakeup timeout for a
  // suspend request.
  int32_t wakeup_timeout = 0;
  reader.PopInt32(&wakeup_timeout);
  base::TimeDelta duration = base::Seconds(wakeup_timeout);
  // Read an optional uint32_t argument specifying the suspend flavor.
  uint32_t suspend_flavor =
      static_cast<uint32_t>(SuspendFlavor::SUSPEND_DEFAULT);
  reader.PopUint32(&suspend_flavor);
  Suspend(SuspendImminent_Reason_OTHER, got_external_wakeup_count,
          external_wakeup_count, duration,
          static_cast<SuspendFlavor>(suspend_flavor));
  return nullptr;
}

void Daemon::SetFullscreenVideoWithTimeout(bool active, int timeout_seconds) {
  dbus::MethodCall method_call(
      resource_manager::kResourceManagerInterface,
      resource_manager::kSetFullscreenVideoWithTimeout);
  dbus::MessageWriter writer(&method_call);
  writer.AppendByte(static_cast<char>(active));
  writer.AppendUint32(timeout_seconds);

  dbus_wrapper_->CallMethodSync(resource_manager_dbus_proxy_, &method_call,
                                kResourceManagerDBusTimeout);
}

std::unique_ptr<dbus::Response> Daemon::HandleVideoActivityMethod(
    dbus::MethodCall* method_call) {
  bool fullscreen = false;
  dbus::MessageReader reader(method_call);
  if (!reader.PopBool(&fullscreen))
    LOG(ERROR) << "Unable to read " << kHandleVideoActivityMethod << " args";

  video_activity_logger_->OnActivityReported();

  for (auto controller : all_backlight_controllers_)
    controller->HandleVideoActivity(fullscreen);
  state_controller_->HandleVideoActivity();

  if (fullscreen)
    SetFullscreenVideoWithTimeout(true /* active */,
                                  10 /* timeout in seconds */);
  return nullptr;
}

std::unique_ptr<dbus::Response> Daemon::HandleUserActivityMethod(
    dbus::MethodCall* method_call) {
  user_activity_logger_->OnActivityReported();

  int type_int = USER_ACTIVITY_OTHER;
  dbus::MessageReader reader(method_call);
  if (!reader.PopInt32(&type_int))
    LOG(ERROR) << "Unable to read " << kHandleUserActivityMethod << " args";
  UserActivityType type = static_cast<UserActivityType>(type_int);

  suspender_->HandleUserActivity();
  state_controller_->HandleUserActivity();
  for (auto controller : all_backlight_controllers_)
    controller->HandleUserActivity(type);
  return nullptr;
}

std::unique_ptr<dbus::Response> Daemon::HandleWakeNotificationMethod(
    dbus::MethodCall* method_call) {
  suspender_->HandleWakeNotification();
  state_controller_->HandleWakeNotification();
  for (auto controller : all_backlight_controllers_)
    controller->HandleWakeNotification();
  return nullptr;
}

std::unique_ptr<dbus::Response> Daemon::HandleSetIsProjectingMethod(
    dbus::MethodCall* method_call) {
  bool is_projecting = false;
  dbus::MessageReader reader(method_call);
  if (!reader.PopBool(&is_projecting)) {
    LOG(ERROR) << "Unable to read " << kSetIsProjectingMethod << " args";
    return CreateInvalidArgsError(method_call, "Expected boolean state");
  }

  DisplayMode mode =
      is_projecting ? DisplayMode::PRESENTATION : DisplayMode::NORMAL;
  LOG(INFO) << "Chrome is using " << DisplayModeToString(mode)
            << " display mode";
  state_controller_->HandleDisplayModeChange(mode);
  suspender_->HandleDisplayModeChange(mode);
  input_device_controller_->SetDisplayMode(mode);
  for (auto controller : all_backlight_controllers_)
    controller->HandleDisplayModeChange(mode);
  return nullptr;
}

std::unique_ptr<dbus::Response> Daemon::HandleSetPolicyMethod(
    dbus::MethodCall* method_call) {
  PowerManagementPolicy policy;
  dbus::MessageReader reader(method_call);
  if (!reader.PopArrayOfBytesAsProto(&policy)) {
    LOG(ERROR) << "Unable to parse " << kSetPolicyMethod << " request";
    return CreateInvalidArgsError(method_call, "Expected protobuf");
  }

  LOG(INFO) << "Received updated external policy: "
            << policy::StateController::GetPolicyDebugString(policy);
  state_controller_->HandlePolicyChange(policy);

  if (charge_controller_) {
    charge_controller_->HandlePolicyChange(policy);
  }

  if (adaptive_charging_controller_) {
    adaptive_charging_controller_->HandlePolicyChange(policy);
  }

  for (auto controller : all_backlight_controllers_)
    controller->HandlePolicyChange(policy);
  return nullptr;
}

std::unique_ptr<dbus::Response> Daemon::HandleSetBacklightsForcedOffMethod(
    dbus::MethodCall* method_call) {
  bool force_off = false;
  if (!dbus::MessageReader(method_call).PopBool(&force_off)) {
    LOG(ERROR) << "Unable to read " << kSetBacklightsForcedOffMethod << " args";
    return CreateInvalidArgsError(method_call, "Expected bool");
  }
  LOG(INFO) << "Received request to " << (force_off ? "start" : "stop")
            << " forcing backlights off";
  for (auto controller : all_backlight_controllers_)
    controller->SetForcedOff(force_off);
  return nullptr;
}

std::unique_ptr<dbus::Response> Daemon::HandleGetBacklightsForcedOffMethod(
    dbus::MethodCall* method_call) {
  std::unique_ptr<dbus::Response> response(
      dbus::Response::FromMethodCall(method_call));

  // We can get the current state from any backlight controller.
  bool forced_off = all_backlight_controllers_.empty()
                        ? false
                        : all_backlight_controllers_.front()->GetForcedOff();
  dbus::MessageWriter(response.get()).AppendBool(forced_off);
  return response;
}

std::unique_ptr<dbus::Response> Daemon::HandleChangeWifiRegDomainMethod(
    dbus::MethodCall* method_call) {
  int32_t arg = 0;
  dbus::MessageReader reader(method_call);
  WifiRegDomain domain = WifiRegDomain::NONE;
  if (!reader.PopInt32(&arg)) {
    LOG(ERROR) << "Unable to read " << kChangeWifiRegDomainMethod << " args";
    return CreateInvalidArgsError(method_call, "Expected Int32");
  }
  switch (static_cast<WifiRegDomainDbus>(arg)) {
    case WIFI_REG_DOMAIN_FCC:
      domain = WifiRegDomain::FCC;
      break;
    case WIFI_REG_DOMAIN_EU:
      domain = WifiRegDomain::EU;
      break;
    case WIFI_REG_DOMAIN_REST_OF_WORLD:
      domain = WifiRegDomain::REST_OF_WORLD;
      break;
    case WIFI_REG_DOMAIN_NONE:
      break;
    default:
      LOG(WARNING) << "Got unknown WiFi regulatory domain " << arg;
  }

  LOG(INFO) << "Received request to change reg domain to \""
            << WifiRegDomainToString(domain) << "\"";
  wifi_controller_->HandleRegDomainChange(domain);
  return nullptr;
}

std::unique_ptr<dbus::Response> Daemon::HandleGetTabletModeMethod(
    dbus::MethodCall* method_call) {
  std::unique_ptr<dbus::Response> response(
      dbus::Response::FromMethodCall(method_call));

  const TabletMode tablet_mode = input_watcher_->GetTabletMode();
  dbus::MessageWriter(response.get()).AppendBool(tablet_mode == TabletMode::ON);
  return response;
}

void Daemon::OnSessionStateChange(const std::string& state_str) {
  SessionState state = (state_str == kSessionStarted) ? SessionState::STARTED
                                                      : SessionState::STOPPED;
  if (state == session_state_)
    return;

  LOG(INFO) << "Session state changed to " << SessionStateToString(state);
  session_state_ = state;
  metrics_collector_->HandleSessionStateChange(state);
  state_controller_->HandleSessionStateChange(state);
  for (auto controller : all_backlight_controllers_)
    controller->HandleSessionStateChange(state);
}

void Daemon::OnPrivacyScreenStateChange(
    const privacy_screen::PrivacyScreenSetting_PrivacyScreenState& state) {
  if (state == privacy_screen_state_)
    return;

  VLOG(1) << "Privacy screen state changed to "
          << PrivacyScreenStateToString(state);
  privacy_screen_state_ = state;
  metrics_collector_->HandlePrivacyScreenStateChange(privacy_screen_state_);
}

void Daemon::RequestTpmStatus() {
  TRACE_EVENT("power", "Daemon::RequestTpmStatus");
  DCHECK(tpm_manager_proxy_);
  tpm_manager::GetDictionaryAttackInfoRequest request;
  tpm_manager_proxy_->GetDictionaryAttackInfoAsync(
      request,
      base::BindRepeating(&Daemon::HandleGetDictionaryAttackInfoSuccess,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindRepeating(&Daemon::HandleGetDictionaryAttackInfoFailed,
                          weak_ptr_factory_.GetWeakPtr()),
      kTpmManagerdDBusTimeout.InMilliseconds());
}

void Daemon::ShutDown(ShutdownMode mode, ShutdownReason reason) {
  if (shutting_down_) {
    LOG(INFO) << "Shutdown already initiated; ignoring additional request";
    return;
  }

  std::string details;
  if (SuspendAndShutdownAreBlocked(&details)) {
    LOG(INFO) << "Postponing shutdown for lockfile(s): " << details;
    if (!retry_shutdown_for_lockfile_timer_.IsRunning()) {
      retry_shutdown_for_lockfile_timer_.Start(
          FROM_HERE, kShutdownLockfileRetryInterval,
          base::BindRepeating(&Daemon::ShutDown, weak_ptr_factory_.GetWeakPtr(),
                              mode, reason));
    }
    return;
  }

  shutting_down_ = true;
  retry_shutdown_for_lockfile_timer_.Stop();
  suspender_->HandleShutdown();
  metrics_collector_->HandleShutdown(reason);
  if (adaptive_charging_controller_)
    adaptive_charging_controller_->HandleShutdown();

  for (auto controller : all_backlight_controllers_) {
    // If we're going to display a low-battery alert while shutting down, don't
    // turn the screen off immediately.
    if (!(reason == ShutdownReason::LOW_BATTERY &&
          controller == display_backlight_controller_.get()))
      controller->SetShuttingDown(true);
  }

  const std::string reason_str = ShutdownReasonToString(reason);
  switch (mode) {
    case ShutdownMode::POWER_OFF:
      LOG(INFO) << "Shutting down, reason: " << reason_str;
      RunSetuidHelper("shut_down", "--shutdown_reason=" + reason_str, false);
      break;
    case ShutdownMode::REBOOT:
      if (state_controller_->in_docked_mode()) {
        LOG(INFO) << "In docked mode, so telling EC to force lid open to avoid "
                  << "shutting down after reboot";
        RunSetuidHelper("set_force_lid_open", "--force_lid_open", true);
      }
      LOG(INFO) << "Restarting, reason: " << reason_str;
      RunSetuidHelper("reboot", "--shutdown_reason=" + reason_str, false);
      break;
  }
}

void Daemon::Suspend(SuspendImminent::Reason reason,
                     bool use_external_wakeup_count,
                     uint64_t external_wakeup_count,
                     base::TimeDelta duration,
                     SuspendFlavor flavor) {
  if (shutting_down_) {
    LOG(INFO) << "Ignoring request for suspend with outstanding shutdown";
    return;
  }

  if (flavor == SuspendFlavor::RESUME_FROM_DISK_ABORT) {
    suspender_->AbortResumeFromHibernate();

  } else if (use_external_wakeup_count) {
    suspender_->RequestSuspendWithExternalWakeupCount(
        reason, external_wakeup_count, duration, flavor);
  } else {
    suspender_->RequestSuspend(reason, duration, flavor);
  }
}

void Daemon::SetBacklightsDimmedForInactivity(bool dimmed) {
  for (auto controller : all_backlight_controllers_)
    controller->SetDimmedForInactivity(dimmed);
  metrics_collector_->HandleScreenDimmedChange(
      dimmed, state_controller_->last_user_activity_time());
}

void Daemon::SetBacklightsOffForInactivity(bool off) {
  for (auto controller : all_backlight_controllers_)
    controller->SetOffForInactivity(off);
  metrics_collector_->HandleScreenOffChange(
      off, state_controller_->last_user_activity_time());
}

void Daemon::SetBacklightsSuspended(bool suspended) {
  for (auto controller : all_backlight_controllers_)
    controller->SetSuspended(suspended);
}

}  // namespace power_manager
