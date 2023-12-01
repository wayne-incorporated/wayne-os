// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/daemon.h"

#include <fcntl.h>

#include <cmath>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/ec/ec_commands.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>
#include <featured/fake_platform_features.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libec/mock_ec_command_factory.h>
#include <ml-client-test/ml/dbus-proxy-mocks.h>

#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/metrics_sender_stub.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/daemon_delegate.h"
#include "power_manager/powerd/policy/mock_adaptive_charging_controller.h"
#include "power_manager/powerd/policy/mock_backlight_controller.h"
#include "power_manager/powerd/system/acpi_wakeup_helper_stub.h"
#include "power_manager/powerd/system/ambient_light_sensor_manager_stub.h"
#include "power_manager/powerd/system/ambient_light_sensor_watcher_stub.h"
#include "power_manager/powerd/system/audio_client_stub.h"
#include "power_manager/powerd/system/backlight_stub.h"
#include "power_manager/powerd/system/charge_controller_helper_stub.h"
#include "power_manager/powerd/system/cros_ec_helper_stub.h"
#include "power_manager/powerd/system/dark_resume_stub.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/display/display_power_setter_stub.h"
#include "power_manager/powerd/system/display/display_watcher_stub.h"
#include "power_manager/powerd/system/external_ambient_light_sensor_factory_stub.h"
#include "power_manager/powerd/system/input_watcher_stub.h"
#include "power_manager/powerd/system/lockfile_checker_stub.h"
#include "power_manager/powerd/system/machine_quirks_stub.h"
#include "power_manager/powerd/system/peripheral_battery_watcher.h"
#include "power_manager/powerd/system/power_supply.h"
#include "power_manager/powerd/system/power_supply_stub.h"
#include "power_manager/powerd/system/sensor_service_handler.h"
#include "power_manager/powerd/system/suspend_configurator_stub.h"
#include "power_manager/powerd/system/suspend_freezer_stub.h"
#include "power_manager/powerd/system/thermal/thermal_device.h"
#include "power_manager/powerd/system/udev_stub.h"
#include "power_manager/powerd/system/user_proximity_watcher_stub.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/backlight.pb.h"
#include "power_manager/proto_bindings/switch_states.pb.h"

using ::testing::_;
using ::testing::Mock;
using ::testing::Return;
using ::testing::Sequence;

namespace power_manager {

class MockChargeControlSetCommand : public ec::ChargeControlSetCommand {
 public:
  MockChargeControlSetCommand(uint32_t mode, uint8_t lower, uint8_t upper)
      : ec::ChargeControlSetCommand(mode, lower, upper) {}
  MOCK_METHOD(bool, Run, (int fd));
};

class MockChargeCurrentLimitSetCommand
    : public ec::ChargeCurrentLimitSetCommand {
 public:
  explicit MockChargeCurrentLimitSetCommand(uint32_t limit_mA)
      : ec::ChargeCurrentLimitSetCommand(limit_mA) {}

  MOCK_METHOD(bool, Run, (int fd));
};

class DaemonTest : public TestEnvironment, public DaemonDelegate {
 public:
  // The hardcoded constants here are arbitrary and not used by Daemon.
  DaemonTest()
      : passed_prefs_(new FakePrefs()),
        passed_dbus_wrapper_(new system::DBusWrapperStub()),
        passed_platform_features_(
            std::make_unique<feature::FakePlatformFeatures>(
                passed_dbus_wrapper_.get()->GetBus())),
        passed_udev_(new system::UdevStub()),
        passed_ambient_light_sensor_manager_(
            new system::AmbientLightSensorManagerStub()),
        passed_ambient_light_sensor_watcher_(
            new system::AmbientLightSensorWatcherStub()),
        passed_external_ambient_light_sensor_factory_(
            new system::ExternalAmbientLightSensorFactoryStub()),
        passed_display_watcher_(new system::DisplayWatcherStub()),
        passed_display_power_setter_(new system::DisplayPowerSetterStub()),
        passed_internal_backlight_(new system::BacklightStub(
            100, 100, system::BacklightInterface::BrightnessScale::kUnknown)),
        passed_keyboard_backlight_(new system::BacklightStub(
            100, 100, system::BacklightInterface::BrightnessScale::kUnknown)),
        passed_ec_command_factory_(new ec::MockEcCommandFactory()),
        passed_ec_usb_endpoint_(new ec::EcUsbEndpointStub()),
        passed_ec_keyboard_backlight_(new system::BacklightStub(
            100, 100, system::BacklightInterface::BrightnessScale::kUnknown)),
        passed_external_backlight_controller_(
            new policy::MockBacklightController()),
        passed_internal_backlight_controller_(
            new policy::MockBacklightController()),
        passed_keyboard_backlight_controller_(
            new policy::MockBacklightController()),
        passed_input_watcher_(new system::InputWatcherStub()),
        passed_acpi_wakeup_helper_(new system::AcpiWakeupHelperStub()),
        passed_ec_helper_(new system::CrosEcHelperStub()),
        passed_power_supply_(new system::PowerSupplyStub()),
        passed_user_proximity_watcher_(new system::UserProximityWatcherStub()),
        passed_dark_resume_(new system::DarkResumeStub()),
        passed_audio_client_(new system::AudioClientStub()),
        passed_lockfile_checker_(new system::LockfileCheckerStub()),
        passed_machine_quirks_(new system::MachineQuirksStub()),
        passed_metrics_sender_(new MetricsSenderStub()),
        passed_charge_controller_helper_(
            new system::ChargeControllerHelperStub()),
        passed_adaptive_charging_controller_(
            new policy::MockAdaptiveChargingController()),
        passed_adaptive_charging_proxy_(
            new org::chromium::MachineLearning::AdaptiveChargingProxyMock()),
        passed_suspend_configurator_(new system::SuspendConfiguratorStub()),
        passed_suspend_freezer_(new system::SuspendFreezerStub()),
        prefs_(passed_prefs_.get()),
        platform_features_(passed_platform_features_.get()),
        dbus_wrapper_(passed_dbus_wrapper_.get()),
        udev_(passed_udev_.get()),
        ambient_light_sensor_manager_(
            passed_ambient_light_sensor_manager_.get()),
        ambient_light_sensor_watcher_(
            passed_ambient_light_sensor_watcher_.get()),
        external_ambient_light_sensor_factory_(
            passed_external_ambient_light_sensor_factory_.get()),
        display_watcher_(passed_display_watcher_.get()),
        display_power_setter_(passed_display_power_setter_.get()),
        internal_backlight_(passed_internal_backlight_.get()),
        keyboard_backlight_(passed_keyboard_backlight_.get()),
        ec_command_factory_(passed_ec_command_factory_.get()),
        ec_keyboard_backlight_(passed_ec_keyboard_backlight_.get()),
        external_backlight_controller_(
            passed_external_backlight_controller_.get()),
        internal_backlight_controller_(
            passed_internal_backlight_controller_.get()),
        keyboard_backlight_controller_(
            passed_keyboard_backlight_controller_.get()),
        input_watcher_(passed_input_watcher_.get()),
        acpi_wakeup_helper_(passed_acpi_wakeup_helper_.get()),
        ec_helper_(passed_ec_helper_.get()),
        power_supply_(passed_power_supply_.get()),
        user_proximity_watcher_(passed_user_proximity_watcher_.get()),
        dark_resume_(passed_dark_resume_.get()),
        audio_client_(passed_audio_client_.get()),
        lockfile_checker_(passed_lockfile_checker_.get()),
        machine_quirks_(passed_machine_quirks_.get()),
        metrics_sender_(passed_metrics_sender_.get()),
        adaptive_charging_controller_(
            passed_adaptive_charging_controller_.get()),
        adaptive_charging_proxy_(passed_adaptive_charging_proxy_.get()) {
    CHECK(run_dir_.CreateUniqueTempDir());
    CHECK(run_dir_.IsValid());

    CHECK(temp_dir_.CreateUniqueTempDir());
    CHECK(temp_dir_.IsValid());
    wakeup_count_path_ = temp_dir_.GetPath().Append("wakeup_count");
    oobe_completed_path_ = temp_dir_.GetPath().Append("oobe_completed");
    cros_ec_path_ = temp_dir_.GetPath().Append("cros_ec");
    suspended_state_path_ = temp_dir_.GetPath().Append("suspended_state");
    hibernated_state_path_ = temp_dir_.GetPath().Append("hibernated_state");
    flashrom_lock_path_ = temp_dir_.GetPath().Append("flashrom_lock");
    battery_tool_lock_path_ = temp_dir_.GetPath().Append("battery_tool_lock");
    proc_path_ = temp_dir_.GetPath().Append("proc");
  }
  DaemonTest(const DaemonTest&) = delete;
  DaemonTest& operator=(const DaemonTest&) = delete;

  ~DaemonTest() override = default;

  void Init() {
    // These prefs are required by policy::Suspender.
    prefs_->SetInt64(kRetrySuspendMsPref, 10000);
    prefs_->SetInt64(kRetrySuspendAttemptsPref, 10);

    // These prefs are required by policy::StateController.
    prefs_->SetInt64(kPluggedSuspendMsPref, 1800000);
    prefs_->SetInt64(kPluggedOffMsPref, 480000);
    prefs_->SetInt64(kPluggedDimMsPref, 420000);
    prefs_->SetInt64(kPluggedQuickDimMsPref, 120000);
    prefs_->SetInt64(kPluggedQuickLockMsPref, 180000);
    prefs_->SetInt64(kUnpluggedSuspendMsPref, 600000);
    prefs_->SetInt64(kUnpluggedOffMsPref, 360000);
    prefs_->SetInt64(kUnpluggedDimMsPref, 300000);
    prefs_->SetInt64(kUnpluggedQuickDimMsPref, 60000);
    prefs_->SetInt64(kUnpluggedQuickLockMsPref, 120000);

    // This pref is required by policy::ShutdownFromSuspend.
    prefs_->SetBool(kDisableHibernatePref, false);

    // This external setting is required for policy::AdaptiveChargingController.
    prefs_->set_external_string_for_testing("/hardware-properties", "psu-type",
                                            "battery");

    resourced_call_count_ = 0;
    resourced_fail_ = 0;

    daemon_ = std::make_unique<Daemon>(this, run_dir_.GetPath());
    daemon_->set_wakeup_count_path_for_testing(wakeup_count_path_);
    daemon_->set_oobe_completed_path_for_testing(oobe_completed_path_);
    daemon_->set_cros_ec_path_for_testing(cros_ec_path_);
    daemon_->set_suspended_state_path_for_testing(suspended_state_path_);
    daemon_->set_hibernated_state_path_for_testing(hibernated_state_path_);
    daemon_->disable_mojo_for_testing();
    daemon_->Init();
  }

  // DaemonDelegate:
  std::unique_ptr<PrefsInterface> CreatePrefs() override {
    return std::move(passed_prefs_);
  }
  feature::FakePlatformFeatures* CreatePlatformFeatures(
      system::DBusWrapperInterface* dbus_wrapper) override {
    return passed_platform_features_.get();
  }
  std::unique_ptr<system::DBusWrapperInterface> CreateDBusWrapper() override {
    return std::move(passed_dbus_wrapper_);
  }
  std::unique_ptr<system::UdevInterface> CreateUdev() override {
    return std::move(passed_udev_);
  }
  std::unique_ptr<system::SensorServiceHandler> CreateSensorServiceHandler()
      override {
    return std::make_unique<system::SensorServiceHandler>();
  }
  std::unique_ptr<system::AmbientLightSensorManagerInterface>
  CreateAmbientLightSensorManager(
      PrefsInterface* prefs,
      system::SensorServiceHandler* sensor_service_handler) override {
    return std::move(passed_ambient_light_sensor_manager_);
  }
  std::unique_ptr<system::AmbientLightSensorWatcherInterface>
  CreateAmbientLightSensorWatcher(system::UdevInterface* udev) override {
    EXPECT_EQ(udev_, udev);
    return std::move(passed_ambient_light_sensor_watcher_);
  }
  std::unique_ptr<system::AmbientLightSensorWatcherInterface>
  CreateAmbientLightSensorWatcher(
      system::SensorServiceHandler* sensor_service_handler) override {
    return std::move(passed_ambient_light_sensor_watcher_);
  }
  std::unique_ptr<system::ExternalAmbientLightSensorFactoryInterface>
  CreateExternalAmbientLightSensorFactory() override {
    return std::move(passed_external_ambient_light_sensor_factory_);
  }
  std::unique_ptr<system::ExternalAmbientLightSensorFactoryInterface>
  CreateExternalAmbientLightSensorFactory(
      system::AmbientLightSensorWatcherMojo* watcher) override {
    return std::move(passed_external_ambient_light_sensor_factory_);
  }
  std::unique_ptr<system::DisplayWatcherInterface> CreateDisplayWatcher(
      system::UdevInterface* udev) override {
    EXPECT_EQ(udev_, udev);
    return std::move(passed_display_watcher_);
  }
  std::unique_ptr<system::DisplayPowerSetterInterface> CreateDisplayPowerSetter(
      system::DBusWrapperInterface* dbus_wrapper) override {
    EXPECT_EQ(dbus_wrapper_, dbus_wrapper);
    return std::move(passed_display_power_setter_);
  }
  std::unique_ptr<policy::BacklightController>
  CreateExternalBacklightController(
      PrefsInterface* prefs,
      system::AmbientLightSensorWatcherInterface* ambient_light_sensor_watcher,
      system::ExternalAmbientLightSensorFactoryInterface*
          external_ambient_light_sensor_factory,
      system::DisplayWatcherInterface* display_watcher,
      system::DisplayPowerSetterInterface* display_power_setter,
      system::DBusWrapperInterface* dbus_wrapper) override {
    EXPECT_EQ(prefs_, prefs);
    EXPECT_EQ(ambient_light_sensor_watcher_, ambient_light_sensor_watcher);
    EXPECT_EQ(external_ambient_light_sensor_factory_,
              external_ambient_light_sensor_factory);
    EXPECT_EQ(display_watcher_, display_watcher);
    EXPECT_EQ(display_power_setter_, display_power_setter);
    EXPECT_EQ(dbus_wrapper_, dbus_wrapper);
    return std::move(passed_external_backlight_controller_);
  }
  std::unique_ptr<system::BacklightInterface> CreateInternalBacklight(
      const base::FilePath& base_path, const std::string& pattern) override {
    // This should only be called for the display backlight.
    EXPECT_EQ(kInternalBacklightPath, base_path.value());
    EXPECT_EQ(kInternalBacklightPattern, pattern);
    return std::move(passed_internal_backlight_);
  }
  std::unique_ptr<system::BacklightInterface> CreatePluggableInternalBacklight(
      system::UdevInterface* udev,
      const std::string& udev_subsystem,
      const base::FilePath& base_path,
      const std::string& pattern) override {
    // This should only be called for the keyboard backlight.
    EXPECT_EQ(udev_, udev);
    EXPECT_EQ(kKeyboardBacklightUdevSubsystem, udev_subsystem);
    EXPECT_EQ(kKeyboardBacklightPath, base_path.value());
    EXPECT_EQ(kKeyboardBacklightPattern, pattern);
    return std::move(passed_keyboard_backlight_);
  }
  std::unique_ptr<policy::BacklightController>
  CreateInternalBacklightController(
      system::BacklightInterface* backlight,
      PrefsInterface* prefs,
      system::AmbientLightSensorInterface* sensor,
      system::DisplayPowerSetterInterface* power_setter,
      system::DBusWrapperInterface* dbus_wrapper,
      LidState initial_lid_state) override {
    EXPECT_EQ(internal_backlight_, backlight);
    EXPECT_EQ(prefs_, prefs);
    EXPECT_TRUE(
        !sensor ||
        sensor ==
            ambient_light_sensor_manager_->GetSensorForInternalBacklight());
    EXPECT_EQ(display_power_setter_, power_setter);
    EXPECT_EQ(dbus_wrapper_, dbus_wrapper);
    EXPECT_EQ(input_watcher_->QueryLidState(), initial_lid_state);
    return std::move(passed_internal_backlight_controller_);
  }
  std::unique_ptr<policy::BacklightController>
  CreateKeyboardBacklightController(system::BacklightInterface* backlight,
                                    PrefsInterface* prefs,
                                    system::AmbientLightSensorInterface* sensor,
                                    system::DBusWrapperInterface* dbus_wrapper,
                                    LidState initial_lid_state,
                                    TabletMode initial_tablet_mode) override {
    if (ec_keyboard_backlight_enabled_) {
      EXPECT_EQ(ec_keyboard_backlight_, backlight);
    } else {
      EXPECT_EQ(keyboard_backlight_, backlight);
    }
    EXPECT_EQ(prefs_, prefs);
    EXPECT_TRUE(
        !sensor ||
        sensor ==
            ambient_light_sensor_manager_->GetSensorForKeyboardBacklight());
    EXPECT_EQ(dbus_wrapper_, dbus_wrapper);
    EXPECT_EQ(input_watcher_->QueryLidState(), initial_lid_state);
    EXPECT_EQ(input_watcher_->GetTabletMode(), initial_tablet_mode);
    return std::move(passed_keyboard_backlight_controller_);
  }
  std::unique_ptr<ec::EcCommandFactoryInterface> CreateEcCommandFactory()
      override {
    return std::move(passed_ec_command_factory_);
  }
  std::unique_ptr<ec::EcUsbEndpointInterface> CreateEcUsbEndpoint() override {
    return std::move(passed_ec_usb_endpoint_);
  }
  bool ec_keyboard_backlight_enabled_ = false;
  std::unique_ptr<system::BacklightInterface> CreateEcKeyboardBacklight(
      ec::EcUsbEndpointInterface* endpoint) override {
    if (ec_keyboard_backlight_enabled_) {
      return std::move(passed_ec_keyboard_backlight_);
    } else {
      return nullptr;
    }
  }
  std::unique_ptr<system::InputWatcherInterface> CreateInputWatcher(
      PrefsInterface* prefs, system::UdevInterface* udev) override {
    EXPECT_EQ(prefs_, prefs);
    EXPECT_EQ(udev_, udev);
    return std::move(passed_input_watcher_);
  }
  std::unique_ptr<system::AcpiWakeupHelperInterface> CreateAcpiWakeupHelper()
      override {
    return std::move(passed_acpi_wakeup_helper_);
  }
  std::unique_ptr<system::CrosEcHelperInterface> CreateCrosEcHelper() override {
    return std::move(passed_ec_helper_);
  }
  std::unique_ptr<system::PeripheralBatteryWatcher>
  CreatePeripheralBatteryWatcher(system::DBusWrapperInterface* dbus_wrapper,
                                 system::UdevInterface* udev) override {
    EXPECT_EQ(dbus_wrapper_, dbus_wrapper);
    EXPECT_EQ(udev_, udev);
    return nullptr;
  }
  std::unique_ptr<system::PowerSupplyInterface> CreatePowerSupply(
      const base::FilePath& power_supply_path,
      const base::FilePath& cros_ec_path,
      ec::EcCommandFactoryInterface* ec_command_factory,
      PrefsInterface* prefs,
      system::UdevInterface* udev,
      system::DBusWrapperInterface* dbus_wrapper,
      BatteryPercentageConverter* battery_percentage_converter) override {
    EXPECT_EQ(kPowerStatusPath, power_supply_path.value());
    EXPECT_EQ(cros_ec_path_, cros_ec_path);
    EXPECT_EQ(ec_command_factory_, ec_command_factory);
    EXPECT_EQ(prefs_, prefs);
    EXPECT_EQ(udev_, udev);
    EXPECT_EQ(dbus_wrapper_, dbus_wrapper);
    EXPECT_TRUE(battery_percentage_converter);
    return std::move(passed_power_supply_);
  }
  std::unique_ptr<system::UserProximityWatcherInterface>
  CreateUserProximityWatcher(PrefsInterface* prefs,
                             system::UdevInterface* udev,
                             TabletMode initial_tablet_mode) override {
    EXPECT_EQ(prefs_, prefs);
    EXPECT_EQ(udev_, udev);
    EXPECT_EQ(input_watcher_->GetTabletMode(), initial_tablet_mode);
    return std::move(passed_user_proximity_watcher_);
  }
  std::unique_ptr<system::DarkResumeInterface> CreateDarkResume(
      PrefsInterface* prefs,
      system::WakeupSourceIdentifierInterface* wakeup_source_identifier)
      override {
    EXPECT_EQ(prefs_, prefs);
    return std::move(passed_dark_resume_);
  }
  std::unique_ptr<system::AudioClientInterface> CreateAudioClient(
      system::DBusWrapperInterface* dbus_wrapper,
      const base::FilePath& run_dir) override {
    EXPECT_EQ(dbus_wrapper_, dbus_wrapper);
    return std::move(passed_audio_client_);
  }
  std::unique_ptr<system::LockfileCheckerInterface> CreateLockfileChecker(
      const base::FilePath& dir,
      const std::vector<base::FilePath>& files) override {
    return std::move(passed_lockfile_checker_);
  }
  std::unique_ptr<system::MachineQuirksInterface> CreateMachineQuirks(
      PrefsInterface* prefs) override {
    EXPECT_EQ(prefs_, prefs);
    // Init is necessary here as prefs_ will be written to while testing
    // MachineQuirks.
    passed_machine_quirks_->Init(prefs);
    return std::move(passed_machine_quirks_);
  }
  std::unique_ptr<MetricsSenderInterface> CreateMetricsSender() override {
    return std::move(passed_metrics_sender_);
  }
  std::unique_ptr<system::ChargeControllerHelperInterface>
  CreateChargeControllerHelper() override {
    return std::move(passed_charge_controller_helper_);
  }
  std::unique_ptr<policy::AdaptiveChargingControllerInterface>
  CreateAdaptiveChargingController(
      policy::AdaptiveChargingControllerInterface::Delegate* delegate,
      policy::BacklightController* backlight_controller,
      system::InputWatcherInterface* input_watcher,
      system::PowerSupplyInterface* power_supply,
      system::DBusWrapperInterface* dbus_wrapper,
      feature::PlatformFeaturesInterface* platform_features,
      PrefsInterface* prefs) override {
    EXPECT_EQ(daemon_.get(), delegate);
    // Sometimes the `display_backlight_controller_` in Daemon is NULL for
    // tests (and factory mode).
    if (backlight_controller)
      EXPECT_EQ(internal_backlight_controller_, backlight_controller);
    EXPECT_EQ(input_watcher_, input_watcher);
    EXPECT_EQ(power_supply_, power_supply);
    EXPECT_EQ(dbus_wrapper_, dbus_wrapper);
    EXPECT_EQ(platform_features_, platform_features);
    EXPECT_EQ(prefs_, prefs);
    return std::move(passed_adaptive_charging_controller_);
  }
  std::unique_ptr<
      org::chromium::MachineLearning::AdaptiveChargingProxyInterface>
  CreateAdaptiveChargingProxy(const scoped_refptr<dbus::Bus>& bus) override {
    return std::move(passed_adaptive_charging_proxy_);
  }
  std::unique_ptr<system::SuspendConfiguratorInterface>
  CreateSuspendConfigurator(
      feature::PlatformFeaturesInterface* platform_features,
      PrefsInterface* prefs) override {
    EXPECT_EQ(platform_features_, platform_features);
    EXPECT_EQ(prefs_, prefs);
    return std::move(passed_suspend_configurator_);
  }
  std::unique_ptr<system::SuspendFreezerInterface> CreateSuspendFreezer(
      PrefsInterface* prefs) override {
    EXPECT_EQ(prefs_, prefs);
    return std::move(passed_suspend_freezer_);
  }
  std::vector<std::unique_ptr<system::ThermalDeviceInterface>>
  CreateThermalDevices() override {
    // Not using pass_* pattern because this is a vector, not just an
    // object.
    return std::vector<std::unique_ptr<system::ThermalDeviceInterface>>();
  }
  pid_t GetPid() override { return pid_; }
  void Launch(const std::string& command) override {
    async_commands_.push_back(command);
  }
  int Run(const std::string& command) override {
    sync_commands_.push_back(command);
    return 0;
  }

  // DBusWrapperStub::MethodCallback implementation used to handle resourced
  // D-Bus call (resource_manager::kSetFullscreenVideoWithTimeout).
  int resourced_call_count_;
  int resourced_fail_;
  std::unique_ptr<dbus::Response> HandleResourcedMethodCall(
      dbus::ObjectProxy* proxy, dbus::MethodCall* method_call) {
    resourced_call_count_++;
    if (resourced_call_count_ != 1) {
      return nullptr;
    }

    if (method_call->GetInterface() !=
        resource_manager::kResourceManagerInterface) {
      resourced_fail_ = 1;
      return nullptr;
    }

    std::unique_ptr<dbus::Response> response =
        dbus::Response::FromMethodCall(method_call);
    return response;
  }

 protected:
  // Send the appropriate events to put StateController into docked mode.
  void EnterDockedMode() {
    dbus::MethodCall call(kPowerManagerInterface, kSetIsProjectingMethod);
    dbus::MessageWriter(&call).AppendBool(true /* is_projecting */);
    ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&call).get());

    input_watcher_->set_lid_state(LidState::CLOSED);
    input_watcher_->NotifyObserversAboutLidState();
  }

  // Returns the command that Daemon should execute to shut down for a given
  // reason.
  std::string GetShutdownCommand(ShutdownReason reason) {
    return base::StringPrintf("%s --action=shut_down --shutdown_reason=%s",
                              kSetuidHelperPath,
                              ShutdownReasonToString(reason).c_str());
  }

  bool IsSuspendCommandIdle() {
    std::string suspend_arg = "--suspend_to_idle";
    async_commands_.clear();
    sync_commands_.clear();
    daemon_->DoSuspend(1, true, base::Milliseconds(0), false);
    return sync_commands_[0].find(suspend_arg) != std::string::npos;
  }

  // Commands for forcing the lid open or stopping forcing it open.
  const std::string kForceLidOpenCommand =
      std::string(kSetuidHelperPath) +
      " --action=set_force_lid_open --force_lid_open";
  const std::string kNoForceLidOpenCommand =
      std::string(kSetuidHelperPath) +
      " --action=set_force_lid_open --noforce_lid_open";

  // Stub objects to be transferred by Create* methods.
  std::unique_ptr<FakePrefs> passed_prefs_;
  std::unique_ptr<system::DBusWrapperStub> passed_dbus_wrapper_;
  std::unique_ptr<feature::FakePlatformFeatures> passed_platform_features_;
  std::unique_ptr<system::UdevStub> passed_udev_;
  std::unique_ptr<system::AmbientLightSensorManagerStub>
      passed_ambient_light_sensor_manager_;
  std::unique_ptr<system::AmbientLightSensorWatcherStub>
      passed_ambient_light_sensor_watcher_;
  std::unique_ptr<system::ExternalAmbientLightSensorFactoryStub>
      passed_external_ambient_light_sensor_factory_;
  std::unique_ptr<system::DisplayWatcherStub> passed_display_watcher_;
  std::unique_ptr<system::DisplayPowerSetterStub> passed_display_power_setter_;
  std::unique_ptr<system::BacklightStub> passed_internal_backlight_;
  std::unique_ptr<system::BacklightStub> passed_keyboard_backlight_;
  std::unique_ptr<ec::MockEcCommandFactory> passed_ec_command_factory_;
  std::unique_ptr<ec::EcUsbEndpointInterface> passed_ec_usb_endpoint_;
  std::unique_ptr<system::BacklightStub> passed_ec_keyboard_backlight_;
  std::unique_ptr<policy::MockBacklightController>
      passed_external_backlight_controller_;
  std::unique_ptr<policy::MockBacklightController>
      passed_internal_backlight_controller_;
  std::unique_ptr<policy::MockBacklightController>
      passed_keyboard_backlight_controller_;
  std::unique_ptr<system::InputWatcherStub> passed_input_watcher_;
  std::unique_ptr<system::AcpiWakeupHelperStub> passed_acpi_wakeup_helper_;
  std::unique_ptr<system::CrosEcHelperStub> passed_ec_helper_;
  std::unique_ptr<system::PowerSupplyStub> passed_power_supply_;
  std::unique_ptr<system::UserProximityWatcherStub>
      passed_user_proximity_watcher_;
  std::unique_ptr<system::DarkResumeStub> passed_dark_resume_;
  std::unique_ptr<system::AudioClientStub> passed_audio_client_;
  std::unique_ptr<system::LockfileCheckerStub> passed_lockfile_checker_;
  std::unique_ptr<system::MachineQuirksStub> passed_machine_quirks_;
  std::unique_ptr<MetricsSenderStub> passed_metrics_sender_;
  std::unique_ptr<system::ChargeControllerHelperInterface>
      passed_charge_controller_helper_;
  std::unique_ptr<policy::MockAdaptiveChargingController>
      passed_adaptive_charging_controller_;
  std::unique_ptr<org::chromium::MachineLearning::AdaptiveChargingProxyMock>
      passed_adaptive_charging_proxy_;
  std::unique_ptr<system::SuspendConfiguratorInterface>
      passed_suspend_configurator_;
  std::unique_ptr<system::SuspendFreezerInterface> passed_suspend_freezer_;

  // Pointers to objects originally stored in |passed_*| members. These
  // allow continued access by tests even after the corresponding Create*
  // method has been called and ownership has been transferred to |daemon_|.
  FakePrefs* prefs_;
  feature::PlatformFeaturesInterface* platform_features_;
  system::DBusWrapperStub* dbus_wrapper_;
  system::UdevStub* udev_;
  system::AmbientLightSensorManagerStub* ambient_light_sensor_manager_;
  system::AmbientLightSensorWatcherStub* ambient_light_sensor_watcher_;
  system::ExternalAmbientLightSensorFactoryStub*
      external_ambient_light_sensor_factory_;
  system::DisplayWatcherStub* display_watcher_;
  system::DisplayPowerSetterStub* display_power_setter_;
  system::BacklightStub* internal_backlight_;
  system::BacklightStub* keyboard_backlight_;
  ec::MockEcCommandFactory* ec_command_factory_;
  system::BacklightStub* ec_keyboard_backlight_;
  policy::MockBacklightController* external_backlight_controller_;
  policy::MockBacklightController* internal_backlight_controller_;
  policy::MockBacklightController* keyboard_backlight_controller_;
  system::InputWatcherStub* input_watcher_;
  system::AcpiWakeupHelperStub* acpi_wakeup_helper_;
  system::CrosEcHelperStub* ec_helper_;
  system::PowerSupplyStub* power_supply_;
  system::UserProximityWatcherStub* user_proximity_watcher_;
  system::DarkResumeStub* dark_resume_;
  system::AudioClientStub* audio_client_;
  system::LockfileCheckerStub* lockfile_checker_;
  system::MachineQuirksStub* machine_quirks_;
  MetricsSenderStub* metrics_sender_;
  policy::MockAdaptiveChargingController* adaptive_charging_controller_;
  org::chromium::MachineLearning::AdaptiveChargingProxyMock*
      adaptive_charging_proxy_;

  // Run directory passed to |daemon_|.
  base::ScopedTempDir run_dir_;

  // Temp files passed to |daemon_|.
  base::ScopedTempDir temp_dir_;
  base::FilePath wakeup_count_path_;
  base::FilePath oobe_completed_path_;
  base::FilePath cros_ec_path_;
  base::FilePath suspended_state_path_;
  base::FilePath hibernated_state_path_;
  base::FilePath flashrom_lock_path_;
  base::FilePath battery_tool_lock_path_;
  base::FilePath proc_path_;

  // Value to return from GetPid().
  pid_t pid_ = 2;

  // Command lines executed via Launch() and Run(), respectively.
  std::vector<std::string> async_commands_;
  std::vector<std::string> sync_commands_;

  std::unique_ptr<Daemon> daemon_;
};

TEST_F(DaemonTest, NotifyMembersAboutEvents) {
  prefs_->SetInt64(kHasKeyboardBacklightPref, 1);

  Init();

  // Power button events.
  EXPECT_CALL(*internal_backlight_controller_, HandlePowerButtonPress())
      .Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_, HandlePowerButtonPress())
      .Times(1);
  input_watcher_->NotifyObserversAboutPowerButtonEvent(ButtonState::DOWN);
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // Hover state changes.
  {
    Sequence s1, s2;
    EXPECT_CALL(*internal_backlight_controller_, HandleHoverStateChange(true))
        .InSequence(s1);
    EXPECT_CALL(*internal_backlight_controller_, HandleHoverStateChange(false))
        .InSequence(s1);
    EXPECT_CALL(*keyboard_backlight_controller_, HandleHoverStateChange(true))
        .InSequence(s2);
    EXPECT_CALL(*keyboard_backlight_controller_, HandleHoverStateChange(false))
        .InSequence(s2);

    input_watcher_->NotifyObserversAboutHoverState(true);
    input_watcher_->NotifyObserversAboutHoverState(false);

    Mock::VerifyAndClearExpectations(internal_backlight_controller_);
    Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);
  }

  // Lid events.
  EXPECT_CALL(*internal_backlight_controller_,
              HandleLidStateChange(LidState::CLOSED))
      .Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_,
              HandleLidStateChange(LidState::CLOSED))
      .Times(1);
  input_watcher_->set_lid_state(LidState::CLOSED);
  input_watcher_->NotifyObserversAboutLidState();
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // Tablet mode changes.
  EXPECT_CALL(*internal_backlight_controller_,
              HandleTabletModeChange(TabletMode::ON))
      .Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_,
              HandleTabletModeChange(TabletMode::ON))
      .Times(1);
  input_watcher_->set_tablet_mode(TabletMode::ON);
  input_watcher_->NotifyObserversAboutTabletMode();
  ASSERT_EQ(1, user_proximity_watcher_->tablet_mode_changes().size());
  EXPECT_EQ(TabletMode::ON, user_proximity_watcher_->tablet_mode_changes()[0]);
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // Power source changes.
  EXPECT_CALL(*internal_backlight_controller_,
              HandlePowerSourceChange(PowerSource::AC))
      .Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_,
              HandlePowerSourceChange(PowerSource::AC))
      .Times(1);
  system::PowerStatus status;
  status.line_power_on = true;
  power_supply_->set_status(status);
  power_supply_->NotifyObservers();
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // User activity reports.
  EXPECT_CALL(*internal_backlight_controller_,
              HandleUserActivity(USER_ACTIVITY_BRIGHTNESS_UP_KEY_PRESS))
      .Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_,
              HandleUserActivity(USER_ACTIVITY_BRIGHTNESS_UP_KEY_PRESS))
      .Times(1);
  dbus::MethodCall user_call(kPowerManagerInterface, kHandleUserActivityMethod);
  dbus::MessageWriter(&user_call)
      .AppendInt32(USER_ACTIVITY_BRIGHTNESS_UP_KEY_PRESS);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&user_call).get());
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // Video activity reports.
  EXPECT_CALL(*internal_backlight_controller_, HandleVideoActivity(true))
      .Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_, HandleVideoActivity(true))
      .Times(1);
  dbus_wrapper_->SetMethodCallback(base::BindRepeating(
      &DaemonTest::HandleResourcedMethodCall, base::Unretained(this)));
  dbus::MethodCall video_call(kPowerManagerInterface,
                              kHandleVideoActivityMethod);
  dbus::MessageWriter(&video_call).AppendBool(true /* fullscreen */);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&video_call).get());
  ASSERT_EQ(0, resourced_fail_);
  ASSERT_EQ(1, resourced_call_count_);
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // Display mode / projecting changes.
  EXPECT_CALL(*internal_backlight_controller_,
              HandleDisplayModeChange(DisplayMode::PRESENTATION))
      .Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_,
              HandleDisplayModeChange(DisplayMode::PRESENTATION))
      .Times(1);
  dbus::MethodCall display_call(kPowerManagerInterface, kSetIsProjectingMethod);
  dbus::MessageWriter(&display_call).AppendBool(true /* is_projecting */);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&display_call).get());
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // Policy updates.
  const char kPolicyReason[] = "foo";
  PowerManagementPolicy policy;
  policy.set_reason(kPolicyReason);
  EXPECT_CALL(*internal_backlight_controller_, HandlePolicyChange(_)).Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_, HandlePolicyChange(_)).Times(1);
  dbus::MethodCall policy_call(kPowerManagerInterface, kSetPolicyMethod);
  dbus::MessageWriter(&policy_call).AppendProtoAsArrayOfBytes(policy);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&policy_call).get());
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // Session state changes.
  EXPECT_CALL(*internal_backlight_controller_,
              HandleSessionStateChange(SessionState::STARTED))
      .Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_,
              HandleSessionStateChange(SessionState::STARTED))
      .Times(1);
  dbus::Signal session_signal(login_manager::kSessionManagerInterface,
                              login_manager::kSessionStateChangedSignal);
  dbus::MessageWriter(&session_signal).AppendString("started");
  dbus_wrapper_->EmitRegisteredSignal(
      dbus_wrapper_->GetObjectProxy(login_manager::kSessionManagerServiceName,
                                    login_manager::kSessionManagerServicePath),
      &session_signal);
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // Chrome restarts.
  EXPECT_CALL(*internal_backlight_controller_, HandleDisplayServiceStart())
      .Times(2);
  EXPECT_CALL(*keyboard_backlight_controller_, HandleDisplayServiceStart())
      .Times(2);
  dbus_wrapper_->NotifyNameOwnerChanged(chromeos::kDisplayServiceName, "old",
                                        "new");
  dbus_wrapper_->NotifyNameOwnerChanged(chromeos::kDisplayServiceName, "new",
                                        "newer");
  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  // Wake notification events.
  EXPECT_CALL(*internal_backlight_controller_, HandleWakeNotification())
      .Times(1);
  dbus::MethodCall wake_notification_call(kPowerManagerInterface,
                                          kHandleWakeNotificationMethod);
  ASSERT_TRUE(
      dbus_wrapper_->CallExportedMethodSync(&wake_notification_call).get());
}

TEST_F(DaemonTest, DontReportTabletModeChangeFromInit) {
  EXPECT_CALL(*internal_backlight_controller_, HandleTabletModeChange(_))
      .Times(0);
  EXPECT_CALL(*keyboard_backlight_controller_, HandleTabletModeChange(_))
      .Times(0);

  // The initial tablet mode is already passed to
  // CreateKeyboardBacklightController(), so Init() shouldn't send an extra
  // notification about it changing.

  prefs_->SetInt64(kHasKeyboardBacklightPref, 1);
  input_watcher_->set_tablet_mode(TabletMode::ON);
  Init();
}

TEST_F(DaemonTest, EcKeyboardBacklightEnabled) {
  ec_keyboard_backlight_enabled_ = true;
  Init();
}

TEST_F(DaemonTest, ForceBacklightsOff) {
  prefs_->SetInt64(kHasKeyboardBacklightPref, 1);
  Init();

  EXPECT_CALL(*internal_backlight_controller_, SetForcedOff(true)).Times(1);
  ON_CALL(*internal_backlight_controller_, GetForcedOff())
      .WillByDefault(Return(true));

  EXPECT_CALL(*keyboard_backlight_controller_, SetForcedOff(true)).Times(1);
  ON_CALL(*keyboard_backlight_controller_, GetForcedOff())
      .WillByDefault(Return(true));

  // Tell Daemon to force the backlights off.
  dbus::MethodCall set_off_call(kPowerManagerInterface,
                                kSetBacklightsForcedOffMethod);
  dbus::MessageWriter(&set_off_call).AppendBool(true);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&set_off_call).get());

  dbus::MethodCall get_call(kPowerManagerInterface,
                            kGetBacklightsForcedOffMethod);
  auto response = dbus_wrapper_->CallExportedMethodSync(&get_call);
  ASSERT_TRUE(response.get());
  bool forced_off = false;
  ASSERT_TRUE(dbus::MessageReader(response.get()).PopBool(&forced_off));
  EXPECT_TRUE(forced_off);

  Mock::VerifyAndClearExpectations(internal_backlight_controller_);
  Mock::VerifyAndClearExpectations(keyboard_backlight_controller_);

  EXPECT_CALL(*internal_backlight_controller_, SetForcedOff(false)).Times(1);
  ON_CALL(*internal_backlight_controller_, GetForcedOff())
      .WillByDefault(Return(false));

  EXPECT_CALL(*keyboard_backlight_controller_, SetForcedOff(false)).Times(1);
  ON_CALL(*keyboard_backlight_controller_, GetForcedOff())
      .WillByDefault(Return(false));

  // Now stop forcing them off.
  dbus::MethodCall set_on_call(kPowerManagerInterface,
                               kSetBacklightsForcedOffMethod);
  dbus::MessageWriter(&set_on_call).AppendBool(false);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&set_on_call).get());

  response = dbus_wrapper_->CallExportedMethodSync(&get_call);
  ASSERT_TRUE(response.get());
  ASSERT_TRUE(dbus::MessageReader(response.get()).PopBool(&forced_off));
  EXPECT_FALSE(forced_off);
}

TEST_F(DaemonTest, RequestShutdown) {
  prefs_->SetInt64(kHasKeyboardBacklightPref, 1);
  Init();

  EXPECT_CALL(*adaptive_charging_controller_, HandleShutdown()).Times(1);
  EXPECT_CALL(*internal_backlight_controller_, SetShuttingDown(true)).Times(1);
  EXPECT_CALL(*keyboard_backlight_controller_, SetShuttingDown(true)).Times(1);

  async_commands_.clear();
  sync_commands_.clear();
  dbus::MethodCall method_call(kPowerManagerInterface, kRequestShutdownMethod);
  dbus::MessageWriter message_writer(&method_call);
  message_writer.AppendInt32(REQUEST_SHUTDOWN_FOR_USER);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&method_call).get());

  EXPECT_EQ(0, sync_commands_.size());
  ASSERT_EQ(1, async_commands_.size());
  EXPECT_EQ(GetShutdownCommand(ShutdownReason::USER_REQUEST),
            async_commands_[0]);

  // Sending another request shouldn't do anything.
  async_commands_.clear();
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&method_call).get());
  EXPECT_EQ(0, async_commands_.size());
}

TEST_F(DaemonTest, RequestRestart) {
  Init();

  EXPECT_CALL(*adaptive_charging_controller_, HandleShutdown()).Times(1);

  async_commands_.clear();
  dbus::MethodCall method_call(kPowerManagerInterface, kRequestRestartMethod);
  dbus::MessageWriter message_writer(&method_call);
  message_writer.AppendInt32(REQUEST_RESTART_FOR_UPDATE);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&method_call).get());

  ASSERT_EQ(1, async_commands_.size());
  EXPECT_EQ(base::StringPrintf(
                "%s --action=reboot --shutdown_reason=%s", kSetuidHelperPath,
                ShutdownReasonToString(ShutdownReason::SYSTEM_UPDATE).c_str()),
            async_commands_[0]);
}

TEST_F(DaemonTest, ShutDownForLowBattery) {
  prefs_->SetInt64(kHasKeyboardBacklightPref, 1);
  Init();

  // Keep the display backlight on so we can show a low-battery alert.
  EXPECT_CALL(*internal_backlight_controller_, SetShuttingDown(_)).Times(0);
  EXPECT_CALL(*keyboard_backlight_controller_, SetShuttingDown(true)).Times(1);

  // We shouldn't shut down if the battery isn't below the threshold.
  async_commands_.clear();
  system::PowerStatus status;
  status.battery_is_present = true;
  status.battery_below_shutdown_threshold = false;
  power_supply_->set_status(status);
  power_supply_->NotifyObservers();
  EXPECT_EQ(0, async_commands_.size());

  // Now drop below the threshold.
  async_commands_.clear();
  status.battery_below_shutdown_threshold = true;
  power_supply_->set_status(status);
  power_supply_->NotifyObservers();

  ASSERT_EQ(1, async_commands_.size());
  EXPECT_EQ(GetShutdownCommand(ShutdownReason::LOW_BATTERY),
            async_commands_[0]);
}

TEST_F(DaemonTest, DeferShutdownWhileFlashromRunning) {
  Init();
  async_commands_.clear();

  // The system should stay up if a lockfile exists.
  lockfile_checker_->set_files_to_return(
      {temp_dir_.GetPath().Append("lockfile")});
  dbus::MethodCall method_call(kPowerManagerInterface, kRequestShutdownMethod);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&method_call).get());
  EXPECT_EQ(0, async_commands_.size());

  // It should still be up after the retry timer fires.
  ASSERT_TRUE(daemon_->TriggerRetryShutdownTimerForTesting());
  EXPECT_EQ(0, async_commands_.size());

  // Now remove the lockfile. The next time the timer fires, Daemon should
  // start shutting down.
  lockfile_checker_->set_files_to_return({});
  ASSERT_TRUE(daemon_->TriggerRetryShutdownTimerForTesting());
  ASSERT_EQ(1, async_commands_.size());
  EXPECT_EQ(GetShutdownCommand(ShutdownReason::OTHER_REQUEST_TO_POWERD),
            async_commands_[0]);

  // The timer should've been stopped.
  EXPECT_FALSE(daemon_->TriggerRetryShutdownTimerForTesting());
}

TEST_F(DaemonTest, ForceLidOpenForDockedModeReboot) {
  // During initialization, we should always stop forcing the lid open to
  // undo a force request that might've been sent earlier.
  prefs_->SetInt64(kUseLidPref, 1);
  Init();
  ASSERT_EQ(1, async_commands_.size());
  EXPECT_EQ(kNoForceLidOpenCommand, async_commands_[0]);

  // We should synchronously force the lid open before rebooting.
  async_commands_.clear();
  EnterDockedMode();
  dbus::MethodCall call(kPowerManagerInterface, kRequestRestartMethod);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&call).get());
  ASSERT_EQ(1, sync_commands_.size());
  EXPECT_EQ(kForceLidOpenCommand, sync_commands_[0]);
}

TEST_F(DaemonTest, DontForceLidOpenForDockedModeShutdown) {
  // When shutting down in docked mode, we shouldn't force the lid open.
  prefs_->SetInt64(kUseLidPref, 1);
  Init();
  async_commands_.clear();
  EnterDockedMode();
  dbus::MethodCall call(kPowerManagerInterface, kRequestShutdownMethod);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&call).get());
  EXPECT_EQ(0, sync_commands_.size());
}

TEST_F(DaemonTest, DontForceLidOpenForNormalReboot) {
  // When rebooting outside of docked mode, we shouldn't force the lid open.
  prefs_->SetInt64(kUseLidPref, 1);
  Init();
  dbus::MethodCall call(kPowerManagerInterface, kRequestRestartMethod);
  ASSERT_TRUE(dbus_wrapper_->CallExportedMethodSync(&call).get());
  EXPECT_EQ(0, sync_commands_.size());
}

TEST_F(DaemonTest, DontResetForceLidOpenWhenNotUsingLid) {
  // When starting while configured to not use the lid, powerd shouldn't
  // stop forcing the lid open. This lets developers tell the EC to force
  // the lid open without having powerd continually undo their setting
  // whenever they reboot.
  prefs_->SetInt64(kUseLidPref, 0);
  Init();
  EXPECT_EQ(0, async_commands_.size());
}

TEST_F(DaemonTest, FirstRunAfterBootWhenTrue) {
  const base::FilePath already_ran_path =
      run_dir_.GetPath().Append(Daemon::kAlreadyRanFileName);
  Init();
  EXPECT_TRUE(daemon_->first_run_after_boot_for_testing());
  EXPECT_TRUE(base::PathExists(already_ran_path));
}

TEST_F(DaemonTest, FirstRunAfterBootWhenFalse) {
  const base::FilePath already_ran_path =
      run_dir_.GetPath().Append(Daemon::kAlreadyRanFileName);

  ASSERT_EQ(base::WriteFile(already_ran_path, nullptr, 0), 0);
  Init();
  EXPECT_FALSE(daemon_->first_run_after_boot_for_testing());
  EXPECT_TRUE(base::PathExists(already_ran_path));
}

TEST_F(DaemonTest, SuspendToIdleQuirkPrecedence) {
  // When SuspendToIdle quirk is detected, override pref value.
  // If this test fails, it could be because the suspend_to_idle setting was
  // modified before MachineQuirks prefs were set
  prefs_->SetInt64(kSuspendToIdlePref, 0);
  machine_quirks_->SetSuspendToIdleQuirkDetected(true);
  Init();
  EXPECT_EQ(true, IsSuspendCommandIdle());
}

TEST_F(DaemonTest, NoSuspendToIdleFromQuirk) {
  // When no quirks are detected, MachineQuirks does not write to the
  // SuspendToIdle pref.
  prefs_->SetInt64(kSuspendToIdlePref, 0);
  // Set IsSuspendToIdle to false.
  machine_quirks_->SetSuspendToIdleQuirkDetected(false);
  Init();
  EXPECT_EQ(false, IsSuspendCommandIdle());
}

TEST_F(DaemonTest, FactoryMode) {
  prefs_->SetInt64(kFactoryModePref, 1);
  prefs_->SetInt64(kUseLidPref, 1);
  prefs_->SetInt64(kHasAmbientLightSensorPref, 1);
  prefs_->SetInt64(kHasKeyboardBacklightPref, 1);

  Init();

  // kNoForceLidOpenCommand shouldn't be executed at startup in factory
  // mode.
  EXPECT_EQ(std::vector<std::string>(), async_commands_);

  // Check that Daemon didn't initialize most objects related to adjusting
  // the display or keyboard backlights.
  EXPECT_TRUE(passed_ambient_light_sensor_manager_);
  EXPECT_TRUE(passed_internal_backlight_);
  EXPECT_TRUE(passed_keyboard_backlight_);
  EXPECT_TRUE(passed_external_backlight_controller_);
  EXPECT_TRUE(passed_internal_backlight_controller_);
  EXPECT_TRUE(passed_keyboard_backlight_controller_);

  // The initial display power still needs to be set after Chrome's display
  // service comes up, though: http://b/78436034
  EXPECT_EQ(0, display_power_setter_->num_power_calls());
  dbus_wrapper_->NotifyNameOwnerChanged(chromeos::kDisplayServiceName, "", "1");
  EXPECT_EQ(1, display_power_setter_->num_power_calls());
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_ON, display_power_setter_->state());
  EXPECT_EQ(base::TimeDelta(), display_power_setter_->delay());

  // Display- and keyboard-backlight-related D-Bus methods shouldn't be
  // exported.
  EXPECT_FALSE(dbus_wrapper_->IsMethodExported(kSetScreenBrightnessMethod));
  EXPECT_FALSE(
      dbus_wrapper_->IsMethodExported(kIncreaseScreenBrightnessMethod));
  EXPECT_FALSE(
      dbus_wrapper_->IsMethodExported(kDecreaseScreenBrightnessMethod));
  EXPECT_FALSE(
      dbus_wrapper_->IsMethodExported(kGetScreenBrightnessPercentMethod));
  EXPECT_FALSE(
      dbus_wrapper_->IsMethodExported(kIncreaseKeyboardBrightnessMethod));
  EXPECT_FALSE(
      dbus_wrapper_->IsMethodExported(kDecreaseKeyboardBrightnessMethod));
}

TEST_F(DaemonTest, GetAdaptiveChargingPrediction) {
  Init();

  // Check that the proper DBus method is called for the ML Adaptive Charging
  // Service, and that the
  // `AdaptiveChargingControllerInterface::OnPredictionResponse` function is
  // called, directly or indirectly, by the callback passed to
  // `RequestAdaptiveChargingDecisionAsync`.
  const std::vector<double> result;
  EXPECT_CALL(*adaptive_charging_proxy_, RequestAdaptiveChargingDecisionAsync)
      .WillOnce(
          [&result](
              const std::vector<uint8_t>& proto,
              base::OnceCallback<void(bool, const std::vector<double>&)> cb,
              base::OnceCallback<void(brillo::Error*)> fb,
              int) { std::move(cb).Run(true, result); });
  EXPECT_CALL(*adaptive_charging_controller_,
              OnPredictionResponse(true, result))
      .Times(1);

  assist_ranker::RankerExample proto;
  daemon_->GetAdaptiveChargingPrediction(proto, true);
}

TEST_F(DaemonTest, SetBatterySustain) {
  Init();

  // `Daemon::SetBatterySustain` expects `cros_ec_path_` to already exist.
  EXPECT_EQ(0, base::WriteFile(cros_ec_path_, "", 0));
  // Verify that the ChargeControlSetCommand is Run once and check the Req.
  EXPECT_CALL(*ec_command_factory_, ChargeControlSetCommand)
      .WillOnce([](uint32_t mode, uint8_t lower, uint8_t upper) {
        auto cmd =
            std::make_unique<MockChargeControlSetCommand>(mode, lower, upper);
        EXPECT_EQ(cmd->Req()->mode, CHARGE_CONTROL_NORMAL);
        EXPECT_EQ(cmd->Req()->sustain_soc.lower, 70);
        EXPECT_EQ(cmd->Req()->sustain_soc.upper, 80);
        EXPECT_CALL(*cmd, Run(_)).WillOnce(Return(true));
        return cmd;
      });
  EXPECT_TRUE(daemon_->SetBatterySustain(70, 80));
}

TEST_F(DaemonTest, SetBatteryChargeLimit) {
  Init();

  // `Daemon::SetBatteryChargeLimit` expects `cros_ec_path_` to already exist.
  EXPECT_EQ(0, base::WriteFile(cros_ec_path_, "", 0));

  // Verify that the ChargeCurrentLimitSetCommand is Run once and check the Req.
  EXPECT_CALL(*ec_command_factory_, ChargeCurrentLimitSetCommand)
      .WillOnce([](uint32_t limit_mA) {
        auto cmd = std::make_unique<MockChargeCurrentLimitSetCommand>(limit_mA);
        EXPECT_EQ(cmd->Req()->limit, limit_mA);
        EXPECT_CALL(*cmd, Run(_)).WillOnce(Return(true));
        return cmd;
      });
  EXPECT_TRUE(daemon_->SetBatteryChargeLimit(1000));
}

TEST_F(DaemonTest, PrepareToSuspendAndResume) {
  Sequence s1;
  EXPECT_CALL(*internal_backlight_controller_,
              HandleLidStateChange(LidState::CLOSED))
      .InSequence(s1);
  EXPECT_CALL(*internal_backlight_controller_, SetSuspended(true))
      .InSequence(s1);
  // The following steps in the sequence are to ensure that the lid state is
  // handled before being notified of a resume from suspend.
  EXPECT_CALL(*internal_backlight_controller_,
              HandleLidStateChange(LidState::OPEN))
      .InSequence(s1);
  EXPECT_CALL(*internal_backlight_controller_, SetSuspended(false))
      .InSequence(s1);

  // We require that no ambient light sensor readings are received by the
  // delegate between suspend and resume.
  // If an ALS reading is received before the internal backlight
  // controller gets the lid state open update it would result in the reading
  // being ignored and a later reading being reported in the UMA.
  EXPECT_CALL(*internal_backlight_controller_,
              ReportAmbientLightOnResumeMetrics(_))
      .Times(0);

  // Initial lid state
  input_watcher_->set_lid_state(LidState::OPEN);

  Init();

  input_watcher_->set_lid_state(LidState::CLOSED);
  input_watcher_->NotifyObserversAboutLidState();

  daemon_->PrepareToSuspend();
  EXPECT_TRUE(power_supply_->suspended());

  daemon_->DoSuspend(1, true, base::Milliseconds(0), false);

  input_watcher_->set_lid_state(LidState::OPEN);
  daemon_->UndoPrepareToSuspend(true, 0, false);
  EXPECT_FALSE(power_supply_->suspended());
}

// TODO(chromeos-power): Add more tests. Namely:
// - PrepareToSuspend / UndoPrepareToSuspend
// - Creating and deleting suspend_announced file
// - Handling D-Bus RequestSuspend method calls
// - Reading wakeup_count
// - Fetching TPM counter status from cryptohome
// - Generating suspend IDs
// - Probably other stuff :-/

}  // namespace power_manager
