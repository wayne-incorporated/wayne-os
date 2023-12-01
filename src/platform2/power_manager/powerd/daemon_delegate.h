// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_DAEMON_DELEGATE_H_
#define POWER_MANAGER_POWERD_DAEMON_DELEGATE_H_

#include <sys/types.h>

#include <memory>
#include <string>
#include <vector>

#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/adaptive_charging_controller.h"
#include "power_manager/powerd/system/cros_ec_helper_interface.h"
#include "power_manager/powerd/system/suspend_freezer.h"

#include <base/files/file_path.h>
#include <dbus/bus.h>
#include <featured/feature_library.h>
#include <libec/charge_control_set_command.h>
#include <libec/charge_current_limit_set_command.h>
#include <libec/ec_usb_endpoint.h>
#include <ml/dbus-proxies.h>

namespace power_manager {

namespace policy {
class BacklightController;
}  // namespace policy

namespace system {
class AcpiWakeupHelperInterface;
class AmbientLightSensorInterface;
class AmbientLightSensorManagerInterface;
class AmbientLightSensorWatcherInterface;
class AmbientLightSensorWatcherMojo;
class AudioClientInterface;
class BacklightInterface;
class ChargeControllerHelperInterface;
class DarkResumeInterface;
class DBusWrapperInterface;
class DisplayPowerSetterInterface;
class DisplayWatcherInterface;
class EcHelperInterface;
class ExternalAmbientLightSensorFactoryInterface;
class InputWatcherInterface;
class LockfileCheckerInterface;
class MachineQuirksInterface;
class PeripheralBatteryWatcher;
class PowerSupplyInterface;
class SensorServiceHandler;
class SuspendConfiguratorInterface;
class ThermalDeviceInterface;
class UdevInterface;
class UserProximityWatcherInterface;
class WakeupSourceIdentifierInterface;
}  // namespace system

class MetricsSenderInterface;
class PrefsInterface;

// Delegate class implementing functionality on behalf of the Daemon class.
// Create*() methods perform any necessary initialization of the returned
// objects.
class DaemonDelegate {
 public:
  DaemonDelegate() = default;
  DaemonDelegate(const DaemonDelegate&) = delete;
  DaemonDelegate& operator=(const DaemonDelegate&) = delete;

  virtual ~DaemonDelegate() = default;

  // Crashes if prefs can't be loaded (e.g. due to a missing directory).
  virtual std::unique_ptr<PrefsInterface> CreatePrefs() = 0;

  // Crashes if the connection to the system bus fails.
  virtual std::unique_ptr<system::DBusWrapperInterface> CreateDBusWrapper() = 0;

  // Crashes if udev initialization fails.
  virtual std::unique_ptr<system::UdevInterface> CreateUdev() = 0;

  virtual std::unique_ptr<system::SensorServiceHandler>
  CreateSensorServiceHandler() = 0;
  virtual std::unique_ptr<system::AmbientLightSensorManagerInterface>
  CreateAmbientLightSensorManager(
      PrefsInterface* prefs,
      system::SensorServiceHandler* sensor_service_handler) = 0;

  virtual std::unique_ptr<system::AmbientLightSensorWatcherInterface>
  CreateAmbientLightSensorWatcher(system::UdevInterface* udev) = 0;
  virtual std::unique_ptr<system::AmbientLightSensorWatcherInterface>
  CreateAmbientLightSensorWatcher(
      system::SensorServiceHandler* sensor_service_handler) = 0;

  virtual std::unique_ptr<system::ExternalAmbientLightSensorFactoryInterface>
  CreateExternalAmbientLightSensorFactory() = 0;
  virtual std::unique_ptr<system::ExternalAmbientLightSensorFactoryInterface>
  CreateExternalAmbientLightSensorFactory(
      system::AmbientLightSensorWatcherMojo* watcher) = 0;

  virtual std::unique_ptr<system::DisplayWatcherInterface> CreateDisplayWatcher(
      system::UdevInterface* udev) = 0;

  virtual std::unique_ptr<system::DisplayPowerSetterInterface>
  CreateDisplayPowerSetter(system::DBusWrapperInterface* dbus_wrapper) = 0;

  virtual std::unique_ptr<policy::BacklightController>
  CreateExternalBacklightController(
      PrefsInterface* prefs,
      system::AmbientLightSensorWatcherInterface* ambient_light_sensor_watcher,
      system::ExternalAmbientLightSensorFactoryInterface*
          external_ambient_light_sensor_factory,
      system::DisplayWatcherInterface* display_watcher,
      system::DisplayPowerSetterInterface* display_power_setter,
      system::DBusWrapperInterface* dbus_wrapper) = 0;

  // Returns null if the backlight couldn't be initialized.
  virtual std::unique_ptr<system::BacklightInterface> CreateInternalBacklight(
      const base::FilePath& base_path, const std::string& pattern) = 0;

  virtual std::unique_ptr<system::BacklightInterface>
  CreatePluggableInternalBacklight(system::UdevInterface* udev,
                                   const std::string& udev_subsystem,
                                   const base::FilePath& base_path,
                                   const std::string& pattern) = 0;

  virtual std::unique_ptr<ec::EcCommandFactoryInterface>
  CreateEcCommandFactory() = 0;

  virtual std::unique_ptr<ec::EcUsbEndpointInterface> CreateEcUsbEndpoint() = 0;

  virtual std::unique_ptr<system::BacklightInterface> CreateEcKeyboardBacklight(
      ec::EcUsbEndpointInterface* endpoint) = 0;

  virtual std::unique_ptr<policy::BacklightController>
  CreateInternalBacklightController(
      system::BacklightInterface* backlight,
      PrefsInterface* prefs,
      system::AmbientLightSensorInterface* sensor,
      system::DisplayPowerSetterInterface* power_setter,
      system::DBusWrapperInterface* dbus_wrapper,
      LidState initial_lid_state) = 0;

  virtual std::unique_ptr<policy::BacklightController>
  CreateKeyboardBacklightController(system::BacklightInterface* backlight,
                                    PrefsInterface* prefs,
                                    system::AmbientLightSensorInterface* sensor,
                                    system::DBusWrapperInterface* dbus_wrapper,
                                    LidState initial_lid_state,
                                    TabletMode initial_tablet_mode) = 0;

  virtual std::unique_ptr<system::InputWatcherInterface> CreateInputWatcher(
      PrefsInterface* prefs, system::UdevInterface* udev) = 0;

  virtual std::unique_ptr<system::AcpiWakeupHelperInterface>
  CreateAcpiWakeupHelper() = 0;

  virtual std::unique_ptr<system::CrosEcHelperInterface>
  CreateCrosEcHelper() = 0;

  // Test implementations may return null.
  virtual std::unique_ptr<system::PeripheralBatteryWatcher>
  CreatePeripheralBatteryWatcher(system::DBusWrapperInterface* dbus_wrapper,
                                 system::UdevInterface* udev) = 0;

  virtual std::unique_ptr<system::PowerSupplyInterface> CreatePowerSupply(
      const base::FilePath& power_supply_path,
      const base::FilePath& cros_ec_path,
      ec::EcCommandFactoryInterface* ec_command_factory,
      PrefsInterface* prefs,
      system::UdevInterface* udev,
      system::DBusWrapperInterface* dbus_wrapper,
      BatteryPercentageConverter* battery_percentage_converter) = 0;

  virtual std::unique_ptr<system::UserProximityWatcherInterface>
  CreateUserProximityWatcher(PrefsInterface* prefs,
                             system::UdevInterface* udev,
                             TabletMode initial_tablet_mode) = 0;

  virtual std::unique_ptr<system::DarkResumeInterface> CreateDarkResume(
      PrefsInterface* prefs,
      system::WakeupSourceIdentifierInterface* wakeup_source_identifier) = 0;

  virtual std::unique_ptr<system::AudioClientInterface> CreateAudioClient(
      system::DBusWrapperInterface* dbus_wrapper,
      const base::FilePath& run_dir) = 0;

  virtual std::unique_ptr<system::LockfileCheckerInterface>
  CreateLockfileChecker(const base::FilePath& dir,
                        const std::vector<base::FilePath>& files) = 0;

  virtual std::unique_ptr<system::MachineQuirksInterface> CreateMachineQuirks(
      PrefsInterface* prefs) = 0;

  virtual feature::PlatformFeaturesInterface* CreatePlatformFeatures(
      system::DBusWrapperInterface* dbus_wrapper) = 0;
  virtual std::unique_ptr<MetricsSenderInterface> CreateMetricsSender() = 0;

  virtual std::unique_ptr<system::ChargeControllerHelperInterface>
  CreateChargeControllerHelper() = 0;

  virtual std::unique_ptr<policy::AdaptiveChargingControllerInterface>
  CreateAdaptiveChargingController(
      policy::AdaptiveChargingControllerInterface::Delegate* delegate,
      policy::BacklightController* backlight_controller,
      system::InputWatcherInterface* input_watcher,
      system::PowerSupplyInterface* power_supply,
      system::DBusWrapperInterface* dbus_wrapper,
      feature::PlatformFeaturesInterface* platform_features,
      PrefsInterface* prefs) = 0;

  virtual std::unique_ptr<
      org::chromium::MachineLearning::AdaptiveChargingProxyInterface>
  CreateAdaptiveChargingProxy(const scoped_refptr<dbus::Bus>& bus) = 0;

  virtual std::unique_ptr<system::SuspendConfiguratorInterface>
  CreateSuspendConfigurator(
      feature::PlatformFeaturesInterface* platform_features,
      PrefsInterface* prefs) = 0;

  virtual std::unique_ptr<system::SuspendFreezerInterface> CreateSuspendFreezer(
      PrefsInterface* prefs) = 0;

  virtual std::vector<std::unique_ptr<system::ThermalDeviceInterface>>
  CreateThermalDevices() = 0;

  // Returns the process's PID.
  virtual pid_t GetPid() = 0;

  // Runs |command| asynchronously.
  virtual void Launch(const std::string& command) = 0;

  // Runs |command| synchronously.  The process's exit code is returned.
  virtual int Run(const std::string& command) = 0;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_DAEMON_DELEGATE_H_
