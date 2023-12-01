// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdlib>
#include <memory>
#include <string>
#include <utility>

#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <unistd.h>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <base/time/time.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/vcsid.h>
#include <cros_config/cros_config.h>
#include <libec/charge_current_limit_set_command.h>
#include <libec/ec_usb_endpoint.h>
#include <metrics/metrics_library.h>
#include <ml/dbus-proxies.h>

#if USE_IIOSERVICE
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#endif  // USE_IIOSERVICE

#include "power_manager/common/metrics_sender.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/util.h"
#include "power_manager/powerd/daemon.h"
#include "power_manager/powerd/daemon_delegate.h"
#include "power_manager/powerd/policy/external_backlight_controller.h"
#include "power_manager/powerd/policy/internal_backlight_controller.h"
#include "power_manager/powerd/policy/keyboard_backlight_controller.h"
#include "power_manager/powerd/system/acpi_wakeup_helper.h"
#include "power_manager/powerd/system/ambient_light_sensor_interface.h"
#if USE_IIOSERVICE
#include "power_manager/powerd/system/ambient_light_sensor_manager_mojo.h"
#else  // !USE_IIOSERVICE
#include "power_manager/powerd/system/ambient_light_sensor_manager_file.h"
#endif  // USE_IIOSERVICE
#include "power_manager/powerd/system/ambient_light_sensor_manager_interface.h"
#include "power_manager/powerd/system/ambient_light_sensor_watcher_mojo.h"
#include "power_manager/powerd/system/ambient_light_sensor_watcher_udev.h"
#include "power_manager/powerd/system/audio_client.h"
#include "power_manager/powerd/system/cros_ec_helper.h"
#include "power_manager/powerd/system/dark_resume.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/powerd/system/display/display_power_setter.h"
#include "power_manager/powerd/system/display/display_watcher.h"
#include "power_manager/powerd/system/ec_keyboard_backlight.h"
#include "power_manager/powerd/system/event_device.h"
#include "power_manager/powerd/system/external_ambient_light_sensor_factory_file.h"
#include "power_manager/powerd/system/external_ambient_light_sensor_factory_mojo.h"
#include "power_manager/powerd/system/input_watcher.h"
#include "power_manager/powerd/system/internal_backlight.h"
#include "power_manager/powerd/system/lockfile_checker.h"
#include "power_manager/powerd/system/machine_quirks.h"
#include "power_manager/powerd/system/peripheral_battery_watcher.h"
#include "power_manager/powerd/system/pluggable_internal_backlight.h"
#include "power_manager/powerd/system/power_supply.h"
#include "power_manager/powerd/system/sensor_service_handler.h"
#include "power_manager/powerd/system/suspend_configurator.h"
#include "power_manager/powerd/system/suspend_freezer.h"
#include "power_manager/powerd/system/thermal/thermal_device.h"
#include "power_manager/powerd/system/thermal/thermal_device_factory.h"
#include "power_manager/powerd/system/udev.h"
#include "power_manager/powerd/system/user_proximity_watcher.h"
#include "power_manager/powerd/system/wilco_charge_controller_helper.h"

namespace power_manager {

class DaemonDelegateImpl : public DaemonDelegate {
 public:
  DaemonDelegateImpl() = default;
  DaemonDelegateImpl(const DaemonDelegateImpl&) = delete;
  DaemonDelegateImpl& operator=(const DaemonDelegateImpl&) = delete;

  ~DaemonDelegateImpl() override = default;

  // DaemonDelegate:
  std::unique_ptr<PrefsInterface> CreatePrefs() override {
    auto prefs = std::make_unique<Prefs>();
    CHECK(prefs->Init(Prefs::GetDefaultStore(), Prefs::GetDefaultSources()));
    return prefs;
  }

  std::unique_ptr<system::DBusWrapperInterface> CreateDBusWrapper() override {
    auto wrapper = system::DBusWrapper::Create();
    CHECK(wrapper);
    return wrapper;
  }

  std::unique_ptr<system::UdevInterface> CreateUdev() override {
    auto udev = std::make_unique<system::Udev>();
    CHECK(udev->Init());
    return udev;
  }

  std::unique_ptr<system::SensorServiceHandler> CreateSensorServiceHandler()
      override {
    return std::make_unique<system::SensorServiceHandler>();
  }

  std::unique_ptr<system::AmbientLightSensorManagerInterface>
  CreateAmbientLightSensorManager(
      PrefsInterface* prefs,
      system::SensorServiceHandler* sensor_service_handler) override {
#if USE_IIOSERVICE
    auto light_sensor_manager =
        std::make_unique<system::AmbientLightSensorManagerMojo>(
            prefs, sensor_service_handler);
#else   // !USE_IIOSERVICE
    auto light_sensor_manager =
        std::make_unique<system::AmbientLightSensorManagerFile>(prefs);
    light_sensor_manager->Run(false /* read_immediately */);
#endif  // USE_IIOSERVICE
    return light_sensor_manager;
  }

  std::unique_ptr<system::AmbientLightSensorWatcherInterface>
  CreateAmbientLightSensorWatcher(system::UdevInterface* udev) override {
    auto watcher = std::make_unique<system::AmbientLightSensorWatcherUdev>();
    watcher->Init(udev);
    return watcher;
  }
  std::unique_ptr<system::AmbientLightSensorWatcherInterface>
  CreateAmbientLightSensorWatcher(
      system::SensorServiceHandler* sensor_service_handler) override {
    return std::make_unique<system::AmbientLightSensorWatcherMojo>(
        sensor_service_handler);
  }

  std::unique_ptr<system::ExternalAmbientLightSensorFactoryInterface>
  CreateExternalAmbientLightSensorFactory() override {
    return std::make_unique<system::ExternalAmbientLightSensorFactoryFile>();
  }
  std::unique_ptr<system::ExternalAmbientLightSensorFactoryInterface>
  CreateExternalAmbientLightSensorFactory(
      system::AmbientLightSensorWatcherMojo* watcher) override {
    return std::make_unique<system::ExternalAmbientLightSensorFactoryMojo>(
        watcher);
  }

  std::unique_ptr<system::DisplayWatcherInterface> CreateDisplayWatcher(
      system::UdevInterface* udev) override {
    auto watcher = std::make_unique<system::DisplayWatcher>();
    watcher->Init(udev);
    return watcher;
  }

  std::unique_ptr<system::DisplayPowerSetterInterface> CreateDisplayPowerSetter(
      system::DBusWrapperInterface* dbus_wrapper) override {
    auto setter = std::make_unique<system::DisplayPowerSetter>();
    setter->Init(dbus_wrapper);
    return setter;
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
    auto controller = std::make_unique<policy::ExternalBacklightController>();
    controller->Init(prefs, ambient_light_sensor_watcher,
                     external_ambient_light_sensor_factory, display_watcher,
                     display_power_setter, dbus_wrapper);
    return controller;
  }

  std::unique_ptr<system::BacklightInterface> CreateInternalBacklight(
      const base::FilePath& base_path, const std::string& pattern) override {
    auto backlight = std::make_unique<system::InternalBacklight>();
    return backlight->Init(base_path, pattern)
               ? std::move(backlight)
               : std::unique_ptr<system::BacklightInterface>();
  }

  std::unique_ptr<system::BacklightInterface> CreatePluggableInternalBacklight(
      system::UdevInterface* udev,
      const std::string& udev_subsystem,
      const base::FilePath& base_path,
      const std::string& pattern) override {
    auto backlight = std::make_unique<system::PluggableInternalBacklight>();
    backlight->Init(udev, udev_subsystem, base_path, pattern);
    return backlight;
  }

  std::unique_ptr<ec::EcCommandFactoryInterface> CreateEcCommandFactory()
      override {
    return std::make_unique<ec::EcCommandFactory>();
  }

  std::unique_ptr<ec::EcUsbEndpointInterface> CreateEcUsbEndpoint() override {
    auto endpoint = std::make_unique<ec::EcUsbEndpoint>();
    return endpoint->Init(ec::kUsbVidGoogle, ec::kUsbPidCrosEc)
               ? std::move(endpoint)
               : std::unique_ptr<ec::EcUsbEndpoint>();
  }

  std::unique_ptr<system::BacklightInterface> CreateEcKeyboardBacklight(
      ec::EcUsbEndpointInterface* endpoint) override {
    auto backlight = std::make_unique<system::EcKeyboardBacklight>();
    return backlight->Init(endpoint) ? std::move(backlight) : nullptr;
  }

  std::unique_ptr<policy::BacklightController>
  CreateInternalBacklightController(
      system::BacklightInterface* backlight,
      PrefsInterface* prefs,
      system::AmbientLightSensorInterface* sensor,
      system::DisplayPowerSetterInterface* power_setter,
      system::DBusWrapperInterface* dbus_wrapper,
      LidState initial_lid_state) override {
    auto controller = std::make_unique<policy::InternalBacklightController>();
    controller->Init(backlight, prefs, sensor, power_setter, dbus_wrapper,
                     initial_lid_state);
    return controller;
  }

  std::unique_ptr<policy::BacklightController>
  CreateKeyboardBacklightController(system::BacklightInterface* backlight,
                                    PrefsInterface* prefs,
                                    system::AmbientLightSensorInterface* sensor,
                                    system::DBusWrapperInterface* dbus_wrapper,
                                    LidState initial_lid_state,
                                    TabletMode initial_tablet_mode) override {
    auto controller = std::make_unique<policy::KeyboardBacklightController>();
    controller->Init(backlight, prefs, sensor, dbus_wrapper, initial_lid_state,
                     initial_tablet_mode);
    return controller;
  }

  std::unique_ptr<system::InputWatcherInterface> CreateInputWatcher(
      PrefsInterface* prefs, system::UdevInterface* udev) override {
    auto watcher = std::make_unique<system::InputWatcher>();
    CHECK(watcher->Init(std::unique_ptr<system::EventDeviceFactoryInterface>(
                            new system::EventDeviceFactory),
                        prefs, udev));
    return watcher;
  }

  std::unique_ptr<system::AcpiWakeupHelperInterface> CreateAcpiWakeupHelper()
      override {
    return std::make_unique<system::AcpiWakeupHelper>();
  }

  std::unique_ptr<system::CrosEcHelperInterface> CreateCrosEcHelper() override {
    return std::make_unique<system::CrosEcHelper>();
  }

  std::unique_ptr<system::PeripheralBatteryWatcher>
  CreatePeripheralBatteryWatcher(system::DBusWrapperInterface* dbus_wrapper,
                                 system::UdevInterface* udev) override {
    auto watcher = std::make_unique<system::PeripheralBatteryWatcher>();
    watcher->Init(dbus_wrapper, udev);
    return watcher;
  }

  std::unique_ptr<system::PowerSupplyInterface> CreatePowerSupply(
      const base::FilePath& power_supply_path,
      const base::FilePath& cros_ec_path,
      ec::EcCommandFactoryInterface* ec_command_factory,
      PrefsInterface* prefs,
      system::UdevInterface* udev,
      system::DBusWrapperInterface* dbus_wrapper,
      BatteryPercentageConverter* battery_percentage_converter) override {
    auto supply = std::make_unique<system::PowerSupply>();
    supply->Init(power_supply_path, cros_ec_path, ec_command_factory, prefs,
                 udev, dbus_wrapper, battery_percentage_converter);
    return supply;
  }

  std::unique_ptr<system::UserProximityWatcherInterface>
  CreateUserProximityWatcher(PrefsInterface* prefs,
                             system::UdevInterface* udev,
                             TabletMode initial_tablet_mode) override {
    auto watcher = std::make_unique<system::UserProximityWatcher>();
    auto config = std::make_unique<brillo::CrosConfig>();
    watcher->Init(prefs, udev, std::move(config), initial_tablet_mode);
    return watcher;
  }

  std::unique_ptr<system::DarkResumeInterface> CreateDarkResume(
      PrefsInterface* prefs,
      system::WakeupSourceIdentifierInterface* wakeup_source_identifier)
      override {
    auto dark_resume = std::make_unique<system::DarkResume>();
    dark_resume->Init(prefs, wakeup_source_identifier);
    return dark_resume;
  }

  std::unique_ptr<system::AudioClientInterface> CreateAudioClient(
      system::DBusWrapperInterface* dbus_wrapper,
      const base::FilePath& run_dir) override {
    auto client = std::make_unique<system::AudioClient>();
    client->Init(dbus_wrapper, run_dir);
    return client;
  }

  std::unique_ptr<system::LockfileCheckerInterface> CreateLockfileChecker(
      const base::FilePath& dir,
      const std::vector<base::FilePath>& files) override {
    return std::make_unique<system::LockfileChecker>(dir, files);
  }

  std::unique_ptr<system::MachineQuirksInterface> CreateMachineQuirks(
      PrefsInterface* prefs) override {
    auto machine_quirks = std::make_unique<system::MachineQuirks>();
    machine_quirks->Init(prefs);
    return machine_quirks;
  }

  feature::PlatformFeaturesInterface* CreatePlatformFeatures(
      system::DBusWrapperInterface* dbus_wrapper) override {
    if (!feature::PlatformFeatures::Initialize(dbus_wrapper->GetBus())) {
      return nullptr;
    }
    return feature::PlatformFeatures::Get();
  }

  std::unique_ptr<MetricsSenderInterface> CreateMetricsSender() override {
    return std::make_unique<MetricsSender>(metrics_library_);
  }

  std::unique_ptr<system::ChargeControllerHelperInterface>
  CreateChargeControllerHelper() override {
    return std::make_unique<system::WilcoChargeControllerHelper>();
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
    auto adaptive = std::make_unique<policy::AdaptiveChargingController>();
    adaptive->Init(delegate, backlight_controller, input_watcher, power_supply,
                   dbus_wrapper, platform_features, prefs);
    return adaptive;
  }

  std::unique_ptr<
      org::chromium::MachineLearning::AdaptiveChargingProxyInterface>
  CreateAdaptiveChargingProxy(const scoped_refptr<dbus::Bus>& bus) override {
    return std::make_unique<
        org::chromium::MachineLearning::AdaptiveChargingProxy>(
        bus, ml::kMachineLearningAdaptiveChargingServiceName);
  }

  std::unique_ptr<system::SuspendConfiguratorInterface>
  CreateSuspendConfigurator(
      feature::PlatformFeaturesInterface* platform_features,
      PrefsInterface* prefs) override {
    auto suspend_configurator = std::make_unique<system::SuspendConfigurator>();
    suspend_configurator->Init(platform_features, prefs);
    return suspend_configurator;
  }

  std::unique_ptr<system::SuspendFreezerInterface> CreateSuspendFreezer(
      PrefsInterface* prefs) override {
    auto suspend_freezer = std::make_unique<system::SuspendFreezer>();
    suspend_freezer->Init(prefs);
    return suspend_freezer;
  }

  std::vector<std::unique_ptr<system::ThermalDeviceInterface>>
  CreateThermalDevices() override {
    return system::ThermalDeviceFactory::CreateThermalDevices();
  }

  pid_t GetPid() override { return getpid(); }

  void Launch(const std::string& command) override {
    LOG(INFO) << "Launching \"" << command << "\"";
    pid_t pid = fork();
    if (pid == 0) {
      setsid();
      // fork() again and exit so that init becomes the command's parent and
      // cleans up when it finally finishes.
      exit(fork() == 0 ? ::system(command.c_str()) : 0);
    } else if (pid > 0) {
      // powerd cleans up after the originally-forked process, which exits
      // immediately after forking again.
      if (waitpid(pid, nullptr, 0) == -1)
        PLOG(ERROR) << "waitpid() on PID " << pid << " failed";
    } else if (pid == -1) {
      PLOG(ERROR) << "fork() failed";
    }
  }

  int Run(const std::string& command) override {
    LOG(INFO) << "Running \"" << command << "\"";
    int return_value = ::system(command.c_str());
    int exit_status = WEXITSTATUS(return_value);
    if (return_value == -1) {
      PLOG(ERROR) << "fork() failed";
      return return_value;
    } else if (exit_status) {
      LOG(ERROR) << "Command failed with exit status " << exit_status;
    }
    return exit_status;
  }

 private:
  MetricsLibrary metrics_library_;
  base::FilePath read_write_prefs_dir_;
  base::FilePath read_only_prefs_dir_;
};

}  // namespace power_manager

int main(int argc, char* argv[]) {
  DEFINE_string(log_dir, "", "Directory where logs are written.");
  DEFINE_string(run_dir, "", "Directory where stateful data is written.");
  // This flag is handled by libbase/libchrome's logging library instead of
  // directly by powerd, but it is defined here so FlagHelper won't abort after
  // seeing an unexpected flag.
  DEFINE_string(vmodule, "",
                "Per-module verbose logging levels, e.g. \"foo=1,bar=2\"");

  brillo::FlagHelper::Init(argc, argv,
                           "powerd, the Chromium OS userspace power manager.");

  CHECK(!FLAGS_log_dir.empty()) << "--log_dir is required";
  CHECK(!FLAGS_run_dir.empty()) << "--run_dir is required";

  const base::FilePath log_file =
      base::FilePath(FLAGS_log_dir)
          .Append(base::StringPrintf(
              "powerd.%s",
              brillo::GetTimeAsLogString(base::Time::Now()).c_str()));
  brillo::UpdateLogSymlinks(
      base::FilePath(FLAGS_log_dir).Append("powerd.LATEST"),
      base::FilePath(FLAGS_log_dir).Append("powerd.PREVIOUS"), log_file);

  logging::LoggingSettings logging_settings;
  logging_settings.logging_dest = logging::LOG_TO_FILE;
  logging_settings.log_file_path = log_file.value().c_str();
  logging_settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  logging::InitLogging(logging_settings);
  LOG(INFO) << "vcsid " << brillo::kShortVCSID.value_or("<not set>");

  // Make it easier to tell if the system just booted, which is useful to know
  // when reading logs from bug reports.
  struct sysinfo info;
  if (sysinfo(&info) == 0) {
    LOG(INFO) << "System uptime: "
              << power_manager::util::TimeDeltaToString(
                     base::Seconds(info.uptime));
  } else {
    PLOG(ERROR) << "sysinfo() failed";
  }

  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  // This is used in AlarmTimer.
  base::FileDescriptorWatcher watcher{task_executor.task_runner()};

#if USE_IIOSERVICE
  mojo::core::Init();
  mojo::core::ScopedIPCSupport ipc_support(
      task_executor.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);
#endif  // USE_IIOSERVICE

  power_manager::DaemonDelegateImpl delegate;
  // Extra parens to avoid http://en.wikipedia.org/wiki/Most_vexing_parse.
  power_manager::Daemon daemon(&delegate, (base::FilePath(FLAGS_run_dir)));
  daemon.Init();

  base::RunLoop().Run();
  return 0;
}
