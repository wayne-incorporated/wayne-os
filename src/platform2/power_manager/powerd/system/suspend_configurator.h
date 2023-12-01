// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_SUSPEND_CONFIGURATOR_H_
#define POWER_MANAGER_POWERD_SYSTEM_SUSPEND_CONFIGURATOR_H_

#include <memory>
#include <string>

#include "power_manager/powerd/system/dbus_wrapper.h"

#include <base/files/file_path.h>
#include <base/time/time.h>
#include <brillo/timers/alarm_timer.h>
#include <featured/feature_library.h>

namespace power_manager {

class PrefsInterface;

namespace system {

class DBusWrapperInterface;

extern const char kCpuInfoPath[];
extern const char kSuspendToHibernateFeatureName[];
extern const char kSnapshotDevicePath[];
extern const char kHibermanExecutablePath[];

// Interface to configure suspend-related kernel parameters on startup or
// before suspend as needed.
class SuspendConfiguratorInterface {
 public:
  SuspendConfiguratorInterface() = default;
  SuspendConfiguratorInterface(const SuspendConfiguratorInterface&) = delete;
  SuspendConfiguratorInterface& operator=(const SuspendConfiguratorInterface&) =
      delete;

  virtual ~SuspendConfiguratorInterface() = default;

  // Do pre-suspend configuration and logging just before asking kernel to
  // suspend.
  virtual void PrepareForSuspend(const base::TimeDelta& suspend_duration) = 0;
  // Do post-suspend work just after resuming from suspend. Returns false if the
  // last suspend was a failure. Returns true otherwise.
  virtual bool UndoPrepareForSuspend() = 0;
  // Check the system to see if hibernate is set up and enabled.
  virtual bool IsHibernateAvailable() = 0;
};

class SuspendConfigurator : public SuspendConfiguratorInterface {
 public:
  // Path to write to enable/disable console during suspend.
  static const base::FilePath kConsoleSuspendPath;

  SuspendConfigurator() = default;
  SuspendConfigurator(const SuspendConfigurator&) = delete;
  SuspendConfigurator& operator=(const SuspendConfigurator&) = delete;

  ~SuspendConfigurator() override = default;

  void Init(feature::PlatformFeaturesInterface* platform_features,
            PrefsInterface* prefs);

  // SuspendConfiguratorInterface implementation.
  void PrepareForSuspend(const base::TimeDelta& suspend_duration) override;
  bool UndoPrepareForSuspend() override;
  bool IsHibernateAvailable() override;
  bool IsHibernateEnabled();

  // Sets a prefix path which is used as file system root when testing.
  // Setting to an empty path removes the prefix.
  void set_prefix_path_for_testing(const base::FilePath& file) {
    prefix_path_for_testing_ = file;
  }

 private:
  // Configures whether console should be enabled/disabled during suspend.
  void ConfigureConsoleForSuspend();

  // Returns true if the serial console is enabled.
  bool IsSerialConsoleEnabled();

  // Get cpu information of the system
  // Reads from /proc/cpuinfo by default
  bool ReadCpuInfo(std::string& cpuInfo);

  // Returns true if running on an Intel CPU.
  bool HasIntelCpu();

  // Returns true if the system supports aeskl (Keylocker).
  bool HasAESKL();

  // Reads preferences and sets |suspend_mode_|.
  void ReadSuspendMode();

  // Returns new FilePath after prepending |prefix_path_for_testing_| to
  // given file path.
  base::FilePath GetPrefixedFilePath(const base::FilePath& file_path) const;

  // Used for communicating with featured.
  feature::PlatformFeaturesInterface* platform_features_ = nullptr;  // unowned
  PrefsInterface* prefs_ = nullptr;                                  // unowned

  // Prefixing all paths for testing with a temp directory. Empty (no
  // prefix) by default.
  base::FilePath prefix_path_for_testing_;

  // Timer to wake the system from suspend. Set when suspend_duration is passed
  // to  PrepareForSuspend().
  std::unique_ptr<brillo::timers::SimpleAlarmTimer> alarm_ =
      brillo::timers::SimpleAlarmTimer::Create();

  // Mode for suspend. One of Suspend-to-idle, Power-on-suspend, or
  // Suspend-to-RAM.
  std::string suspend_mode_;
};

}  // namespace system
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_SYSTEM_SUSPEND_CONFIGURATOR_H_
