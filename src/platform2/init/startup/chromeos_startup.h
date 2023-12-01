// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_STARTUP_CHROMEOS_STARTUP_H_
#define INIT_STARTUP_CHROMEOS_STARTUP_H_

#include <memory>
#include <stack>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/values.h>
#include <metrics/bootstat.h>

#include "init/crossystem.h"
#include "init/startup/flags.h"
#include "init/startup/mount_helper.h"
#include "init/startup/platform_impl.h"
#include "init/startup/stateful_mount.h"

namespace startup {

// This is the primary class for the startup functionality, making use of the
// other classes in the startup directory. chromeos_startup sets up different
// mount points, initializes kernel sysctl settings, configures security
// policies sets up the stateful partition, checks if we need a stateful wipe,
// gathers logs and collects crash reports.
class ChromeosStartup {
 public:
  // Process the included USE flags.
  static void ParseFlags(Flags* flags);

  // Constructor for the class
  ChromeosStartup(std::unique_ptr<CrosSystem> cros_system,
                  const Flags& flags,
                  const base::FilePath& root,
                  const base::FilePath& stateful,
                  const base::FilePath& lsb_file,
                  const base::FilePath& proc_file,
                  std::unique_ptr<Platform> platform,
                  std::unique_ptr<MountHelper> mount_helper);

  virtual ~ChromeosStartup() = default;

  // Utility functions that are defined and run when in dev mode.
  // Returns if we are running on a debug build.
  bool DevIsDebugBuild() const;
  // Updated stateful partition if an update is pending.
  bool DevUpdateStatefulPartition(const std::string& args);
  // Gather logs.
  void DevGatherLogs();
  // Updated stateful partition if an update is pending.
  bool DevUpdateStatefulPartition();
  void DevMountPackages(const base::FilePath& device);
  // Restores the paths to preserve from protected path.
  void RestorePreservedPaths();

  // Returns if the TPM is owned or couldn't be determined.
  bool IsTPMOwned();
  // Returns if device needs to clobber even though there's no devmode file
  // present and boot is in verified mode.
  bool NeedsClobberWithoutDevModeFile();
  void Sysctl();
  void ForceCleanFileAttrs(const base::FilePath& path);
  bool IsVarFull();

  // EarlySetup contains the early mount calls of chromeos_startup. This
  // function exists to help break up the Run function into smaller functions.
  void EarlySetup();

  void TmpfilesConfiguration(const std::vector<std::string>& dirs);
  void CreateDaemonStore();
  void RemoveVarEmpty();
  void CheckVarLog();
  void RestoreContextsForVar(
      void (*restorecon_func)(const base::FilePath& path,
                              const std::vector<base::FilePath>& exclude,
                              bool is_recursive,
                              bool set_digests));

  // Run the chromeos startup routine.
  int Run();

 protected:
  // Check whether the device is allowed to boot in dev mode.
  void DevCheckBlockDevMode(const base::FilePath& dev_mode_file) const;

  // Set dev_mode_ for tests.
  void SetDevMode(bool dev_mode);

  // Clean up after a TPM firmware update.
  void CleanupTpm();

  // Move from /var/lib/whitelist to /var/lib/devicesettings.
  void MoveToLibDeviceSettings();

 private:
  friend class DevCheckBlockTest;
  FRIEND_TEST(DevCheckBlockTest, DevSWBoot);
  FRIEND_TEST(DevCheckBlockTest, SysFsVpdSlow);
  FRIEND_TEST(DevCheckBlockTest, CrosSysBlockDev);
  FRIEND_TEST(DevCheckBlockTest, ReadVpdSlowFail);
  FRIEND_TEST(DevCheckBlockTest, ReadVpdSlowPass);

  friend class TpmCleanupTest;
  FRIEND_TEST(TpmCleanupTest, TpmCleanupNoFlagFile);
  FRIEND_TEST(TpmCleanupTest, TpmCleanupNoCmdPath);
  FRIEND_TEST(TpmCleanupTest, TpmCleanupSuccess);

  friend class DeviceSettingsTest;
  FRIEND_TEST(DeviceSettingsTest, OldPathEmpty);
  FRIEND_TEST(DeviceSettingsTest, NewPathEmpty);
  FRIEND_TEST(DeviceSettingsTest, NeitherPathEmpty);

  friend class RestorePreservedPathsTest;
  FRIEND_TEST(RestorePreservedPathsTest, PopPaths);

  void CheckClock();
  // Returns if the device is transitioning between verified boot and
  // dev mode.
  bool IsDevToVerifiedModeTransition(int devsw_boot);

  // Check for whether we need a stateful wipe, and alert the use as
  // necessary.
  void CheckForStatefulWipe();

  // Mount /home.
  void MountHome();

  // Start tpm2-simulator if it exists.
  void StartTpm2Simulator();

  // Runs the bash version of chromeos startup to allow for incremental
  // migration.
  int RunChromeosStartupScript();

  std::unique_ptr<CrosSystem> cros_system_;
  const Flags flags_;
  const base::FilePath lsb_file_;
  const base::FilePath proc_;
  const base::FilePath root_;
  const base::FilePath stateful_;
  bootstat::BootStat bootstat_;
  std::unique_ptr<Platform> platform_;
  std::unique_ptr<MountHelper> mount_helper_;
  bool enable_stateful_security_hardening_;
  std::unique_ptr<StatefulMount> stateful_mount_;
  bool dev_mode_;
  base::FilePath state_dev_;
  base::FilePath dev_mode_allowed_file_;
  base::FilePath dev_image_;
};

}  // namespace startup

#endif  // INIT_STARTUP_CHROMEOS_STARTUP_H_
