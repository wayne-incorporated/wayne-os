// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_WATCHER_H_
#define POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_WATCHER_H_

#include <string>
#include <vector>

#include <base/compiler_specific.h>
#include <base/files/file_path.h>
#include <base/observer_list.h>
#include <base/timer/timer.h>

#include "power_manager/powerd/system/display/display_info.h"
#include "power_manager/powerd/system/display/display_watcher_observer.h"
#include "power_manager/powerd/system/udev_subsystem_observer.h"

namespace power_manager::system {

struct UdevEvent;
class UdevInterface;

// Watches for displays being connected or disconnected.
class DisplayWatcherInterface {
 public:
  virtual ~DisplayWatcherInterface() = default;

  // Returns the current list of connected displays.
  virtual const std::vector<DisplayInfo>& GetDisplays() const = 0;

  // Adds or removes an observer.
  virtual void AddObserver(DisplayWatcherObserver* observer) = 0;
  virtual void RemoveObserver(DisplayWatcherObserver* observer) = 0;
};

// Real implementation of DisplayWatcherInterface that reports devices from
// /sys.
class DisplayWatcher : public DisplayWatcherInterface,
                       public UdevSubsystemObserver {
 public:
  // Udev subsystems used for display-related changes.
  static const char kI2CUdevSubsystem[];
  static const char kDrmUdevSubsystem[];

  // Filename within a DRM device directory containing the device's hotplug
  // status.
  static const char kDrmStatusFile[];

  // Value in |kDrmStatusFile| indicating that the connector status is
  // connected.
  static const char kDrmStatusConnected[];

  // Value in |kDrmStatusFile| indicating that the connector status is
  // unknown.
  static const char kDrmStatusUnknown[];

  DisplayWatcher() = default;
  DisplayWatcher(const DisplayWatcher&) = delete;
  DisplayWatcher& operator=(const DisplayWatcher&) = delete;

  ~DisplayWatcher() override;

  void set_sysfs_drm_path_for_testing(const base::FilePath& path) {
    sysfs_drm_path_for_testing_ = path;
  }
  void set_i2c_dev_path_for_testing(const base::FilePath& path) {
    i2c_dev_path_for_testing_ = path;
  }

  bool trigger_debounce_timeout_for_testing();

  // Ownership of |udev| remains with the caller.
  void Init(UdevInterface* udev);

  // DisplayWatcherInterface implementation:
  const std::vector<DisplayInfo>& GetDisplays() const override;
  void AddObserver(DisplayWatcherObserver* observer) override;
  void RemoveObserver(DisplayWatcherObserver* observer) override;

  // UdevSubsystemObserver implementation:
  void OnUdevEvent(const UdevEvent& event) override;

 private:
  // Returns the sys path of the parent device of the DRM device.
  base::FilePath GetSysPath(const base::FilePath& drm_dir);

  // Returns the path to the I2C device used for communicating with the display
  // connected to the device described by |drm_dir|. Returns an empty path if
  // the device isn't found.
  base::FilePath GetI2CDevicePath(const base::FilePath& drm_dir);

  // Helper used by GetI2CDevicePath() to locate the I2C device used for DDC/CI
  // communication. Returns an empty path if the device isn't found.
  base::FilePath FindI2CDeviceInDir(const base::FilePath& dir);

  // Invoked by |debounce_timer_| used to delay publishing display changes. This
  // helps aggregating multiple display configuration events when they are
  // reported in short time spans.
  void HandleDebounceTimeout();

  // Scans /sys and updates |displays_|.
  void UpdateDisplays();

  UdevInterface* udev_ = nullptr;  // owned elsewhere

  base::ObserverList<DisplayWatcherObserver> observers_;

  // Currently-connected displays.
  std::vector<DisplayInfo> displays_;

  // Runs HandleDebounceTimeout().
  base::OneShotTimer debounce_timer_;

  // Used instead of the default paths if non-empty.
  base::FilePath sysfs_drm_path_for_testing_;
  base::FilePath i2c_dev_path_for_testing_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_WATCHER_H_
