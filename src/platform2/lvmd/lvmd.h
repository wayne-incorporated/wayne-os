// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LVMD_LVMD_H_
#define LVMD_LVMD_H_

#include <memory>
#include <string>
#include <utility>

#include <base/cancelable_callback.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/blkdev_utils/lvm.h>
#include <lvmd/proto_bindings/lvmd.pb.h>
#include <sysexits.h>

#include "lvmd/dbus_adaptors/org.chromium.Lvmd.h"

namespace lvmd {

class Lvmd : public brillo::DBusServiceDaemon,
             public org::chromium::LvmdInterface {
 public:
  explicit Lvmd(std::unique_ptr<brillo::LogicalVolumeManager> lvm);
  Lvmd(const Lvmd&) = delete;
  Lvmd& operator=(const Lvmd&) = delete;
  ~Lvmd() = default;

  // org::chromium::LvmdInterface overrides.

  // Returns the physical volumes on device, if it exists.
  bool GetPhysicalVolume(brillo::ErrorPtr* error,
                         const std::string& in_device_path,
                         lvmd::PhysicalVolume* out_physical_volume) override;

  // Returns the volume group on a physical volume, if it exists.
  bool GetVolumeGroup(brillo::ErrorPtr* error,
                      const lvmd::PhysicalVolume& in_physical_volume,
                      lvmd::VolumeGroup* out_volume_group) override;

  // Returns the thinpool on a volume group, if it exists.
  bool GetThinpool(brillo::ErrorPtr* error,
                   const lvmd::VolumeGroup& in_volume_group,
                   const std::string& in_thinpool_name,
                   lvmd::Thinpool* out_thinpool) override;

  // Returns the list of logical volumes, if any exists.
  bool ListLogicalVolumes(
      brillo::ErrorPtr* error,
      const lvmd::VolumeGroup& in_volume_group,
      lvmd::LogicalVolumeList* out_logical_volume_list) override;

  // Returns the logical volume, if it exists.
  bool GetLogicalVolume(brillo::ErrorPtr* error,
                        const lvmd::VolumeGroup& in_volume_group,
                        const std::string& in_logical_volume_name,
                        lvmd::LogicalVolume* out_logical_volume) override;

  // Returns the logical volume created.
  bool CreateLogicalVolume(
      brillo::ErrorPtr* error,
      const lvmd::Thinpool& in_thinpool,
      const lvmd::LogicalVolumeConfiguration& in_logical_volume_configuration,
      lvmd::LogicalVolume* out_logical_volume) override;

  // Removes the logical volume, if it exists.
  bool RemoveLogicalVolume(
      brillo::ErrorPtr* error,
      const lvmd::LogicalVolume& in_logical_volume) override;

  // Toggles the logical volume activation, if it exists.
  // Activating/deactivating already active/inactive logical volume has no
  // effect.
  bool ToggleLogicalVolumeActivation(
      brillo::ErrorPtr* error,
      const lvmd::LogicalVolume& in_logical_volume,
      bool activate) override;

 protected:
  int OnInit() override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;
  void OnShutdown(int* return_code) override;

 private:
  void PostponeShutdown();

  // Daemon will automatically shutdown after this length of idle time.
  static constexpr base::TimeDelta kShutdownTimeout = base::Seconds(30);

  // The shutdown callback so daemon can shutdown.
  base::CancelableRepeatingClosure shutdown_callback_;

  // The brillo library implementation of managing logical volumes.
  std::unique_ptr<brillo::LogicalVolumeManager> lvm_;

  // DBus related members.
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  org::chromium::LvmdAdaptor dbus_adaptor_{this};

  base::WeakPtrFactory<Lvmd> weak_factory_{this};
};

}  // namespace lvmd

#endif  // LVMD_LVMD_H_
