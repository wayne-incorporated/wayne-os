// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_UDEV_MONITOR_H_
#define TYPECD_UDEV_MONITOR_H_

#include <libudev.h>

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>
#include <brillo/udev/mock_udev.h>
#include <gtest/gtest_prod.h>

namespace typecd {

constexpr char kPartnerRegex[] = R"(port(\d+)-partner)";
constexpr char kTypeCSubsystem[] = "typec";
constexpr char kUdevMonitorName[] = "udev";
constexpr char kUsbPdSubsystem[] = "usb_power_delivery";

// Class to monitor udev events on the Type C subsystem and inform other
// objects / classes of these events.
class UdevMonitor {
 public:
  UdevMonitor() = default;

  // Create a Udev device for enumeration and monitoring.
  bool InitUdev();

  // Enumerate all existing events/devices, and send the appropriate
  // notifications to other classes.
  bool ScanDevices();

  // Start monitoring udev for typec and usb events.
  bool BeginMonitoring();

  class TypecObserver : public base::CheckedObserver {
   public:
    virtual ~TypecObserver() {}
    // Callback that is executed when a port is connected or disconnected.
    //
    // The |path| argument refers to the sysfs device path of the port.
    // The |port_num| argmnet refers to the port's index number.
    // The |added| argument is set to true if the port was added, and false
    // otherwise.
    virtual void OnPortAddedOrRemoved(const base::FilePath& path,
                                      int port_num,
                                      bool added) = 0;

    // Callback that is executed when a port partner is connected or
    // disconnected.
    //
    // The |path| argument refers to the sysfs device path of the port partner.
    // The |port_num| argument refers to the port's index number.
    // The |added| argument is set to true if the partner was added, and false
    // otherwise.
    virtual void OnPartnerAddedOrRemoved(const base::FilePath& path,
                                         int port_num,
                                         bool added,
                                         bool is_hotplug) = 0;

    // Callback that is executed when a port partner alt mode is registered or
    // removed.
    //
    // The |path| argument refers to the sysfs device path of the partner alt
    // mode. The |port_num| argmnet refers to the port's index number. The
    // |added| argument is set to true if the alt mode was added, and false
    // otherwise.
    virtual void OnPartnerAltModeAddedOrRemoved(const base::FilePath& path,
                                                int port_num,
                                                bool added) = 0;

    // Callback that is executed when a port cable is connected or
    // disconnected.
    //
    // The |path| argument refers to the sysfs device path of the port cable.
    // The |port_num| argument refers to the port's index number.
    // The |added| argument is set to true if the cable was added, and false
    // otherwise.
    virtual void OnCableAddedOrRemoved(const base::FilePath& path,
                                       int port_num,
                                       bool added) = 0;

    // Callback that is executed when a cable plug (SOP') device is registered.
    //
    // The |path| argument refers to the sysfs device path of the cable plug
    // (SOP'). The |port_num| argument refers to the port's index number.
    virtual void OnCablePlugAdded(const base::FilePath& path, int port_num) = 0;

    // Callback that is executed when a cable (SOP') alternate mode is
    // registered.
    //
    // The |path| argument refers to the sysfs device path of the cable (SOP')
    // alternate mode. The |port_num| argument refers to the port's index
    // number.
    virtual void OnCableAltModeAdded(const base::FilePath& path,
                                     int port_num) = 0;

    // Callback that is executed when a USB PD device is registered or removed.
    //
    // The |path| argument refers to the sysfs path of the PD object.
    virtual void OnPdDeviceAddedOrRemoved(const base::FilePath& path,
                                          bool added) = 0;

    // Callback that is executed when a partner "change" event is received.
    //
    // The |port_num| argument refers to the port's index number.
    virtual void OnPartnerChanged(int port_num) = 0;

    // Callback that is executed when a port "change" event is received.
    //
    // The |port_num| argument refers to the port's index number.
    virtual void OnPortChanged(int port_num) = 0;
  };

  void AddTypecObserver(TypecObserver* obs);
  void RemoveTypecObserver(TypecObserver* obs);

 private:
  friend class UdevMonitorTest;
  friend class UdevMonitorFuzzer;
  FRIEND_TEST(UdevMonitorTest, Basic);
  FRIEND_TEST(UdevMonitorTest, Hotplug);
  FRIEND_TEST(UdevMonitorTest, InvalidPortSyspath);
  FRIEND_TEST(UdevMonitorTest, CableAndAltModeAddition);
  FRIEND_TEST(UdevMonitorTest, PartnerChanged);
  FRIEND_TEST(UdevMonitorTest, PortChanged);
  FRIEND_TEST(UdevMonitorTest, PdDevice);

  // Set the |udev_| pointer to a MockUdev device. *Only* used by unit tests.
  void SetUdev(std::unique_ptr<brillo::MockUdev> udev) {
    udev_ = std::move(udev);
  }

  // Handle a udev event which causes a Type C device and/or USB device to be
  // added/removed.
  bool HandleDeviceAddedRemoved(const base::FilePath& path,
                                bool added,
                                bool is_initial_scan = false);

  // Handle a udev "change" event for a Type C device.
  void HandleDeviceChange(const base::FilePath& path);

  // Handle Udev events emanating from |udev_monitor_watcher_|.
  void HandleUdevEvent();

  std::unique_ptr<brillo::Udev> udev_;
  std::unique_ptr<brillo::UdevMonitor> udev_monitor_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller>
      udev_monitor_watcher_;
  base::ObserverList<TypecObserver> typec_observer_list_;
};

}  // namespace typecd

#endif  // TYPECD_UDEV_MONITOR_H_
