// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_PORT_MANAGER_H_
#define TYPECD_PORT_MANAGER_H_

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <gtest/gtest_prod.h>

#include "typecd/chrome_features_service_client.h"
#include "typecd/dbus_manager.h"
#include "typecd/ec_util.h"
#include "typecd/metrics.h"
#include "typecd/port.h"
#include "typecd/session_manager_observer_interface.h"
#include "typecd/udev_monitor.h"

namespace typecd {

// PortManager and DBusManager classes include pointers to each other.
// Forward declare DBusManager to resolve dependencies during compilation.
class DBusManager;

// This class is used to manage Type C ports and related state. Its role is to
// provide the daemon with an accurate view of the Type C state (after reading
// from the Type C connector class framework sysfs files), as well as provide a
// means to change this state according to policy defined in the daemon.
class PortManager : public UdevMonitor::TypecObserver,
                    public SessionManagerObserverInterface {
 public:
  PortManager();
  PortManager(const PortManager&) = delete;
  PortManager& operator=(const PortManager&) = delete;

  void SetECUtil(ECUtil* ec_util) { ec_util_ = ec_util; }

  bool GetModeEntrySupported() { return mode_entry_supported_; }
  void SetModeEntrySupported(bool supported);

  bool GetUserActive() { return user_active_; }
  void SetUserActive(bool active) { user_active_ = active; }

  void SetDBusManager(DBusManager* mgr) { dbus_mgr_ = mgr; }

  void SetMetrics(Metrics* metrics) { metrics_ = metrics; }

  void SetFeaturesClient(ChromeFeaturesServiceClient* client) {
    features_client_ = client;
  }

  void SetSupportsUSB4(bool enable) { supports_usb4_ = enable; }

  void SetPortsUsingDisplays(const std::vector<uint32_t>& port_nums);

 protected:
  bool GetPeripheralDataAccess() { return peripheral_data_access_; }
  void SetPeripheralDataAccess(bool val) { peripheral_data_access_ = val; }

 private:
  friend class PortManagerFuzzer;
  friend class PortManagerTest;
  FRIEND_TEST(PortManagerTest, ModeEntryNotSupported);
  FRIEND_TEST(PortManagerTest, SimpleModeEntry);
  FRIEND_TEST(PortManagerTest, ModeSwitchUnlockDPandTBT);
  FRIEND_TEST(PortManagerTest, ModeSwitchUnlockUSB4);
  FRIEND_TEST(PortManagerTest, ModeSwitchSessionStoppedDPandTBT);
  FRIEND_TEST(PortManagerTest, ModeSwitchSessionStoppedTBT);
  FRIEND_TEST(PortManagerTest, ModeSwitchUnlockDPAndTBTNoPeripheralAccess);
  FRIEND_TEST(PortManagerTest, ModeSwitchDPandTBTPeripheralDataAccessChanging);
  FRIEND_TEST(PortManagerTest,
              ModeSwitchDPandTBTPeripheralDataAccessChangingLockUnlock);
  FRIEND_TEST(PortManagerTest, ModeSwitchTBTPeripheralDataAccessChanging);
  FRIEND_TEST(PortManagerTest, ModeEntryDPOnlySystem);
  FRIEND_TEST(PortManagerTest, MetricsReportingWaitsForPD);
  FRIEND_TEST(PortManagerTest, MetricsReportingOnMultiplePorts);
  FRIEND_TEST(PortManagerTest, MetricsReportingCancelled);
  FRIEND_TEST(PortManagerTest, PartnerPdDeviceAddRemove);
  FRIEND_TEST(PortManagerTest, RunModeEntryOnceEnabled);
  FRIEND_TEST(PortManagerNotificationTest, ModeEntryUSB4NotifyThunderboltDp);
  FRIEND_TEST(PortManagerNotificationTest, ModeEntryTBTNotifyThunderboltOnly);
  FRIEND_TEST(PortManagerNotificationTest, ModeEntryDpAltModeNoNotifications);
  FRIEND_TEST(PortManagerNotificationTest,
              ModeEntryUSB4NotifySpeedLimitingCable);
  FRIEND_TEST(PortManagerNotificationTest,
              ModeEntryTBTNotifySpeedLimitingCable);
  FRIEND_TEST(PortManagerNotificationTest,
              ModeEntryTBTNotifyInvalidUSB4ValidTBTCable);
  FRIEND_TEST(PortManagerNotificationTest,
              ModeEntryDpAltModeNotifyInvalidUSB4Cable);
  FRIEND_TEST(PortManagerNotificationTest,
              ModeEntryDpAltModeNotifyInvalidTBTCable);
  FRIEND_TEST(PortManagerNotificationTest,
              ModeEntryDpAltModeNotifyInvalidDpCable);
  FRIEND_TEST(PortManagerNotificationTest, ECModeEntryNoCableNotification);
  FRIEND_TEST(PortManagerNotificationTest, ECModeEntryNotifyInvalidDpCable);
  FRIEND_TEST(MetricsTest, CheckPartnerLocationPreferRightSide);
  FRIEND_TEST(MetricsTest, CheckPartnerLocationPreferLeftSide);
  FRIEND_TEST(MetricsTest, CheckPartnerLocationNoPreference);
  FRIEND_TEST(MetricsTest, CheckPowerSourceLocation);
  FRIEND_TEST(MetricsTest, CheckPowerSourceLocationNoChoice);

  // UdevMonitor::Observer overrides.
  void OnPortAddedOrRemoved(const base::FilePath& path,
                            int port_num,
                            bool added) override;
  void OnPartnerAddedOrRemoved(const base::FilePath& path,
                               int port_num,
                               bool added,
                               bool is_hotplug = true) override;
  void OnPartnerAltModeAddedOrRemoved(const base::FilePath& path,
                                      int port_num,
                                      bool added) override;
  void OnCableAddedOrRemoved(const base::FilePath& path,
                             int port_num,
                             bool added) override;
  void OnCablePlugAdded(const base::FilePath& path, int port_num) override;
  void OnCableAltModeAdded(const base::FilePath& path, int port_num) override;
  void OnPdDeviceAddedOrRemoved(const base::FilePath& path,
                                bool added) override;
  void OnPartnerChanged(int port_num) override;
  void OnPortChanged(int port_num) override;

  // SessionManagerObserverInterface overrides.
  void OnScreenIsLocked() override;
  void OnScreenIsUnlocked() override;
  void OnSessionStarted() override;
  void OnSessionStopped() override;

  void HandleUnlock();

  void HandleSessionStopped();

  // Central function to perform metrics reporting for the peripherals.
  void ReportMetrics(int port_num, bool is_hotplug);

  // Convenience function used by ReportMetrics to get the right enum for
  // PartnerLocationMetric.
  PartnerLocationMetric GetPartnerLocationMetric(int port_num, bool is_hotplug);

  // Convenience function used by ReportMetrics to get the right enum for
  // PowerSourceLocationMetric.
  PowerSourceLocationMetric GetPowerSourceLocationMetric(int port_num);

  // The central function which contains the main mode entry logic. This decides
  // which partner mode we select, based on partner/cable characteristics as
  // well as host properties and any other device specific policy we choose to
  // implement.
  void RunModeEntry(int port_num);

  std::map<int, std::unique_ptr<Port>> ports_;
  bool mode_entry_supported_;

  // Variable used to reflect whether the system supports USB4. When it is
  // false, we should not enter USB4 or TBT mode even if a partner which
  // supports those modes is connected.
  bool supports_usb4_;

  ECUtil* ec_util_;
  // Pointer to the DBusManager instance. NOTE: This is owned by the parent
  // Daemon, and not PortManager.
  DBusManager* dbus_mgr_;

  // Pointer to the ChromeFeaturesServiceClient instance. NOTE: This is owned
  // by the parent Daemon, and not PortManager.
  ChromeFeaturesServiceClient* features_client_;

  // Variable that is used to determine what alt mode should be entered. It is
  // updated in response to session manager events. It is set to false when the
  // screen is locked, and true when unlocked. In addition to that, it is also
  // set to true when a session starts i.e when a user logs in, and false when a
  // session ends i.e the user logs out.
  bool user_active_;

  // Variable used to reflect the Chrome setting regarding peripheral data
  // access. When it is false, we should *not* trigger a switch to TBT mode
  // (if applicable) even if the |user_active_| state is true.
  bool peripheral_data_access_;

  // Variable used to keep track of the port that has previously been used for
  // connecting a power source. This is used to check if the port used for
  // charging the system has changed during the session.
  int port_num_previously_sink;

  // Pointer to the metrics reporting class. NOTE: THis is owned by the parent
  // Daemon, and not PortManager.
  Metrics* metrics_;
};

}  // namespace typecd

#endif  // TYPECD_PORT_MANAGER_H_
