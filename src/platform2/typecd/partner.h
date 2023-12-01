// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_PARTNER_H_
#define TYPECD_PARTNER_H_

#include <map>
#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>

#include "typecd/alt_mode.h"
#include "typecd/metrics.h"
#include "typecd/peripheral.h"
#include "typecd/power_profile.h"

namespace typecd {

class Port;

// A partner represents a device which is connected to the host. This
// class is used to maintain the state associated with the partner.
class Partner : public Peripheral {
 public:
  // Add a constructor for ONLY for partner unit tests.
  explicit Partner(const base::FilePath& syspath, Port* port);
  explicit Partner(const base::FilePath& syspath);
  Partner(const Partner&) = delete;
  Partner& operator=(const Partner&) = delete;

  // Check if a particular alt mode index (as specified by the Type C connector
  // class framework) is registered.
  bool IsAltModePresent(int index);

  bool AddAltMode(const base::FilePath& mode_syspath);
  void RemoveAltMode(const base::FilePath& mode_syspath);

  // In some cases, some of the PD identity info (like number of alternate
  // modes) is not yet available when the Partner is first created. When these
  // later get added, a udev event occurs. When this event occurs, read sysfs to
  // get this data if it is available.
  void UpdatePDInfoFromSysfs();

  // Parse the registered PDOs from sysfs and create an object to hold them,
  // if one doesn't already exist.
  void AddPowerProfile();

  // Delete a PowerProfile if one was created for this partner.
  void RemovePowerProfile();

  // Return the total number of AltModes supported by the partner. If this value
  // hasn't been populated yet, the default value is -1, signifying that
  // discovery is not yet complete.
  int GetNumAltModes() { return num_alt_modes_; }

  // Set the total number of alternate modes supported by the partner.
  void SetNumAltModes(int num_alt_modes) { num_alt_modes_ = num_alt_modes; }

  // Parse the number of alternate modes supported by the partner. This value
  // should be populated from the corresponding file in sysfs.
  //
  // Returns the number of supported alternate modes, or -1 if the sysfs file is
  // unavailable.
  int ParseNumAltModes();

  // Return the AltMode with index |index|, and nullptr if such an AltMode
  // doesn't exist.
  AltMode* GetAltMode(int index);

  // Checks whether partner PD discovery is complete (and we have all the PD
  // information that the kernel can provide). To determine this, we check
  // whether the number of registered altmodes equals the |num_alt_modes_| value
  // which is read from sysfs.
  bool DiscoveryComplete();

  bool GetSupportsPD() { return supports_pd_; }

  // Report any metrics associated with the partner using UMA reporting. If the
  // |metrics| pointer is nullptr, or if metrics have already been reported i.e
  // |metrics_reported_| is true, we return immediately.
  void ReportMetrics(Metrics* metrics);

  // Checks whether the partner supports DP alt mode.
  bool SupportsDp();

  // Checks whether the partner supports TBT alt mode.
  bool SupportsTbt();

  // Checks whether the partner supports USB4 mode.
  bool SupportsUsb4();

  // Checks whether the partner supports USB. (not USB4)
  bool SupportsUsb();

 private:
  friend class MetricsTest;
  FRIEND_TEST(MetricsTest, CheckPartnerTypeUSB4Hub);
  FRIEND_TEST(MetricsTest, CheckPartnerTypeTBTDPAltHub);
  FRIEND_TEST(MetricsTest, CheckPartnerTypeTBTDPAltPeripheral);
  FRIEND_TEST(MetricsTest, CheckPartnerTypeTBTPeripheral);
  FRIEND_TEST(MetricsTest, CheckPartnerTypeDPAltHub);
  FRIEND_TEST(MetricsTest, CheckPartnerTypePowerBrick);
  FRIEND_TEST(MetricsTest, CheckNoPartnerType);
  FRIEND_TEST(MetricsTest, CheckPartnerTypeOther);
  FRIEND_TEST(PartnerTest, SupportsPD);
  FRIEND_TEST(PartnerTest, PowerProfile);

  // Convenience function used by ReportMetrics to get the right enum for
  // PartnerTypeMetric.
  PartnerTypeMetric GetPartnerTypeMetric();

  // Convenience function used by ReportMetrics to get the right enum for
  // DataRoleMetric.
  DataRoleMetric GetDataRoleMetric();

  // Convenience function used by ReportMetrics to get the right enum for
  // PowerRoleMetric.
  PowerRoleMetric GetPowerRoleMetric();

  // Extract ID values from VDOs.
  int GetVendorId();
  int GetProductId();
  int GetXid();

  // Parse and store the value of the "supports_usb_power_delivery" file from
  // sysfs. If there is an error parsing the file contents, the value is assumed
  // to be false.
  void UpdateSupportsPD();

  // Explicitly set supports_pd for unit testing purpose.
  void SetSupportsPD(bool supports_pd) { supports_pd_ = supports_pd; }

  // A map representing all the alternate modes supported by the partner.
  // The key is the index of the alternate mode as determined by the connector
  // class sysfs directories that represent them. For example, and alternate
  // mode which has the directory
  // "/sys/class/typec/port1-partner/port1-partner.0" will use an key of "0".
  std::map<int, std::unique_ptr<AltMode>> alt_modes_;
  int num_alt_modes_;
  // Field representing the value of "supports_usb_power_delivery" sysfs file.
  // Signifies whether the partner supports PD communication.
  bool supports_pd_;
  // Field which tracks whether metrics have been reported for the partner. This
  // prevents duplicate reporting.
  bool metrics_reported_;
  // Pointer to the parent Port for this partner. The port lifecycle exceeds
  // that of the Partner, so it's fine to have this as a raw pointer.
  Port* port_;
  std::unique_ptr<PowerProfile> power_profile_;
};

}  // namespace typecd

#endif  // TYPECD_PARTNER_H_
