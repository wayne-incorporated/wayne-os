// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/port.h"

#include <string>

#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "typecd/test_constants.h"
#include "typecd/test_utils.h"

namespace {
constexpr char kInvalidDataRole1[] = "xsadft [hasdr]";
constexpr char kInvalidDataRole2[] = "]asdf[ dsdd";
constexpr char kValidDataRole1[] = "device";
constexpr char kValidDataRole2[] = "[host] device";
constexpr char kValidDataRole3[] = "host [device]";

constexpr char kValidPowerRole1[] = "[source] sink";
constexpr char kValidPowerRole2[] = "source [sink]";
constexpr char kInvalidPowerRole1[] = "asdf#//%sxdfa";

constexpr char kValidPanel[] = "left";
constexpr char kInvalidPanel[] = "asdf";
constexpr char kValidHorizontalPosition[] = "right";
constexpr char kInvalidHorizontalPosition[] = "fdas";
constexpr char kValidVerticalPosition[] = "upper";
constexpr char kInvalidVerticalPosition[] = "dsaf";
}  // namespace

namespace typecd {

class PortTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    temp_dir_ = scoped_temp_dir_.GetPath();
  }

 public:
  base::FilePath temp_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

// Check that basic Port creation, partner addition/deletion works.
TEST_F(PortTest, BasicAdd) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);
  EXPECT_NE(nullptr, port);

  port->AddPartner(base::FilePath(kFakePort0PartnerSysPath));
  EXPECT_NE(nullptr, port->partner_);
  port->RemovePartner();
  EXPECT_EQ(nullptr, port->partner_);
}

// Check GetDataRole() for various sysfs values.
TEST_F(PortTest, GetDataRole) {
  // Set up fake sysfs directory for the port..
  auto port_path = temp_dir_.Append("port0");
  ASSERT_TRUE(base::CreateDirectory(port_path));

  auto data_role_path = port_path.Append("data_role");
  ASSERT_TRUE(base::WriteFile(data_role_path, kValidDataRole1,
                              strlen(kValidDataRole1)));

  // Create a port.
  auto port = std::make_unique<Port>(base::FilePath(port_path), 0);
  ASSERT_NE(nullptr, port);

  EXPECT_EQ(DataRole::kDevice, port->GetDataRole());

  ASSERT_TRUE(base::WriteFile(data_role_path, kValidDataRole2,
                              strlen(kValidDataRole2)));
  // Fake a port changed event.
  port->PortChanged();
  EXPECT_EQ(DataRole::kHost, port->GetDataRole());

  ASSERT_TRUE(base::WriteFile(port_path.Append("data_role"), kValidDataRole3,
                              strlen(kValidDataRole3)));
  // Fake a port changed event.
  port->PortChanged();
  EXPECT_EQ(DataRole::kDevice, port->GetDataRole());

  ASSERT_TRUE(base::WriteFile(port_path.Append("data_role"), kInvalidDataRole1,
                              strlen(kInvalidDataRole1)));
  // Fake a port changed event.
  port->PortChanged();
  EXPECT_EQ(DataRole::kNone, port->GetDataRole());

  ASSERT_TRUE(base::WriteFile(port_path.Append("data_role"), kInvalidDataRole2,
                              strlen(kInvalidDataRole2)));
  // Fake a port changed event.
  port->PortChanged();
  EXPECT_EQ(DataRole::kNone, port->GetDataRole());
}

// Check GetPowerRole() for various sysfs values.
TEST_F(PortTest, GetPowerRole) {
  // Set up fake sysfs directory for the port..
  auto port_path = temp_dir_.Append("port0");
  ASSERT_TRUE(base::CreateDirectory(port_path));

  auto data_role_path = port_path.Append("power_role");
  ASSERT_TRUE(base::WriteFile(data_role_path, kValidPowerRole1,
                              strlen(kValidPowerRole1)));

  // Create a port.
  auto port = std::make_unique<Port>(base::FilePath(port_path), 0);
  ASSERT_NE(nullptr, port);

  EXPECT_EQ(PowerRole::kSource, port->GetPowerRole());

  ASSERT_TRUE(base::WriteFile(data_role_path, kValidPowerRole2,
                              strlen(kValidPowerRole2)));
  // Fake a port changed event.
  port->PortChanged();
  EXPECT_EQ(PowerRole::kSink, port->GetPowerRole());

  ASSERT_TRUE(base::WriteFile(data_role_path, kInvalidPowerRole1,
                              strlen(kInvalidPowerRole1)));
  // Fake a port changed event.
  port->PortChanged();
  EXPECT_EQ(PowerRole::kNone, port->GetPowerRole());
}

// Check that DP Alt Mode Entry checks work as expected for a true case:
TEST_F(PortTest, DPAltModeEntryCheckTrue) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  port->AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // Set up fake sysfs paths for 1 alt mode.
  // Set the number of alt modes supported.
  port->partner_->SetNumAltModes(1);

  // Add the DP alt mode.
  std::string mode0_dirname =
      base::StringPrintf("port%d-partner.%d", 0, kDPAltModeIndex);
  auto mode0_path = temp_dir_.Append(mode0_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode0_path, kDPAltModeSID, kDPVDO_WD19TB,
                                kDPVDOIndex_WD19TB));
  port->AddRemovePartnerAltMode(mode0_path, true);

  AddAnkerUSB3p2Gen2Cable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_FALSE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry checks work as expected for a specific false
// case: The Startech dock DP VDO doesn't advertise DFP_D, so we *shouldn't*
// enter DP alternate mode, despite it supporting the DP SID.
TEST_F(PortTest, DPAltModeEntryCheckFalseWithDPSID) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddStartechDock(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_FALSE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_FALSE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry checks work as expected for false cases.
TEST_F(PortTest, DPAltModeEntryCheckFalse) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  port->AddPartner(base::FilePath(kFakePort0PartnerSysPath));
  port->partner_->SetNumAltModes(0);

  // Check the case where the partner doesn't support any alt modes.
  EXPECT_FALSE(port->CanEnterDPAltMode(nullptr));

  port->partner_->SetNumAltModes(1);

  // Set up fake sysfs paths for 1 alt mode.
  // Add the TBT alt mode.
  std::string mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode_path, kTBTAltModeVID, kTBTVDO, kTBTVDOIndex));
  port->AddRemovePartnerAltMode(mode_path, true);

  EXPECT_FALSE(port->CanEnterDPAltMode(nullptr));
}

// Check that DP Alt Mode Entry works with cable check for a passing case.
// Case: The WIMAXIT Type-C display supports DP alternate mode and the CalDigit
// TBT4 cable supports up to USB4 so it should enter DP alternate mode and the
// cable will not be flagged as invalid
TEST_F(PortTest, DPAltModeEntryCalDigitTBT4ToDisplay) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddWimaxitDisplay(*port);
  AddCalDigitTBT4Cable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_FALSE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry works with cable check for a passing case.
// Case: The WIMAXIT Type-C display supports DP alternate mode and the Anker
// USB3.2 Gen2 cable supports USB3 so it should enter DP alternate mode and
// the cable will not be flagged as invalid
TEST_F(PortTest, DPAltModeEntryAnkerUsb3Gen2ToDisplay) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddWimaxitDisplay(*port);
  AddAnkerUSB3p2Gen2Cable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_FALSE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry works with cable check for a passing case.
// Case: The WIMAXIT Type-C display supports DP alternate mode and the HP
// USB3.2 Gen1 cable supports up to USB3.2 Gen1 so it should enter DP
// alternate mode and the cable will not be flagged as invalid
TEST_F(PortTest, DPAltModeEntryHPUsb3Gen1ToDisplay) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddWimaxitDisplay(*port);
  AddHPUSB3p2Gen1Cable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_FALSE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry works with cable check for a passing case.
// Case: The WIMAXIT Type-C display supports DP alternate mode and the Apple
// TBT3 Pro cable supports up to USB4 so it should enter DP alternate mode
// and the cable will not be flagged as invalid
TEST_F(PortTest, DPAltModeEntryAppleTBT3ToDisplay) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddWimaxitDisplay(*port);
  AddAppleTBT3ProCable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_FALSE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry works with cable check for a failing case.
// Case: The WIMAXIT Type-C display supports DP alternate mode but, an unbranded
// USB2 cable is not considered as a cable object in typecd. It should still try
// to enter alternate mode but the cable will be flagged as invalid
TEST_F(PortTest, DPAltModeEntryUnbrandedUSB2ToDisplay) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddWimaxitDisplay(*port);
  AddUnbrandedUSB2Cable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_TRUE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry works with cable check for a failing case.
// Case: The WIMAXIT Type-C display supports DP alternate mode but, a tested
// Nekteck cable only supports up to USB2. The typec daemon should still try
// to enter alternate mode but the cable will be flagged as invalid
TEST_F(PortTest, DPAltModeEntryNekteckUSB2ToDisplay) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddWimaxitDisplay(*port);
  AddNekteckUSB2PassiveCable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_TRUE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry works with cable check for a passing case.
// Case: The Thinkpad Dock supports DP alternate mode and a tested unbranded
// TBT3 cable supports up to USB3.2 Gen2 so it should enter DP alternate mode
// and the cable will not be flagged as invalid
TEST_F(PortTest, DPAltModeEntryTBT3ToDock) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddThinkpadTBT3Dock(*port);
  AddUnbrandedTBT3Cable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_FALSE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry works with cable check for a failing case.
// Case: The Thinkpad Dock supports DP alternate mode but a tested unbranded
// USB2 cable is not recognized by the typec daemon. It should try to enter
// DP alternate mode but the cable will be flagged as invalid.
TEST_F(PortTest, DPAltModeEntryUnbrandedUSB2ToDock) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddThinkpadTBT3Dock(*port);
  AddUnbrandedUSB2Cable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_TRUE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry works with cable check for a failing case.
// Case: The Thinkpad Dock supports DP alternate mode but a tested Nekteck
// type-c cable only supports up to USB2. The typec daemon should try to
// enter DP alternate mode but the cable will be flagged as invalid.
TEST_F(PortTest, DPAltModeEntryNekteckUSB2ToDock) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddThinkpadTBT3Dock(*port);
  AddNekteckUSB2PassiveCable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_TRUE(invalid_dpalt_cable);
}

// Check that DP Alt Mode Entry works with cable check for a passing case.
// Case: A small Cable Matters dock uses a captive cable. The type-c daemon
// will not recognize a cable for this dock, but because the partner notes it
// uses a captive cable typecd should enter DP Alt Mode without flagging the
// cable as invalid
TEST_F(PortTest, DPAltModeEntryCableMattersDock) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddCableMattersDock(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_FALSE(invalid_dpalt_cable);
}

// Check that TBT Compat Mode Entry checks work as expected for the following
// working case:
// - Startech.com TB3DK2DPW Alpine Ridge Dock.
// - StarTech Passive Cable 40 Gbps PD 2.0
TEST_F(PortTest, TBTCompatibilityModeEntryCheckTrueStartech) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddStartechTB3DK2DPWDock(*port);
  AddStartech40GbpsCable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterTBTCompatibilityMode());
}

// Check that TBT Compat Mode Entry checks work as expected for the following
// non-working case:
// - Startech.com TB3DK2DPW Alpine Ridge Dock.
// - Nekteck USB 2.0 cable (5A).
TEST_F(PortTest, TBTCompatibilityModeEntryCheckFalseStartech) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddStartechTB3DK2DPWDock(*port);
  AddNekteckUSB2PassiveCable(*port);

  EXPECT_EQ(ModeEntryResult::kCableError, port->CanEnterTBTCompatibilityMode());
}

// Check that TBT Compat Mode Entry checks work as expected for the following
// working case:
// - Dell WD19TB dock.
TEST_F(PortTest, TBTCompatibilityModeEntryCheckTrueWD19TB) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddDellWD19TBDock(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterTBTCompatibilityMode());
}

// Check that USB4 mode checks work as expected for the following
// working case:
// - Intel Gatkex Creek USB4 dock.
// - Belkin TBT3 Passive Cable 40Gbps.
TEST_F(PortTest, USB4EntryTrueGatkexPassiveTBT3Cable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddIntelUSB4GatkexCreekDock(*port);
  AddBelkinTBT3PassiveCable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterUSB4());
}

// Check that USB4 mode checks work as expected for the following
// working case:
// - Intel Gatkex Creek USB4 dock.
// - Hongju Full USB 3.1 Gen 1 5A passive cable..
TEST_F(PortTest, USB4EntryTrueGatkexPassiveNonTBT3Cable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddIntelUSB4GatkexCreekDock(*port);
  AddHongjuUSB3p1Gen1Cable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterUSB4());
}

// Check that USB4 mode checks work as expected for the following
// non-working case:
// - Intel Gatkex Creek USB4 dock.
// - Nekteck USB 2.0 5A Passive Cable.
TEST_F(PortTest, USB4EntryFalseGatkexPassiveNonTBT3Cable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddIntelUSB4GatkexCreekDock(*port);
  AddNekteckUSB2PassiveCable(*port);

  EXPECT_EQ(ModeEntryResult::kCableError, port->CanEnterUSB4());
}

// Check that USB4 mode checks work as expected for the following
// non-working case:
// - Intel Gatkex Creek USB4 dock.
// - Belkin TBT3 Active Cable 40Gbps.
//
// NOTE: This case is interesting because the TBT3 cable fails as it doesn't
// support Rounded Data rates.
TEST_F(PortTest, USB4EntryFalseGatkexActiveTBT3Cable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddIntelUSB4GatkexCreekDock(*port);
  AddBelkinTBT3ActiveCable(*port);

  EXPECT_EQ(ModeEntryResult::kCableError, port->CanEnterUSB4());
}

// Check that USB4 mode checks work as expected for the following
// working case:
// - OWC Thunderbolt 4 Dock.
// - Anker USB 3.2 Gen2 cable.
// Additionally check that CableLimitingUSBSpeed() returns true.
TEST_F(PortTest, USB4EntryTrueOWCAnker3p2Gen2Cable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddOWCTBT4Dock(*port);
  AddAnkerUSB3p2Gen2Cable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterUSB4());
  EXPECT_TRUE(port->CableLimitingUSBSpeed(false));
}

// Check that USB4 mode checks work as expected for the following
// working case:
// - Intel Gatkex Creek USB4 dock.
// - Apple Thunderbolt 3 Pro Cable.
TEST_F(PortTest, USB4EntryTrueGatkexAppleTBT3ProCable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddIntelUSB4GatkexCreekDock(*port);
  AddAppleTBT3ProCable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterUSB4());
}

// Check that USB4 mode checks work as expected for the following
// non-working case:
// - Targus DV4K AMA dock.
// - Targus USB 3.2 Gen2 Cable.
//
// This is an interesting case because if AMA VDO is incorrectly interpreted as
// UFP VDO, we may incorrectly consider this dock as USB4 dock while AMA dock
// does not actually support USB4.
TEST_F(PortTest, USB4EntryFalseTargusDV4KTargus3p2Gen2Cable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddTargusDV4KDock(*port);
  AddTargusUSB3p2Gen2Cable(*port);

  EXPECT_EQ(ModeEntryResult::kPartnerError, port->CanEnterUSB4());
}

// Check that USB4 mode checks work as expected for the following
// non-working case:
// - Targus 180 AMA dock.
// - Targus USB 3.1 Gen1 Cable.
//
// This is an interesting case because if AMA VDO is incorrectly interpreted as
// UFP VDO, we may incorrectly consider this dock as USB4 dock while AMA dock
// does not actually support USB4.
TEST_F(PortTest, USB4EntryFalseTargus180Targus3p1Gen1Cable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddTargus180Dock(*port);
  AddTargusUSB3p1Gen1Cable(*port);

  EXPECT_EQ(ModeEntryResult::kPartnerError, port->CanEnterUSB4());
}

// Check that USB4 device will enter TBT3 mode if the  cable does not support
// USB4.
// Case: Thunderbolt 4 OWC dock connected with Belkin active TBT3 cable.
TEST_F(PortTest, USB4ToTBT) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddOWCTBT4Dock(*port);
  AddBelkinTBT3ActiveCable(*port);

  EXPECT_EQ(ModeEntryResult::kCableError, port->CanEnterUSB4());
  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterTBTCompatibilityMode());
}

// Check that USB4 device will enter DPAltMode if the cable does not support
// USB4 or TBT.
// Case: Thunderbolt 4 OWC dock connected with unbranded USB2 cable.
TEST_F(PortTest, USB4ToDPAltMode) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddOWCTBT4Dock(*port);
  AddUnbrandedUSB2Cable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_EQ(ModeEntryResult::kCableError, port->CanEnterUSB4());
  EXPECT_EQ(ModeEntryResult::kCableError, port->CanEnterTBTCompatibilityMode());
  // Cable is flagged as invalid, but typecd will still enter DPAltMode. For
  // DPAltMode, the cable check is not a condition for mode entry.
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_TRUE(invalid_dpalt_cable);
}

// Check that CableLimitingUSBSpeed works for "false" case.
// Case: Thunderbolt 4 OWC dock connected with CalDigit Thunderbolt 4 cable.
TEST_F(PortTest, USB4LimitedByCableFalse) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddOWCTBT4Dock(*port);
  AddCalDigitTBT4Cable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterUSB4());
  EXPECT_FALSE(port->CableLimitingUSBSpeed(false));
}

// Check that CableLimitingUSBSpeed works for "true" case.
// Case: Thunderbolt 4 OWC dock connected with Cable Matters USB4 20Gbps cable.
TEST_F(PortTest, USB4LimitedByCableTrue) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddOWCTBT4Dock(*port);
  AddCableMatters20GbpsCable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterUSB4());
  EXPECT_TRUE(port->CableLimitingUSBSpeed(false));
}

// Check that CableLimitingUSBSpeed works for "false" case with passive TBT3
// (USB 3.2 Gen2) Cable.
// Case: Thunderbolt 4 OWC dock connected with unbranded TBT3 cable.
TEST_F(PortTest, USB4LimitedByTBT3PassiveCableFalse) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddOWCTBT4Dock(*port);
  AddUnbrandedTBT3Cable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterUSB4());
  EXPECT_FALSE(port->CableLimitingUSBSpeed(false));
}

// Check that CableLimitingUSBSpeed works for "false" case with passive TBT4
// (USB 3.2 Gen2) LRD Cable.
// Case: Thunderbolt 4 OWC dock connected with Cable Matters TBT4 LRD cable.
TEST_F(PortTest, USB4LimitedByTBT4PassiveLRDCableFalse) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddOWCTBT4Dock(*port);
  AddCableMattersTBT4LRDCable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterUSB4());
  EXPECT_FALSE(port->CableLimitingUSBSpeed(false));
}

// Check that CableLimitingUSBSpeed works for a case with AMA VDO.
// Case: WIMAXIT display connected with Anker USB 3.2 Gen2 cable.
TEST_F(PortTest, BillboardOnlyDisplayNotLimitedByCable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddWimaxitDisplay(*port);
  AddAnkerUSB3p2Gen2Cable(*port);

  bool invalid_dpalt_cable = false;
  EXPECT_TRUE(port->CanEnterDPAltMode(&invalid_dpalt_cable));
  EXPECT_FALSE(invalid_dpalt_cable);
  EXPECT_FALSE(port->CableLimitingUSBSpeed(false));
}

// Check that CableLimitingUSBSpeed() returns false for cases using a TBT3
// active cable for USB4.
// Case: Thunderbolt 4 OWC dock with Apple Thunderbolt 3 Pro Cable.
TEST_F(PortTest, CableLimitingSpeedOWCDockAppleTBT3ProCable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddOWCTBT4Dock(*port);
  AddAppleTBT3ProCable(*port);

  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterUSB4());
  EXPECT_FALSE(port->CableLimitingUSBSpeed(false));
}

// Check that CableLimitingUSBSpeed() returns false after entering TBT3 mode
// with TBT3 dock and passive USB4 Gen3 cable.
// Case: Thinkpad Thunderbolt 3 Dock with Caldigit TBT4 Cable.
TEST_F(PortTest, TBTCableLimitingSpeedTBT3DockFalse) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddThinkpadTBT3Dock(*port);
  AddCalDigitTBT4Cable(*port);

  EXPECT_EQ(ModeEntryResult::kPartnerError, port->CanEnterUSB4());
  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterTBTCompatibilityMode());
  EXPECT_FALSE(port->CableLimitingUSBSpeed(true));
}

// Check that CableLimitingUSBSpeed() returns true after entering TBT3 mode
// with TBT3 dock and passive USB 3.2 Gen2 cable.
// Case: Thinkpad Thunderbolt 3 Dock with Anker USB 3.2 Gen2 Cable.
TEST_F(PortTest, TBTCableLimitingSpeedTBT3DockTrue) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddThinkpadTBT3Dock(*port);
  AddAnkerUSB3p2Gen2Cable(*port);

  EXPECT_EQ(ModeEntryResult::kPartnerError, port->CanEnterUSB4());
  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterTBTCompatibilityMode());
  EXPECT_TRUE(port->CableLimitingUSBSpeed(true));
}

// Check that CableLimitingUSBSpeed() returns false after entering TBT3 mode
// with TBT3 dock and TBT3 cable.
// Case: Thinkpad Thunderbolt 3 Dock with Belkin TBT3 Passive Cable.
TEST_F(PortTest, TBTCableLimitingSpeedTBT3DockFalseTBT3Cable) {
  auto port = std::make_unique<Port>(base::FilePath(kFakePort0SysPath), 0);

  AddThinkpadTBT3Dock(*port);
  AddBelkinTBT3PassiveCable(*port);

  EXPECT_EQ(ModeEntryResult::kPartnerError, port->CanEnterUSB4());
  EXPECT_EQ(ModeEntryResult::kSuccess, port->CanEnterTBTCompatibilityMode());
  EXPECT_FALSE(port->CableLimitingUSBSpeed(true));
}

// Check the physical location functions GetPanel(), GetHorizontalLocation() and
// GetVerticalLocation() for a valid physical_location.
TEST_F(PortTest, GetPhysicalLocationValid) {
  // Set up fake sysfs directory for the ports.
  auto port_path = temp_dir_.Append("port0");
  ASSERT_TRUE(base::CreateDirectory(port_path));

  auto port_physical_location_path = port_path.Append("physical_location");
  ASSERT_TRUE(base::CreateDirectory(port_physical_location_path));

  auto port_panel_path = port_physical_location_path.Append("panel");
  ASSERT_TRUE(
      base::WriteFile(port_panel_path, kValidPanel, strlen(kValidPanel)));
  auto port_horizontal_position_path =
      port_physical_location_path.Append("horizontal_position");
  ASSERT_TRUE(base::WriteFile(port_horizontal_position_path,
                              kValidHorizontalPosition,
                              strlen(kValidHorizontalPosition)));
  auto port_vertical_position_path =
      port_physical_location_path.Append("vertical_position");
  ASSERT_TRUE(base::WriteFile(port_vertical_position_path,
                              kValidVerticalPosition,
                              strlen(kValidVerticalPosition)));

  // Create ports.
  auto port = std::make_unique<Port>(base::FilePath(port_path), 0);
  ASSERT_NE(nullptr, port);

  EXPECT_EQ(Panel::kLeft, port->GetPanel());
  EXPECT_EQ(HorizontalPosition::kRight, port->GetHorizontalPosition());
  EXPECT_EQ(VerticalPosition::kUpper, port->GetVerticalPosition());
}

// Check the physical location functions GetPanel(), GetHorizontalLocation() and
// GetVerticalLocation() for an invalid physical_location.
TEST_F(PortTest, GetPhysicalLocationInvalid) {
  // Set up fake sysfs directory for the ports.
  auto port_path = temp_dir_.Append("port0");
  ASSERT_TRUE(base::CreateDirectory(port_path));

  auto port_physical_location_path = port_path.Append("physical_location");
  ASSERT_TRUE(base::CreateDirectory(port_physical_location_path));

  auto port_panel_path = port_physical_location_path.Append("panel");
  ASSERT_TRUE(
      base::WriteFile(port_panel_path, kInvalidPanel, strlen(kInvalidPanel)));
  auto port_horizontal_position_path =
      port_physical_location_path.Append("horizontal_position");
  ASSERT_TRUE(base::WriteFile(port_horizontal_position_path,
                              kInvalidHorizontalPosition,
                              strlen(kInvalidHorizontalPosition)));
  auto port_vertical_position_path =
      port_physical_location_path.Append("vertical_position");
  ASSERT_TRUE(base::WriteFile(port_vertical_position_path,
                              kInvalidVerticalPosition,
                              strlen(kInvalidVerticalPosition)));

  // Create ports.
  auto port = std::make_unique<Port>(base::FilePath(port_path), 0);
  ASSERT_NE(nullptr, port);

  EXPECT_EQ(Panel::kUnknown, port->GetPanel());
  EXPECT_EQ(HorizontalPosition::kUnknown, port->GetHorizontalPosition());
  EXPECT_EQ(VerticalPosition::kUnknown, port->GetVerticalPosition());
}

// Check the physical location functions GetPanel(), GetHorizontalLocation() and
// GetVerticalLocation() when there is no physical_location data available.
TEST_F(PortTest, GetPhysicalLocationNoValue) {
  // Set up fake sysfs directory for the ports.
  auto port_path = temp_dir_.Append("port0");
  ASSERT_TRUE(base::CreateDirectory(port_path));

  // Create ports.
  auto port = std::make_unique<Port>(base::FilePath(port_path), 0);
  ASSERT_NE(nullptr, port);

  EXPECT_EQ(Panel::kUnknown, port->GetPanel());
  EXPECT_EQ(HorizontalPosition::kUnknown, port->GetHorizontalPosition());
  EXPECT_EQ(VerticalPosition::kUnknown, port->GetVerticalPosition());
}

}  // namespace typecd
