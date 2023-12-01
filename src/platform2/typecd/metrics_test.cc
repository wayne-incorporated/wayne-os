// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/cable.h"
#include "typecd/partner.h"
#include "typecd/port_manager.h"

#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "typecd/mock_ec_util.h"
#include "typecd/mock_port.h"
#include "typecd/test_constants.h"
#include "typecd/test_utils.h"

using ::testing::_;
using ::testing::DoAll;

namespace typecd {

class MetricsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    temp_dir_ = scoped_temp_dir_.GetPath();
  }

 public:
  base::FilePath temp_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

TEST_F(MetricsTest, CheckPartnerTypeUSB4Hub) {
  // Intel Gatkex Creek USB4 dock.
  Partner p(base::FilePath("foo"));
  p.SetPDRevision(PDRevision::k30);
  p.SetIdHeaderVDO(0x4c800000);
  p.SetCertStatVDO(0x0);
  p.SetProductVDO(0x0);
  p.SetProductTypeVDO1(0xd00001b);
  p.SetProductTypeVDO2(0x0);
  p.SetProductTypeVDO3(0x0);

  p.SetNumAltModes(2);

  // Add the DP alt mode.
  auto mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode_path, kDPAltModeSID, kDPVDO_GatkexCreek,
                                kDPVDOIndex_GatkexCreek));
  p.AddAltMode(mode_path);

  // Add the TBT alt mode.
  mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode_path, kTBTAltModeVID, kTBTVDO_GatkexCreek,
                                kTBTVDOIndex_GatkexCreek));
  p.AddAltMode(mode_path);

  EXPECT_TRUE(p.SupportsUsb());
  EXPECT_TRUE(p.SupportsDp());
  EXPECT_TRUE(p.SupportsTbt());
  EXPECT_TRUE(p.SupportsUsb4());
  EXPECT_EQ(PartnerTypeMetric::kUSB4Hub, p.GetPartnerTypeMetric());
}

TEST_F(MetricsTest, CheckPartnerTypeTBTDPAltHub) {
  // Dell WD19TB dock.
  Partner p(base::FilePath("foo"));
  p.SetPDRevision(PDRevision::k30);
  p.SetIdHeaderVDO(0x4c0041c3);
  p.SetCertStatVDO(0x0);
  p.SetProductVDO(0xb0700712);
  p.SetProductTypeVDO1(0x0);
  p.SetProductTypeVDO2(0x0);
  p.SetProductTypeVDO3(0x0);

  p.SetNumAltModes(4);

  // Add the TBT alt mode.
  std::string mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode_path, kTBTAltModeVID, kTBTVDO, kTBTVDOIndex));
  p.AddAltMode(mode_path);

  // Add the DP alt mode.
  mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode_path, kDPAltModeSID, kDPVDO_WD19TB, 0));
  p.AddAltMode(mode_path);

  // Add the Dell alt mode 1.
  mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 2);
  mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode_path, kDellSVID_WD19TB, kDell_WD19TB_VDO1, 0));
  p.AddAltMode(mode_path);

  // Add the Dell alt mode 2.
  mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 3);
  mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode_path, kDellSVID_WD19TB, kDell_WD19TB_VDO2, 1));
  p.AddAltMode(mode_path);

  EXPECT_TRUE(p.SupportsUsb());
  EXPECT_TRUE(p.SupportsDp());
  EXPECT_TRUE(p.SupportsTbt());
  EXPECT_FALSE(p.SupportsUsb4());
  EXPECT_EQ(PartnerTypeMetric::kTBTDPAltHub, p.GetPartnerTypeMetric());
}

TEST_F(MetricsTest, CheckPartnerTypeTBTDPAltPeripheral) {
  // Sabrent Rocket XTRM-Q SSD.
  Partner p(base::FilePath("foo"));
  p.SetPDRevision(PDRevision::k30);
  p.SetIdHeaderVDO(0xd4002eb9);
  p.SetCertStatVDO(0x00000000);
  p.SetProductVDO(0x03070667);
  p.SetProductTypeVDO1(0x0);
  p.SetProductTypeVDO2(0x0);
  p.SetProductTypeVDO3(0x0);

  p.SetNumAltModes(2);

  // Add the TBT alt mode.
  std::string mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode_path, kTBTAltModeVID, kTBTVDO, kTBTVDOIndex));
  p.AddAltMode(mode_path);

  // Add the DP alt mode.
  mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode_path, kDPAltModeSID, kDPVDO_Sabrent,
                                kDPVDOIndex_Sabrent));
  p.AddAltMode(mode_path);

  EXPECT_TRUE(p.SupportsUsb());
  EXPECT_TRUE(p.SupportsDp());
  EXPECT_TRUE(p.SupportsTbt());
  EXPECT_FALSE(p.SupportsUsb4());
  EXPECT_EQ(PartnerTypeMetric::kTBTDPAltPeripheral, p.GetPartnerTypeMetric());
}

TEST_F(MetricsTest, CheckPartnerTypeTBTPeripheral) {
  // Orico drive enclosure TOM2T3-G40.
  Partner p(base::FilePath("foo"));
  p.SetPDRevision(PDRevision::k20);
  p.SetIdHeaderVDO(0xd400042b);
  p.SetCertStatVDO(0x0);
  p.SetProductVDO(0x634c0451);
  p.SetProductTypeVDO1(0x0);
  p.SetProductTypeVDO2(0x0);
  p.SetProductTypeVDO3(0x0);

  p.SetNumAltModes(1);

  // Add the TBT alt mode.
  std::string mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode_path, kTBTAltModeVID, kTBTVDO, kTBTVDOIndex));
  p.AddAltMode(mode_path);

  EXPECT_TRUE(p.SupportsUsb());
  EXPECT_FALSE(p.SupportsDp());
  EXPECT_TRUE(p.SupportsTbt());
  EXPECT_FALSE(p.SupportsUsb4());
  EXPECT_EQ(PartnerTypeMetric::kTBTPeripheral, p.GetPartnerTypeMetric());
}

TEST_F(MetricsTest, CheckPartnerTypeDPAltHub) {
  // Startech.com Type-C dock DK30C2DAGPD.
  Partner p(base::FilePath("foo"));
  p.SetPDRevision(PDRevision::k30);
  p.SetIdHeaderVDO(0x6c002109);
  p.SetCertStatVDO(0x0000038a);
  p.SetProductVDO(0x01030022);
  p.SetProductTypeVDO1(0x00000039);
  p.SetProductTypeVDO2(0x0);
  p.SetProductTypeVDO3(0x0);

  p.SetNumAltModes(1);

  // Add the DP alt mode.
  std::string mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode_path, kDPAltModeSID,
                                kDPVDO_Startech_DK30C2DAGPD,
                                kDPVDOIndex_Startech_DK30C2DAGPD));
  p.AddAltMode(mode_path);

  EXPECT_FALSE(p.SupportsUsb());
  EXPECT_TRUE(p.SupportsDp());
  EXPECT_FALSE(p.SupportsTbt());
  EXPECT_FALSE(p.SupportsUsb4());
  EXPECT_EQ(PartnerTypeMetric::kDPAltHub, p.GetPartnerTypeMetric());
}

TEST_F(MetricsTest, CheckPartnerTypePowerBrick) {
  // ASUS charger W19-065N2A.
  Partner p(base::FilePath("foo"));
  p.SetPDRevision(PDRevision::k30);
  p.SetIdHeaderVDO(0x01800b05);
  p.SetCertStatVDO(0x0);
  p.SetProductVDO(0x0);
  p.SetProductTypeVDO1(0x0);
  p.SetProductTypeVDO2(0x0);
  p.SetProductTypeVDO3(0x0);

  EXPECT_FALSE(p.SupportsUsb());
  EXPECT_FALSE(p.SupportsDp());
  EXPECT_FALSE(p.SupportsTbt());
  EXPECT_FALSE(p.SupportsUsb4());
  EXPECT_EQ(PartnerTypeMetric::kPowerBrick, p.GetPartnerTypeMetric());
}

// Test PartnerType metrics with an invalid id_header, using actual values from
// Google Zinger charger.
TEST_F(MetricsTest, CheckNoPartnerType) {
  auto port = std::make_unique<MockPort>(base::FilePath("bar"), 0);
  EXPECT_CALL(*port, GetDataRole())
      .WillRepeatedly(testing::Return(DataRole::kHost));
  EXPECT_CALL(*port, GetPowerRole())
      .WillRepeatedly(testing::Return(PowerRole::kSink));

  Partner p(base::FilePath("foo"), port.get());
  p.SetPDRevision(PDRevision::k20);
  p.SetIdHeaderVDO(0x040018d1);
  p.SetCertStatVDO(0x0);
  p.SetProductVDO(0x50120001);
  p.SetProductTypeVDO1(0x0);
  p.SetProductTypeVDO2(0x0);
  p.SetProductTypeVDO3(0x0);
  p.SetSupportsPD(true);

  EXPECT_FALSE(p.SupportsUsb());
  EXPECT_FALSE(p.SupportsDp());
  EXPECT_FALSE(p.SupportsTbt());
  EXPECT_FALSE(p.SupportsUsb4());
  EXPECT_EQ(DataRoleMetric::kDevice, p.GetDataRoleMetric());
  EXPECT_EQ(PowerRoleMetric::kSource, p.GetPowerRoleMetric());
  EXPECT_EQ(PartnerTypeMetric::kPDSourcingDevice, p.GetPartnerTypeMetric());
}

TEST_F(MetricsTest, CheckPartnerTypeOther) {
  // A partner which doesn't report any PD data.
  Partner p(base::FilePath("foo"));

  EXPECT_EQ(PartnerTypeMetric::kOther, p.GetPartnerTypeMetric());
}

TEST_F(MetricsTest, CheckCableSpeedTBTOnly) {
  // Belkin TBT3 Active Cable 40Gbps.
  Cable c(base::FilePath("foo"));

  c.SetPDRevision(PDRevision::k20);
  c.SetIdHeaderVDO(0x240020c2);
  c.SetCertStatVDO(0x0);
  c.SetProductVDO(0x40010);
  c.SetProductTypeVDO1(0x21085858);
  c.SetProductTypeVDO2(0x0);
  c.SetProductTypeVDO3(0x0);

  c.SetNumAltModes(2);

  std::string mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode_path, kTBTAltModeVID, 0x430001, 0));
  c.AddAltMode(mode_path);

  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode_path, 0x04b4, 0x1, 0));
  c.AddAltMode(mode_path);

  EXPECT_EQ(CableSpeedMetric::kTBTOnly10G20G, c.GetCableSpeedMetric());
}

TEST_F(MetricsTest, CheckCableSpeedPassive40Gbps) {
  // StarTech Passive Cable 40 Gbps PD 2.0
  Cable c(base::FilePath("foo"));

  c.SetPDRevision(PDRevision::k20);
  c.SetIdHeaderVDO(0x1c0020c2);
  c.SetCertStatVDO(0x000000b6);
  c.SetProductVDO(0x00010310);
  c.SetProductTypeVDO1(0x11082052);
  c.SetProductTypeVDO2(0x0);
  c.SetProductTypeVDO3(0x0);

  c.SetNumAltModes(0);

  EXPECT_EQ(CableSpeedMetric::kUSB3_1Gen1Gen2, c.GetCableSpeedMetric());
}

TEST_F(MetricsTest, CheckCableSpeedPassiveUSB31_Gen1) {
  // Hongju Full USB 3.1 Gen 1 5A passive cable.
  Cable c(base::FilePath("foo"));

  c.SetPDRevision(PDRevision::k20);
  c.SetIdHeaderVDO(0x18005694);
  c.SetCertStatVDO(0x88);
  c.SetProductVDO(0xce901a0);
  c.SetProductTypeVDO1(0x84051);
  c.SetProductTypeVDO2(0x0);
  c.SetProductTypeVDO3(0x0);

  c.SetNumAltModes(0);

  EXPECT_EQ(CableSpeedMetric::kUSB3_1Gen1, c.GetCableSpeedMetric());
}

TEST_F(MetricsTest, CheckPartnerLocationPreferRightSide) {
  auto port_manager = std::make_unique<PortManager>();

  // Vell
  auto port0 = std::make_unique<MockPort>(base::FilePath("port0"), 0);
  auto port1 = std::make_unique<MockPort>(base::FilePath("port1"), 1);
  auto port2 = std::make_unique<MockPort>(base::FilePath("port2"), 2);
  auto port3 = std::make_unique<MockPort>(base::FilePath("port3"), 3);
  EXPECT_CALL(*port0, GetPanel())
      .WillRepeatedly(testing::Return(Panel::kRight));
  EXPECT_CALL(*port1, GetPanel())
      .WillRepeatedly(testing::Return(Panel::kRight));
  EXPECT_CALL(*port2, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  EXPECT_CALL(*port3, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port0)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(1, std::move(port1)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(2, std::move(port2)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(3, std::move(port3)));

  port_manager->OnPartnerAddedOrRemoved(base::FilePath("fakepath"), 0, true);
  EXPECT_EQ(PartnerLocationMetric::kRightFirst,
            port_manager->GetPartnerLocationMetric(0, true));
  port_manager->OnPartnerAddedOrRemoved(base::FilePath("fakepath"), 1, true);
  EXPECT_EQ(PartnerLocationMetric::kRightSecondSameSideWithFirst,
            port_manager->GetPartnerLocationMetric(1, true));
  port_manager->OnPartnerAddedOrRemoved(base::FilePath("fakepath"), 2, true);
  EXPECT_EQ(PartnerLocationMetric::kUserHasNoChoice,
            port_manager->GetPartnerLocationMetric(2, true));
}

TEST_F(MetricsTest, CheckPartnerLocationPreferLeftSide) {
  auto port_manager = std::make_unique<PortManager>();

  // Vell
  auto port0 = std::make_unique<MockPort>(base::FilePath("port0"), 0);
  auto port1 = std::make_unique<MockPort>(base::FilePath("port1"), 1);
  auto port2 = std::make_unique<MockPort>(base::FilePath("port2"), 2);
  auto port3 = std::make_unique<MockPort>(base::FilePath("port3"), 3);
  EXPECT_CALL(*port0, GetPanel())
      .WillRepeatedly(testing::Return(Panel::kRight));
  EXPECT_CALL(*port1, GetPanel())
      .WillRepeatedly(testing::Return(Panel::kRight));
  EXPECT_CALL(*port2, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  EXPECT_CALL(*port3, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port0)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(1, std::move(port1)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(2, std::move(port2)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(3, std::move(port3)));

  port_manager->OnPartnerAddedOrRemoved(base::FilePath("fakepath"), 2, true);
  EXPECT_EQ(PartnerLocationMetric::kLeftFirst,
            port_manager->GetPartnerLocationMetric(2, true));
  port_manager->OnPartnerAddedOrRemoved(base::FilePath("fakepath"), 3, true);
  EXPECT_EQ(PartnerLocationMetric::kLeftSecondSameSideWithFirst,
            port_manager->GetPartnerLocationMetric(3, true));
  port_manager->OnPartnerAddedOrRemoved(base::FilePath("fakepath"), 0, true);
  EXPECT_EQ(PartnerLocationMetric::kUserHasNoChoice,
            port_manager->GetPartnerLocationMetric(0, true));
}

TEST_F(MetricsTest, CheckPartnerLocationNoPreference) {
  auto port_manager = std::make_unique<PortManager>();

  // Vell
  auto port0 = std::make_unique<MockPort>(base::FilePath("port0"), 0);
  auto port1 = std::make_unique<MockPort>(base::FilePath("port1"), 1);
  auto port2 = std::make_unique<MockPort>(base::FilePath("port2"), 2);
  auto port3 = std::make_unique<MockPort>(base::FilePath("port3"), 3);
  EXPECT_CALL(*port0, GetPanel())
      .WillRepeatedly(testing::Return(Panel::kRight));
  EXPECT_CALL(*port1, GetPanel())
      .WillRepeatedly(testing::Return(Panel::kRight));
  EXPECT_CALL(*port2, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  EXPECT_CALL(*port3, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port0)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(1, std::move(port1)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(2, std::move(port2)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(3, std::move(port3)));

  port_manager->OnPartnerAddedOrRemoved(base::FilePath("fakepath"), 0, true);
  EXPECT_EQ(PartnerLocationMetric::kRightColdplugged,
            port_manager->GetPartnerLocationMetric(0, false));
  port_manager->OnPartnerAddedOrRemoved(base::FilePath("fakepath"), 2, true);
  EXPECT_EQ(PartnerLocationMetric::kLeftSecondOppositeSideToFirst,
            port_manager->GetPartnerLocationMetric(2, true));
  port_manager->OnPartnerAddedOrRemoved(base::FilePath("fakepath"), 3, true);
  EXPECT_EQ(PartnerLocationMetric::kLeftThirdOrLater,
            port_manager->GetPartnerLocationMetric(3, true));
}

TEST_F(MetricsTest, CheckPowerSourceLocation) {
  auto port_manager = std::make_unique<PortManager>();

  // Vell
  auto port0 = std::make_unique<MockPort>(base::FilePath("port0"), 0);
  auto port1 = std::make_unique<MockPort>(base::FilePath("port1"), 1);
  auto port2 = std::make_unique<MockPort>(base::FilePath("port2"), 2);
  auto port3 = std::make_unique<MockPort>(base::FilePath("port3"), 3);
  EXPECT_CALL(*port0, GetPanel())
      .WillRepeatedly(testing::Return(Panel::kRight));
  EXPECT_CALL(*port1, GetPanel())
      .WillRepeatedly(testing::Return(Panel::kRight));
  EXPECT_CALL(*port2, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  EXPECT_CALL(*port3, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port0)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(1, std::move(port1)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(2, std::move(port2)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(3, std::move(port3)));

  EXPECT_EQ(PowerSourceLocationMetric::kRightFirst,
            port_manager->GetPowerSourceLocationMetric(0));
  port_manager->port_num_previously_sink = 0;
  EXPECT_EQ(PowerSourceLocationMetric::kRightConstant,
            port_manager->GetPowerSourceLocationMetric(1));
  port_manager->port_num_previously_sink = 1;
  EXPECT_EQ(PowerSourceLocationMetric::kLeftSwitched,
            port_manager->GetPowerSourceLocationMetric(2));
  port_manager->port_num_previously_sink = 2;
  EXPECT_EQ(PowerSourceLocationMetric::kLeftConstant,
            port_manager->GetPowerSourceLocationMetric(3));
  port_manager->port_num_previously_sink = 3;
  EXPECT_EQ(PowerSourceLocationMetric::kRightSwitched,
            port_manager->GetPowerSourceLocationMetric(0));
}

TEST_F(MetricsTest, CheckPowerSourceLocationNoChoice) {
  auto port_manager = std::make_unique<PortManager>();

  // Primus
  auto port0 = std::make_unique<MockPort>(base::FilePath("port0"), 0);
  auto port1 = std::make_unique<MockPort>(base::FilePath("port1"), 1);
  EXPECT_CALL(*port0, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  EXPECT_CALL(*port1, GetPanel()).WillRepeatedly(testing::Return(Panel::kLeft));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(0, std::move(port0)));
  port_manager->ports_.insert(
      std::pair<int, std::unique_ptr<Port>>(1, std::move(port1)));

  EXPECT_EQ(PowerSourceLocationMetric::kUserHasNoChoice,
            port_manager->GetPowerSourceLocationMetric(0));
  port_manager->port_num_previously_sink = 0;
  EXPECT_EQ(PowerSourceLocationMetric::kUserHasNoChoice,
            port_manager->GetPowerSourceLocationMetric(1));
}

// Checks the behaviour of the DP Success metric reporting
// logic for a variety of use cases:
// - System doesn't return a valid HPD
// - System does return a valid HPD:
//   + DP = 0, HPD = 0
//   + DP = 1, HPD = 0
//   + DP = 1, HPD = 1
TEST_F(MetricsTest, CheckDpSuccessMetric) {
  auto ec_util = std::make_unique<MockECUtil>();
  EXPECT_CALL(*ec_util, HpdState(0, _))
      .Times(1)
      .WillOnce(testing::Return(false));

  auto port = std::make_unique<MockPort>(base::FilePath("port0"), 0);
  port->SetECUtil(ec_util.get());

  DpSuccessMetric result;
  EXPECT_FALSE(port->GetDpEntryState(result));

  bool hpd = false;
  bool dp = false;

  ec_util = std::make_unique<MockECUtil>();
  EXPECT_CALL(*ec_util, HpdState(0, _))
      .WillOnce(DoAll(testing::SetArgPointee<1>(hpd), testing::Return(true)));
  EXPECT_CALL(*ec_util, DpState(0, _))
      .WillOnce(DoAll(testing::SetArgPointee<1>(dp), testing::Return(true)));
  port->SetECUtil(ec_util.get());
  ASSERT_TRUE(port->GetDpEntryState(result));
  EXPECT_EQ(DpSuccessMetric::kFail, result);

  dp = true;
  ec_util = std::make_unique<MockECUtil>();
  EXPECT_CALL(*ec_util, HpdState(0, _))
      .WillOnce(DoAll(testing::SetArgPointee<1>(hpd), testing::Return(true)));
  EXPECT_CALL(*ec_util, DpState(0, _))
      .WillOnce(DoAll(testing::SetArgPointee<1>(dp), testing::Return(true)));
  port->SetECUtil(ec_util.get());
  ASSERT_TRUE(port->GetDpEntryState(result));
  EXPECT_EQ(DpSuccessMetric::kSuccessNoHpd, result);

  hpd = true;
  ec_util = std::make_unique<MockECUtil>();
  EXPECT_CALL(*ec_util, HpdState(0, _))
      .WillOnce(DoAll(testing::SetArgPointee<1>(hpd), testing::Return(true)));
  EXPECT_CALL(*ec_util, DpState(0, _))
      .WillOnce(DoAll(testing::SetArgPointee<1>(dp), testing::Return(true)));
  port->SetECUtil(ec_util.get());
  ASSERT_TRUE(port->GetDpEntryState(result));
  EXPECT_EQ(DpSuccessMetric::kSuccessHpd, result);
}

}  // namespace typecd
