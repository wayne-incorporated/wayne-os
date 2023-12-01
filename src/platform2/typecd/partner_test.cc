// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/partner.h"

#include <string>

#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "typecd/alt_mode.h"
#include "typecd/test_constants.h"
#include "typecd/test_utils.h"

namespace {

const uint32_t kPartnerPDProductVDO = 0xdeadbeef;
const uint32_t kPartnerPDProductVDO2 = 0xabcdabcd;
const uint32_t kPartnerPDCertStatVDO = 0xbeefdead;
const uint32_t kPartnerPDIdHeaderVDO = 0x12341234;

}  // namespace

namespace typecd {

class PartnerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(scoped_temp_dir_.CreateUniqueTempDir());
    temp_dir_ = scoped_temp_dir_.GetPath();
  }

 public:
  base::FilePath temp_dir_;
  base::ScopedTempDir scoped_temp_dir_;
};

// Check that calls of AddAltMode() which are done explicitly function
// correctly. Also check that trying to add the same alt mode twice fails. While
// we are here, also check that calls to DiscoveryComplete return the right
// responses at various times of the discovery process.
TEST_F(PartnerTest, AltModeManualAddition) {
  auto partner_path = temp_dir_.Append(std::string("port0-partner"));
  ASSERT_TRUE(base::CreateDirectory(partner_path));

  Partner p(partner_path);

  // Set up fake sysfs paths.

  // Add the sysfs entry and run the update code (in production, this
  // will run in response to a udev event, but since we don't have that here,
  // call it manually).
  std::string num_altmodes("2");
  ASSERT_TRUE(base::WriteFile(partner_path.Append("number_of_alternate_modes"),
                              num_altmodes.c_str(), num_altmodes.length()));
  p.UpdatePDInfoFromSysfs();

  // Add the 1st alt mode sysfs directory.
  std::string mode0_dirname =
      base::StringPrintf("port%d-partner.%d", 0, kDPAltModeIndex);
  auto mode0_path = partner_path.Append(mode0_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode0_path, kDPAltModeSID, kDPVDO, kDPVDOIndex));
  EXPECT_TRUE(p.AddAltMode(mode0_path));

  // We still have 1 more alt mode to register.
  EXPECT_FALSE(p.DiscoveryComplete());

  // Add the 2nd alt mode sysfs directory.
  std::string mode1_dirname =
      base::StringPrintf("port%d-partner.%d", 0, kTBTAltModeIndex);
  auto mode1_path = partner_path.Append(mode1_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode1_path, kTBTAltModeVID, kTBTVDO, kTBTVDOIndex));

  // Add extra white spaces to ensure malformed strings can be parsed. We can do
  // this by overwriting whatever the pre-existing SVID syspath file is.
  auto mode1_svid = base::StringPrintf("%x    ", kTBTAltModeVID);
  ASSERT_TRUE(base::WriteFile(mode1_path.Append("svid"), mode1_svid.c_str(),
                              mode1_svid.length()));
  EXPECT_TRUE(p.AddAltMode(mode1_path));

  // Discovery can now be considered complete.
  EXPECT_TRUE(p.DiscoveryComplete());

  // Trying to add an existing alt mode again should also return true; an INFO
  // log message is displayed but nothing is added.
  EXPECT_TRUE(p.AddAltMode(mode1_path));
}

// Verify that partner PD identity VDOs get scanned and stored correctly.
// Also check that once PD identity VDOs are scanned, subsequent changes to PD
// identity aren't considered.
// Finally, for the case where the "number_of_alternate_modes" attribute gets
// updated after the initial partner registration, ensure that the attribute
// gets parsed and stored correctly.
TEST_F(PartnerTest, PDIdentityScan) {
  // Set up fake sysfs paths.
  auto partner_path = temp_dir_.Append(std::string("port0-partner"));
  ASSERT_TRUE(base::CreateDirectory(partner_path));

  auto identity_path = partner_path.Append(std::string("identity"));
  ASSERT_TRUE(base::CreateDirectory(identity_path));

  // First fill the identity with 0 values.
  auto cert_stat_vdo = base::StringPrintf("0x0");
  ASSERT_TRUE(base::WriteFile(identity_path.Append("cert_stat"),
                              cert_stat_vdo.c_str(), cert_stat_vdo.length()));
  auto id_header_vdo = base::StringPrintf("0x0");
  ASSERT_TRUE(base::WriteFile(identity_path.Append("id_header"),
                              id_header_vdo.c_str(), id_header_vdo.length()));
  auto product_vdo = base::StringPrintf("0x0");
  ASSERT_TRUE(base::WriteFile(identity_path.Append("product"),
                              product_vdo.c_str(), product_vdo.length()));
  auto product_type_vdo1 = base::StringPrintf("0x0");
  ASSERT_TRUE(base::WriteFile(identity_path.Append("product_type_vdo1"),
                              product_type_vdo1.c_str(),
                              product_type_vdo1.length()));
  auto product_type_vdo2 = base::StringPrintf("0x0");
  ASSERT_TRUE(base::WriteFile(identity_path.Append("product_type_vdo2"),
                              product_type_vdo2.c_str(),
                              product_type_vdo2.length()));
  auto product_type_vdo3 = base::StringPrintf("0x0");
  ASSERT_TRUE(base::WriteFile(identity_path.Append("product_type_vdo3"),
                              product_type_vdo3.c_str(),
                              product_type_vdo3.length()));

  Partner p(partner_path);

  // Update the VDOs with some values
  cert_stat_vdo = base::StringPrintf("%#x", kPartnerPDCertStatVDO);
  ASSERT_TRUE(base::WriteFile(identity_path.Append("cert_stat"),
                              cert_stat_vdo.c_str(), cert_stat_vdo.length()));
  id_header_vdo = base::StringPrintf("%#x", kPartnerPDIdHeaderVDO);
  ASSERT_TRUE(base::WriteFile(identity_path.Append("id_header"),
                              id_header_vdo.c_str(), id_header_vdo.length()));
  product_vdo = base::StringPrintf("%#x", kPartnerPDProductVDO);
  ASSERT_TRUE(base::WriteFile(identity_path.Append("product"),
                              product_vdo.c_str(), product_vdo.length()));

  // Since we don't have a UdevMonitor, trigger the PD VDO update manually.
  p.UpdatePDIdentityVDOs();
  EXPECT_EQ(kPartnerPDCertStatVDO, p.GetCertStateVDO());
  EXPECT_EQ(kPartnerPDIdHeaderVDO, p.GetIdHeaderVDO());
  EXPECT_EQ(kPartnerPDProductVDO, p.GetProductVDO());

  // Fake an update to the Product VDO, then ensure it doesn't get accepted.
  product_vdo = base::StringPrintf("%#x", kPartnerPDProductVDO2);
  ASSERT_TRUE(base::WriteFile(identity_path.Append("product"),
                              product_vdo.c_str(), product_vdo.length()));
  p.UpdatePDIdentityVDOs();

  EXPECT_NE(kPartnerPDProductVDO2, p.GetProductVDO());

  // Number of alternate modes is still not set, so it should return -1.
  EXPECT_EQ(-1, p.GetNumAltModes());

  // Now add the sysfs entry and run the update code (in production, this
  // will run in response to a udev event, but since we don't have that here,
  // call it manually).
  auto num_altmodes = base::StringPrintf("0");
  ASSERT_TRUE(base::WriteFile(partner_path.Append("number_of_alternate_modes"),
                              num_altmodes.c_str(), num_altmodes.length()));
  p.UpdatePDInfoFromSysfs();

  EXPECT_EQ(0, p.GetNumAltModes());
}

// Test that a partner's "supports_usb_power_delivery" sysfs attribute gets
// parsed correctly.
TEST_F(PartnerTest, SupportsPD) {
  // Set up fake sysfs paths.
  auto partner_path = temp_dir_.Append(std::string("port0-partner"));
  ASSERT_TRUE(base::CreateDirectory(partner_path));

  auto val = std::string("0xasdfads0");
  auto pd_path = partner_path.Append("supports_usb_power_delivery");
  ASSERT_TRUE(base::WriteFile(pd_path, val.c_str(), val.length()));

  Partner p(partner_path);
  EXPECT_FALSE(p.GetSupportsPD());

  val = std::string("yes");
  ASSERT_TRUE(base::WriteFile(pd_path, val.c_str(), val.length()));
  p.UpdateSupportsPD();
  EXPECT_TRUE(p.GetSupportsPD());

  val = std::string("yesno");
  ASSERT_TRUE(base::WriteFile(pd_path, val.c_str(), val.length()));
  p.UpdateSupportsPD();
  EXPECT_FALSE(p.GetSupportsPD());
}

// Test that a PowerProfile gets successfully created, and then removed
// for a partner.
TEST_F(PartnerTest, PowerProfile) {
  // Set up fake sysfs paths.
  auto partner_path = temp_dir_.Append(std::string("port0-partner"));
  ASSERT_TRUE(base::CreateDirectory(partner_path));

  auto partner = std::make_unique<Partner>(partner_path);
  // First check that we don't have a PowerProfile when the directory isn't
  // present.
  EXPECT_FALSE(partner->power_profile_);

  auto pd_path = partner_path.Append(std::string("usb_power_delivery"));
  ASSERT_TRUE(base::CreateDirectory(pd_path));

  auto val = std::string("yes");
  auto supports_path = partner_path.Append("supports_usb_power_delivery");
  ASSERT_TRUE(base::WriteFile(supports_path, val.c_str(), val.length()));

  partner = std::make_unique<Partner>(partner_path);
  partner->AddPowerProfile();
  EXPECT_TRUE(partner->power_profile_);

  partner->RemovePowerProfile();
  EXPECT_TRUE(!partner->power_profile_);
}

}  // namespace typecd
