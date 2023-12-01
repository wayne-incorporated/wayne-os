// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/cable.h"

#include <string>

#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "typecd/test_constants.h"
#include "typecd/test_utils.h"

namespace typecd {

class CableTest : public ::testing::Test {};

// Check the PD Identity cable speed logic for TBT3 compatibility mode entry
// for various cable PDO values.
// Since we don't have sysfs, we can just manually set the PD identity VDOs.
TEST_F(CableTest, TBT3PDIdentityCheck) {
  // Set up a temp dir.
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  base::FilePath temp_dir = scoped_temp_dir.GetPath();

  auto cable = std::make_unique<Cable>(base::FilePath(kFakePort0CableSysPath));

  // Create sysfs path for SOP' plug.
  auto sop_plug_path = temp_dir.Append(std::string("port0-plug0"));
  ASSERT_TRUE(base::CreateDirectory(sop_plug_path));

  // Apple Active TBT3 Pro Cable PD 3.0
  cable->SetPDRevision(PDRevision::k30);
  cable->SetIdHeaderVDO(0x240005ac);
  cable->SetCertStatVDO(0x0);
  cable->SetProductVDO(0x72043002);
  cable->SetProductTypeVDO1(0x434858da);
  cable->SetProductTypeVDO2(0x5a5f0001);
  cable->SetProductTypeVDO3(0x0);
  cable->SetNumAltModes(2);

  std::string mode0_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  auto mode0_path = sop_plug_path.Append(mode0_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode0_path, kTBTAltModeVID, 0x00cb0001, 0));
  EXPECT_TRUE(cable->AddAltMode(mode0_path));

  std::string mode1_dirname = base::StringPrintf("port%d-plug0.%d", 0, 1);
  auto mode1_path = sop_plug_path.Append(mode1_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode1_path, kDPAltModeSID, 0x000c0c0c, 0));
  EXPECT_TRUE(cable->AddAltMode(mode1_path));

  EXPECT_TRUE(cable->TBT3PDIdentityCheck());

  // Apple Active TBT3 Pro Cable PD 2.0
  cable->SetPDRevision(PDRevision::k20);
  cable->SetIdHeaderVDO(0x240005ac);
  cable->SetCertStatVDO(0x0);
  cable->SetProductVDO(0x72043002);
  cable->SetProductTypeVDO1(0x43085fda);
  cable->SetProductTypeVDO2(0x0);
  cable->SetProductTypeVDO3(0x0);
  // Alt Modes are the same for this cable PD 2.0 vs. PD 3.0
  EXPECT_TRUE(cable->TBT3PDIdentityCheck());
  cable->RemoveAltMode(mode0_path);
  cable->RemoveAltMode(mode1_path);

  // Belkin Active TBT3 Cable F2CD085bt2M-BLK PD 2.0
  cable->SetPDRevision(PDRevision::k20);
  cable->SetIdHeaderVDO(0x240020c2);
  cable->SetCertStatVDO(0x0);
  cable->SetProductVDO(0x00040010);
  cable->SetProductTypeVDO1(0x21085858);
  cable->SetProductTypeVDO2(0x0);
  cable->SetProductTypeVDO3(0x0);

  mode0_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  mode0_path = sop_plug_path.Append(mode1_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode0_path, kTBTAltModeVID, 0x00430001, 0));
  EXPECT_TRUE(cable->AddAltMode(mode0_path));

  EXPECT_TRUE(cable->TBT3PDIdentityCheck());
  cable->RemoveAltMode(mode0_path);

  // Cable Matters Active USB 3.2 + DP Alt Mode Cable PD 2.0
  cable->SetPDRevision(PDRevision::k20);
  cable->SetIdHeaderVDO(0x24000bda);
  cable->SetCertStatVDO(0x0);
  cable->SetProductVDO(0x00000209);
  cable->SetProductTypeVDO1(0x120851b2);
  cable->SetProductTypeVDO2(0x0);
  cable->SetProductTypeVDO3(0x0);

  mode0_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  mode0_path = sop_plug_path.Append(mode1_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode0_path, kDPAltModeSID, 0x001c0005, kDPVDOIndex));
  EXPECT_TRUE(cable->AddAltMode(mode0_path));

  EXPECT_FALSE(cable->TBT3PDIdentityCheck());
  cable->RemoveAltMode(mode0_path);

  // StarTech Passive Cable 40 Gbps PD 2.0
  cable->SetPDRevision(PDRevision::k20);
  cable->SetIdHeaderVDO(0x1c0020c2);
  cable->SetCertStatVDO(0x000000b6);
  cable->SetProductVDO(0x00010310);
  cable->SetProductTypeVDO1(0x11082052);
  cable->SetProductTypeVDO2(0x0);
  cable->SetProductTypeVDO3(0x0);

  mode0_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  mode0_path = sop_plug_path.Append(mode1_dirname);
  ASSERT_TRUE(CreateFakeAltMode(mode0_path, kTBTAltModeVID, 0x00030001, 0));
  EXPECT_TRUE(cable->AddAltMode(mode0_path));

  EXPECT_TRUE(cable->TBT3PDIdentityCheck());
  cable->RemoveAltMode(mode0_path);

  // Nekteck 100W USB 2.0 5A Cable PD 3.0
  cable->SetPDRevision(PDRevision::k20);
  cable->SetIdHeaderVDO(0x18002e98);
  cable->SetCertStatVDO(0x00001533);
  cable->SetProductVDO(0x00010200);
  cable->SetProductTypeVDO1(0xc1082040);
  cable->SetProductTypeVDO2(0x0);
  cable->SetProductTypeVDO3(0x0);
  cable->SetNumAltModes(0);
  EXPECT_FALSE(cable->TBT3PDIdentityCheck());

  // Nekteck 100W USB 2.0 Cable PD 2.0
  cable->SetPDRevision(PDRevision::k20);
  cable->SetIdHeaderVDO(0x18002e98);
  cable->SetCertStatVDO(0x00001533);
  cable->SetProductVDO(0x00010200);
  cable->SetProductTypeVDO1(0xc10827d0);
  cable->SetProductTypeVDO2(0x0);
  cable->SetProductTypeVDO3(0x0);
  cable->SetNumAltModes(0);
  EXPECT_FALSE(cable->TBT3PDIdentityCheck());
}

// Check that calls of AddAltMode() done explicitly function correctly. Also
// check that trying to add the same alt mode twice fails.
TEST_F(CableTest, AltModeManualAddition) {
  // Set up a temp dir.
  base::ScopedTempDir scoped_temp_dir;
  ASSERT_TRUE(scoped_temp_dir.CreateUniqueTempDir());
  base::FilePath temp_dir = scoped_temp_dir.GetPath();

  // Create the sysfs path for the cable and plug.
  auto cable_path = temp_dir.Append(std::string("port0-cable"));
  ASSERT_TRUE(base::CreateDirectory(cable_path));
  Cable cable((base::FilePath(kFakePort0CableSysPath)));

  // Create sysfs path for SOP' plug.
  auto sop_plug_path = temp_dir.Append(std::string("port0-plug0"));
  ASSERT_TRUE(base::CreateDirectory(sop_plug_path));

  // TODO(b/172097194): Modify the test to check for DiscoveryComplete().

  // Set up fake sysfs paths for alternate modes.
  std::string mode0_dirname =
      base::StringPrintf("port%d-plug0.%d", 0, kDPAltModeIndex);
  auto mode0_path = sop_plug_path.Append(mode0_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode0_path, kDPAltModeSID, kDPVDO, kDPVDOIndex));
  EXPECT_TRUE(cable.AddAltMode(mode0_path));

  std::string mode1_dirname =
      base::StringPrintf("port%d-plug0.%d", 0, kTBTAltModeIndex);
  auto mode1_path = sop_plug_path.Append(mode1_dirname);
  ASSERT_TRUE(
      CreateFakeAltMode(mode1_path, kTBTAltModeVID, kTBTVDO, kTBTVDOIndex));
  EXPECT_TRUE(cable.AddAltMode(mode1_path));

  // Trying to add an existing alt mode again should also return true; an INFO
  // log message is displayed but nothing is added.
  EXPECT_TRUE(cable.AddAltMode(mode1_path));
}

}  // namespace typecd
