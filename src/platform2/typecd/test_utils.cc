// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/test_utils.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <memory>
#include <string>

#include "typecd/test_constants.h"

namespace typecd {

bool CreateFakeAltMode(const base::FilePath& mode_path,
                       uint16_t svid,
                       uint32_t vdo,
                       uint32_t vdo_index) {
  if (!base::CreateDirectory(mode_path)) {
    PLOG(ERROR) << "Couldn't create directory: " << mode_path;
    return false;
  }

  auto mode_svid = base::StringPrintf("%x", svid);
  if (!base::WriteFile(mode_path.Append("svid"), mode_svid.c_str(),
                       mode_svid.length())) {
    PLOG(ERROR) << "Failed to create SVID in directory " << mode_path;
    return false;
  }

  auto mode_vdo = base::StringPrintf("%#x", vdo);
  if (!base::WriteFile(mode_path.Append("vdo"), mode_vdo.c_str(),
                       mode_vdo.length())) {
    PLOG(ERROR) << "Failed to create VDO in directory " << mode_path;
    return false;
  }

  auto mode_vdo_index = base::StringPrintf("%x", vdo_index);
  if (!base::WriteFile(mode_path.Append("mode"), mode_vdo_index.c_str(),
                       mode_vdo_index.length())) {
    PLOG(ERROR) << "Failed to create VDO mode index in directory " << mode_path;
    return false;
  }

  return true;
}

void AddUnbrandedUSB2Cable(Port& port) {
  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for the unbranded USB2 cable.
  port.cable_->SetPDRevision(PDRevision::kNone);
  port.cable_->SetIdHeaderVDO(0x0);
  port.cable_->SetCertStatVDO(0x0);
  port.cable_->SetProductVDO(0x0);
  port.cable_->SetProductTypeVDO1(0x0);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddNekteckUSB2PassiveCable(Port& port) {
  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // Nekteck USB 2.0 cable (5A).
  port.cable_->SetPDRevision(PDRevision::k30);
  port.cable_->SetIdHeaderVDO(0x18002e98);
  port.cable_->SetCertStatVDO(0x1533);
  port.cable_->SetProductVDO(0x10200);
  port.cable_->SetProductTypeVDO1(0xc1082040);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddHongjuUSB3p1Gen1Cable(Port& port) {
  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for the Hongju Full USB 3.1 Gen 1 5A passive cable.
  port.cable_->SetPDRevision(PDRevision::k20);
  port.cable_->SetIdHeaderVDO(0x18005694);
  port.cable_->SetCertStatVDO(0x88);
  port.cable_->SetProductVDO(0xce901a0);
  port.cable_->SetProductTypeVDO1(0x84051);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddHPUSB3p2Gen1Cable(Port& port) {
  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for the HP USB3.2 Gen1 cable.
  port.cable_->SetPDRevision(PDRevision::k30);
  port.cable_->SetIdHeaderVDO(0x180003f0);
  port.cable_->SetCertStatVDO(0x4295);
  port.cable_->SetProductVDO(0x264700a0);
  port.cable_->SetProductTypeVDO1(0x11084851);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddAnkerUSB3p2Gen2Cable(Port& port) {
  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for the Anker USB3.2 Gen2 cable.
  port.cable_->SetPDRevision(PDRevision::k20);
  port.cable_->SetIdHeaderVDO(0x1c00291a);
  port.cable_->SetCertStatVDO(0xd0b);
  port.cable_->SetProductVDO(0x1ff90000);
  port.cable_->SetProductTypeVDO1(0x11082032);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddCableMatters20GbpsCable(Port& port) {
  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // Cable Matters 20 Gbps USB4 cable.
  port.AddCable(base::FilePath(kFakePort0CableSysPath));
  port.cable_->SetPDRevision(PDRevision::k30);
  port.cable_->SetIdHeaderVDO(0x1860060f);
  port.cable_->SetCertStatVDO(0x20ef);
  port.cable_->SetProductVDO(0x0);
  port.cable_->SetProductTypeVDO1(0x11084042);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddUnbrandedTBT3Cable(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for the unbranded TBT3 active cable.
  port.cable_->SetPDRevision(PDRevision::k20);
  port.cable_->SetIdHeaderVDO(0x1c0020c2);
  port.cable_->SetCertStatVDO(0xba);
  port.cable_->SetProductVDO(0xa31d0310);
  port.cable_->SetProductTypeVDO1(0x21082852);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.cable_->SetNumAltModes(2);
  auto mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, 0x4b4, 0x1, 0))
    return;
  port.AddCableAltMode(mode_path);
  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kTBTAltModeVID, 0x30001, 0))
    return;
  port.AddCableAltMode(mode_path);
}

void AddBelkinTBT3PassiveCable(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for Belkin TBT3 passive cable.
  port.cable_->SetPDRevision(PDRevision::k30);
  port.cable_->SetIdHeaderVDO(0x1c002b1d);
  port.cable_->SetCertStatVDO(0x0);
  port.cable_->SetProductVDO(0x150c0001);
  port.cable_->SetProductTypeVDO1(0x11082042);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.cable_->SetNumAltModes(1);
  auto mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kTBTAltModeVID, 0x30001, 0))
    return;
  port.AddCableAltMode(mode_path);
}

void AddBelkinTBT3ActiveCable(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for Belkin TBT3 active cable.
  port.cable_->SetPDRevision(PDRevision::k20);
  port.cable_->SetIdHeaderVDO(0x240020c2);
  port.cable_->SetCertStatVDO(0x0);
  port.cable_->SetProductVDO(0x40010);
  port.cable_->SetProductTypeVDO1(0x21085858);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.cable_->SetNumAltModes(2);
  auto mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kTBTAltModeVID, 0x430001, 0))
    return;
  port.AddCableAltMode(mode_path);
  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, 0x04b4, 0x1, 0))
    return;
  port.AddCableAltMode(mode_path);
}

void AddAppleTBT3ProCable(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for the Apple TBT3 Pro cable.
  port.cable_->SetPDRevision(PDRevision::k30);
  port.cable_->SetIdHeaderVDO(0x240005ac);
  port.cable_->SetCertStatVDO(0x0);
  port.cable_->SetProductVDO(0x72043002);
  port.cable_->SetProductTypeVDO1(0x434858da);
  port.cable_->SetProductTypeVDO2(0x5a5f0001);
  port.cable_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.cable_->SetNumAltModes(5);
  auto mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kTBTAltModeVID, 0xcb0001, 0))
    return;
  port.AddCableAltMode(mode_path);
  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kDPAltModeSID, 0xc0c0c, 0))
    return;
  port.AddCableAltMode(mode_path);
  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 2);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, 0x05ac, 0x5, 0))
    return;
  port.AddCableAltMode(mode_path);
  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 3);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, 0x05ac, 0x7, 1))
    return;
  port.AddCableAltMode(mode_path);
  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 4);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, 0x05ac, 0x2, 2))
    return;
  port.AddCableAltMode(mode_path);
}

void AddCalDigitTBT4Cable(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for the CalDigit TBT4 cable.
  port.cable_->SetPDRevision(PDRevision::k30);
  port.cable_->SetIdHeaderVDO(0x1c002b1d);
  port.cable_->SetCertStatVDO(0x0);
  port.cable_->SetProductVDO(0x15120001);
  port.cable_->SetProductTypeVDO1(0x11082043);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.cable_->SetNumAltModes(2);
  auto mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, 0x1e4e, 0x90310119, 0))
    return;
  port.AddCableAltMode(mode_path);
  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kTBTAltModeVID, 0x430001, 0))
    return;
  port.AddCableAltMode(mode_path);
}

void AddCableMattersTBT4LRDCable(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // Cable Matters TBT4 LRD Cable
  port.cable_->SetPDRevision(PDRevision::k20);
  port.cable_->SetIdHeaderVDO(0x1c002b1d);
  port.cable_->SetCertStatVDO(0x0);
  port.cable_->SetProductVDO(0x19010097);
  port.cable_->SetProductTypeVDO1(0x3208485a);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.cable_->SetNumAltModes(3);
  auto mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, 0x04b4, 0x1, 0))
    return;
  port.AddCableAltMode(mode_path);
  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kTBTAltModeVID, 0x28b0001, 0))
    return;
  port.AddCableAltMode(mode_path);
  mode_dirname = base::StringPrintf("port%d-plug0.%d", 0, 2);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kDPAltModeSID, 0xc0c0c, 0))
    return;
  port.AddCableAltMode(mode_path);
}

void AddStartech40GbpsCable(Port& port) {
  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // StarTech Passive Cable 40 Gbps PD 2.0
  port.cable_->SetPDRevision(PDRevision::k20);
  port.cable_->SetIdHeaderVDO(0x1c0020c2);
  port.cable_->SetCertStatVDO(0xb6);
  port.cable_->SetProductVDO(0x10310);
  port.cable_->SetProductTypeVDO1(0x11082052);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddTargusUSB3p1Gen1Cable(Port& port) {
  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // Targus USB 3.1 Gen 1 passive cable
  port.cable_->SetPDRevision(PDRevision::k20);
  port.cable_->SetIdHeaderVDO(0x18000000);
  port.cable_->SetCertStatVDO(0x00002074);
  port.cable_->SetProductVDO(0x000000a0);
  port.cable_->SetProductTypeVDO1(0x000827b1);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddTargusUSB3p2Gen2Cable(Port& port) {
  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // Targus USB 3.2 Gen 2 passive cable
  port.cable_->SetPDRevision(PDRevision::k30);
  port.cable_->SetIdHeaderVDO(0x18001048);
  port.cable_->SetCertStatVDO(0x0000232e);
  port.cable_->SetProductVDO(0x138b0310);
  port.cable_->SetProductTypeVDO1(0x11082842);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddCableMattersDock(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // PD ID VDOs for the Cable Matters dock.
  port.partner_->SetPDRevision(PDRevision::k30);
  port.partner_->SetIdHeaderVDO(0x6c0004b4);
  port.partner_->SetCertStatVDO(0x0);
  port.partner_->SetProductVDO(0xf6490222);
  port.partner_->SetProductTypeVDO1(0x8);
  port.partner_->SetProductTypeVDO2(0x0);
  port.partner_->SetProductTypeVDO3(0x0);

  // Add partner alternate modes.
  port.partner_->SetNumAltModes(1);
  std::string mode0_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode0_path = temp_dir_.Append(mode0_dirname);
  if (!CreateFakeAltMode(mode0_path, kDPAltModeSID, 0x405, 0))
    return;
  port.AddRemovePartnerAltMode(mode0_path, true);

  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // PD ID VDOs for the Cable Matters dock
  port.cable_->SetPDRevision(PDRevision::kNone);
  port.cable_->SetIdHeaderVDO(0x0);
  port.cable_->SetCertStatVDO(0x0);
  port.cable_->SetProductVDO(0x0);
  port.cable_->SetProductTypeVDO1(0x0);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddDellWD19TBDock(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // PD ID VDOs for the Dell WD19TB Titan Ridge Dock.
  port.partner_->SetPDRevision(PDRevision::k30);
  port.partner_->SetIdHeaderVDO(0x4c0041c3);
  port.partner_->SetCertStatVDO(0x0);
  port.partner_->SetProductVDO(0xb0700712);
  port.partner_->SetProductTypeVDO1(0x0);
  port.partner_->SetProductTypeVDO2(0x0);
  port.partner_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.partner_->SetNumAltModes(4);
  std::string mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kTBTAltModeVID, kTBTVDO, kTBTVDOIndex))
    return;
  port.AddRemovePartnerAltMode(mode_path, true);
  mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kDPAltModeSID, kDPVDO_WD19TB, 0))
    return;
  port.AddRemovePartnerAltMode(mode_path, true);
  mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 2);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kDellSVID_WD19TB, kDell_WD19TB_VDO1, 0))
    return;
  port.AddRemovePartnerAltMode(mode_path, true);
  mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 3);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kDellSVID_WD19TB, kDell_WD19TB_VDO2, 1))
    return;
  port.AddRemovePartnerAltMode(mode_path, true);

  port.AddCable(base::FilePath(kFakePort0CableSysPath));

  // Dell's cable is captive.
  port.cable_->SetPDRevision(PDRevision::k30);
  port.cable_->SetIdHeaderVDO(0x1c00413c);
  port.cable_->SetCertStatVDO(0x0);
  port.cable_->SetProductVDO(0xb052000);
  port.cable_->SetProductTypeVDO1(0x110c2042);
  port.cable_->SetProductTypeVDO2(0x0);
  port.cable_->SetProductTypeVDO3(0x0);
}

void AddStartechDock(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // Add alternate modes.
  port.partner_->SetNumAltModes(2);
  std::string mode0_dirname =
      base::StringPrintf("port%d-partner.%d", 0, kDPAltModeIndex);
  auto mode0_path = temp_dir_.Append(mode0_dirname);
  if (!CreateFakeAltMode(mode0_path, kDPAltModeSID, kDPVDO, kDPVDOIndex))
    return;
  port.AddRemovePartnerAltMode(mode0_path, true);
  std::string mode1_dirname =
      base::StringPrintf("port%d-partner.%d", 0, kTBTAltModeIndex);
  auto mode1_path = temp_dir_.Append(mode1_dirname);
  if (!CreateFakeAltMode(mode1_path, kTBTAltModeVID, kTBTVDO, kTBTVDOIndex))
    return;
  port.AddRemovePartnerAltMode(mode1_path, true);
}

void AddStartechTB3DK2DPWDock(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // PD ID VDOs for the Startech.com TB3DK2DPW Alpine Ridge Dock.
  port.partner_->SetPDRevision(PDRevision::k20);
  port.partner_->SetIdHeaderVDO(0xd4008087);
  port.partner_->SetCertStatVDO(0x0);
  port.partner_->SetProductVDO(0x0);
  port.partner_->SetProductTypeVDO1(0);
  port.partner_->SetProductTypeVDO2(0);
  port.partner_->SetProductTypeVDO3(0);

  // Add alternate modes.
  port.partner_->SetNumAltModes(1);
  std::string mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kTBTAltModeVID, kTBTVDO, 0))
    return;
  port.AddRemovePartnerAltMode(mode_path, true);
}

void AddThinkpadTBT3Dock(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // PD ID VDOs for the ThinkPad Dock.
  port.partner_->SetPDRevision(PDRevision::k30);
  port.partner_->SetIdHeaderVDO(0x540017ef);
  port.partner_->SetCertStatVDO(0x0);
  port.partner_->SetProductVDO(0xa31e0000);
  port.partner_->SetProductTypeVDO1(0x0);
  port.partner_->SetProductTypeVDO2(0x0);
  port.partner_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.partner_->SetNumAltModes(3);
  std::string mode0_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode0_path = temp_dir_.Append(mode0_dirname);
  if (!CreateFakeAltMode(mode0_path, kTBTAltModeVID, 0x1, 0))
    return;
  port.AddRemovePartnerAltMode(mode0_path, true);
  std::string mode1_dirname = base::StringPrintf("port%d-partner.%d", 0, 1);
  auto mode1_path = temp_dir_.Append(mode1_dirname);
  if (!CreateFakeAltMode(mode1_path, kDPAltModeSID, 0xc3c47, 0))
    return;
  port.AddRemovePartnerAltMode(mode1_path, true);
  std::string mode2_dirname = base::StringPrintf("port%d-partner.%d", 0, 2);
  auto mode2_path = temp_dir_.Append(mode2_dirname);
  if (!CreateFakeAltMode(mode2_path, 0x17ef, 0x1, 0))
    return;
  port.AddRemovePartnerAltMode(mode2_path, true);
}

void AddIntelUSB4GatkexCreekDock(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // PD ID VDOs for the Gatkex creek USB4 dock..
  port.partner_->SetPDRevision(PDRevision::k30);
  port.partner_->SetIdHeaderVDO(0x4c800000);
  port.partner_->SetCertStatVDO(0x0);
  port.partner_->SetProductVDO(0x0);
  port.partner_->SetProductTypeVDO1(0xd00001b);
  port.partner_->SetProductTypeVDO2(0x0);
  port.partner_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.partner_->SetNumAltModes(2);
  auto mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kDPAltModeSID, kDPVDO_GatkexCreek,
                         kDPVDOIndex_GatkexCreek))
    return;
  port.AddRemovePartnerAltMode(mode_path, true);
  mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 1);
  mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kTBTAltModeVID, kTBTVDO_GatkexCreek,
                         kTBTVDOIndex_GatkexCreek))
    return;
  port.AddRemovePartnerAltMode(mode_path, true);
}

void AddOWCTBT4Dock(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // PD ID VDOs for the OWC Dock.
  port.partner_->SetPDRevision(PDRevision::k30);
  port.partner_->SetIdHeaderVDO(0x4cc01e91);
  port.partner_->SetCertStatVDO(0x0);
  port.partner_->SetProductVDO(0xde430069);
  port.partner_->SetProductTypeVDO1(0xd00003b);
  port.partner_->SetProductTypeVDO2(0x0);
  port.partner_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.partner_->SetNumAltModes(2);
  std::string mode0_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode0_path = temp_dir_.Append(mode0_dirname);
  if (!CreateFakeAltMode(mode0_path, kDPAltModeSID, 0x1c0045, 0))
    return;
  port.AddRemovePartnerAltMode(mode0_path, true);
  std::string mode1_dirname = base::StringPrintf("port%d-partner.%d", 0, 1);
  auto mode1_path = temp_dir_.Append(mode1_dirname);
  if (!CreateFakeAltMode(mode1_path, kTBTAltModeVID, 0x1, 0))
    return;
  port.AddRemovePartnerAltMode(mode1_path, true);
}

void AddWimaxitDisplay(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // PD ID VDOs for the WIMAXIT Type-C Display.
  port.partner_->SetPDRevision(PDRevision::k30);
  port.partner_->SetIdHeaderVDO(0x6c0004e8);
  port.partner_->SetCertStatVDO(0xf4246);
  port.partner_->SetProductVDO(0xa0200212);
  port.partner_->SetProductTypeVDO1(0x110000db);
  port.partner_->SetProductTypeVDO2(0x0);
  port.partner_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.partner_->SetNumAltModes(2);
  std::string mode0_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode0_path = temp_dir_.Append(mode0_dirname);
  if (!CreateFakeAltMode(mode0_path, kDPAltModeSID, 0x40045, 0))
    return;
  port.AddRemovePartnerAltMode(mode0_path, true);
  std::string mode1_dirname = base::StringPrintf("port%d-partner.%d", 0, 1);
  auto mode1_path = temp_dir_.Append(mode1_dirname);
  if (!CreateFakeAltMode(mode1_path, 0x04e8, 0x40045, 0))
    return;
  port.AddRemovePartnerAltMode(mode1_path, true);
}

void AddTargusDV4KDock(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // PD ID VDOs for the Targus DV4K dock
  port.partner_->SetPDRevision(PDRevision::k30);
  port.partner_->SetIdHeaderVDO(0x6c000835);
  port.partner_->SetCertStatVDO(0x00000451);
  port.partner_->SetProductVDO(0x2a080010);
  port.partner_->SetProductTypeVDO1(0xff00003a);
  port.partner_->SetProductTypeVDO2(0x0);
  port.partner_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.partner_->SetNumAltModes(1);
  std::string mode_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode_path = temp_dir_.Append(mode_dirname);
  if (!CreateFakeAltMode(mode_path, kDPAltModeSID, 0xc0045, 1))
    return;
  port.AddRemovePartnerAltMode(mode_path, true);
}

void AddTargus180Dock(Port& port) {
  base::ScopedTempDir scoped_temp_dir_;
  if (!scoped_temp_dir_.CreateUniqueTempDir())
    return;
  base::FilePath temp_dir_ = scoped_temp_dir_.GetPath();

  port.AddPartner(base::FilePath(kFakePort0PartnerSysPath));

  // PD ID VDOs for the Targus 180 dock
  port.partner_->SetPDRevision(PDRevision::k20);
  port.partner_->SetIdHeaderVDO(0x6c000000);
  port.partner_->SetCertStatVDO(0x00000451);
  port.partner_->SetProductVDO(0x00000010);
  port.partner_->SetProductTypeVDO1(0xff00003a);
  port.partner_->SetProductTypeVDO2(0x0);
  port.partner_->SetProductTypeVDO3(0x0);

  // Add alternate modes.
  port.partner_->SetNumAltModes(2);
  std::string mode0_dirname = base::StringPrintf("port%d-partner.%d", 0, 0);
  auto mode0_path = temp_dir_.Append(mode0_dirname);
  if (!CreateFakeAltMode(mode0_path, kDPAltModeSID, 0xc0045, 1))
    return;
  port.AddRemovePartnerAltMode(mode0_path, true);
  std::string mode1_dirname = base::StringPrintf("port%d-partner.%d", 0, 1);
  auto mode1_path = temp_dir_.Append(mode1_dirname);
  if (!CreateFakeAltMode(mode1_path, 0x0451, 0x1, 1))
    return;
  port.AddRemovePartnerAltMode(mode1_path, true);
}

}  // namespace typecd
