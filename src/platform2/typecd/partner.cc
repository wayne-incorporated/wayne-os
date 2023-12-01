// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/partner.h"

#include <string>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

#include "typecd/pd_vdo_constants.h"
#include "typecd/port.h"

namespace {

constexpr char kPartnerAltModeRegex[] = R"(port(\d+)-partner.(\d+))";

}

namespace typecd {

Partner::Partner(const base::FilePath& syspath, Port* port) : Partner(syspath) {
  port_ = port;
}

Partner::Partner(const base::FilePath& syspath)
    : Peripheral(syspath, "Partner"),
      num_alt_modes_(-1),
      supports_pd_(false),
      metrics_reported_(false),
      port_(nullptr),
      power_profile_(nullptr) {
  // Search for all alt modes which were already registered prior to daemon
  // init.
  base::FileEnumerator iter(GetSysPath(), false,
                            base::FileEnumerator::DIRECTORIES);
  // This needs to be called explicitly since it's not in the base Peripheral
  // class.
  UpdateSupportsPD();
  for (auto path = iter.Next(); !path.empty(); path = iter.Next())
    AddAltMode(path);

  SetNumAltModes(ParseNumAltModes());
}

bool Partner::AddAltMode(const base::FilePath& mode_syspath) {
  int port, index;
  if (!RE2::FullMatch(mode_syspath.BaseName().value(), kPartnerAltModeRegex,
                      &port, &index))
    return false;

  if (IsAltModePresent(index)) {
    LOG(INFO) << "Alt mode already registered for syspath "
              << mode_syspath.BaseName();
    return true;
  }

  auto alt_mode = AltMode::CreateAltMode(mode_syspath);
  if (!alt_mode) {
    LOG(ERROR) << "Error creating alt mode for syspath " << mode_syspath;
    return false;
  }

  alt_modes_.emplace(index, std::move(alt_mode));

  LOG(INFO) << "Added alt mode for port " << port << " index " << index;

  return true;
}

void Partner::RemoveAltMode(const base::FilePath& mode_syspath) {
  int port, index;
  if (!RE2::FullMatch(mode_syspath.BaseName().value(), kPartnerAltModeRegex,
                      &port, &index)) {
    LOG(ERROR) << "Couldn't parse alt mode index from syspath " << mode_syspath;
    return;
  }

  auto it = alt_modes_.find(index);
  if (it == alt_modes_.end()) {
    LOG(INFO) << "Trying to delete non-existent alt mode " << index;
    return;
  }

  alt_modes_.erase(it);

  LOG(INFO) << "Removed alt mode for port " << port << " index " << index;
}

bool Partner::IsAltModePresent(int index) {
  auto it = alt_modes_.find(index);
  if (it != alt_modes_.end()) {
    return true;
  }

  LOG(INFO) << "Alt mode not found at index " << index;
  return false;
}

void Partner::AddPowerProfile() {
  if (power_profile_ || !supports_pd_)
    return;
  auto path = GetSysPath().Append("usb_power_delivery");
  // Not all devices have USB power delivery directories.
  if (base::DirectoryExists(path))
    power_profile_ = std::make_unique<PowerProfile>(path);
}

void Partner::RemovePowerProfile() {
  power_profile_.reset();
}

void Partner::UpdatePDInfoFromSysfs() {
  if (GetNumAltModes() == -1)
    SetNumAltModes(ParseNumAltModes());
  UpdatePDIdentityVDOs();
  UpdatePDRevision();
  UpdateSupportsPD();
  AddPowerProfile();
}

int Partner::ParseNumAltModes() {
  auto path = GetSysPath().Append("number_of_alternate_modes");

  std::string val_str;
  if (!base::ReadFileToString(path, &val_str))
    return -1;

  base::TrimWhitespaceASCII(val_str, base::TRIM_TRAILING, &val_str);

  int num_altmodes;
  if (!base::StringToInt(val_str.c_str(), &num_altmodes)) {
    LOG(ERROR) << "Couldn't parse num_altmodes from string: " << val_str;
    return -1;
  }

  return num_altmodes;
}

AltMode* Partner::GetAltMode(int index) {
  if (!IsAltModePresent(index))
    return nullptr;

  return alt_modes_.find(index)->second.get();
}

bool Partner::DiscoveryComplete() {
  return num_alt_modes_ == alt_modes_.size();
}

void Partner::UpdateSupportsPD() {
  auto path = GetSysPath().Append("supports_usb_power_delivery");
  std::string val_str;
  if (!base::ReadFileToString(path, &val_str)) {
    LOG(ERROR) << "Couldn't read value from path " << path;
    return;
  }

  base::TrimWhitespaceASCII(val_str, base::TRIM_TRAILING, &val_str);
  if (val_str == "yes")
    supports_pd_ = true;
  else
    supports_pd_ = false;
}

PartnerTypeMetric Partner::GetPartnerTypeMetric() {
  bool usb4 = SupportsUsb4();
  bool tbt_present = SupportsTbt();
  bool dp_present = SupportsDp();
  bool usb_present = SupportsUsb();

  // Determine whether it is a hub or peripheral.
  bool hub = false;
  bool peripheral = false;
  auto product_type = (GetIdHeaderVDO() >> kIDHeaderVDOProductTypeBitOffset) &
                      kIDHeaderVDOProductTypeMask;
  if (product_type == kIDHeaderVDOProductTypeUFPHub) {
    hub = true;
  } else if (product_type == kIDHeaderVDOProductTypeUFPPeripheral) {
    peripheral = true;
  } else if (product_type == kIDHeaderVDOProductTypeUFPAMA) {
    // If it's an Alternate Mode Adapter, we have to guess.
    // Check the AMA VDO. If only billboard is supported, we guess that it's a
    // peripheral. In all other cases, we consider it's a hub.
    auto usb_speed = GetProductTypeVDO1() & kAMAVDOUSBSpeedBitMask;
    if (usb_speed != kAMAVDOUSBSpeedBillboard)
      hub = true;
    else
      peripheral = true;
  }

  // Now that we have all the data, let's make a type selection.
  PartnerTypeMetric ret = PartnerTypeMetric::kOther;
  if (usb4) {
    if (hub)
      ret = PartnerTypeMetric::kUSB4Hub;
    else if (peripheral)
      ret = PartnerTypeMetric::kUSB4Peripheral;
  } else if (tbt_present && dp_present) {
    if (hub)
      ret = PartnerTypeMetric::kTBTDPAltHub;
    else if (peripheral)
      ret = PartnerTypeMetric::kTBTDPAltPeripheral;
  } else if (tbt_present) {
    if (hub)
      ret = PartnerTypeMetric::kTBTHub;
    else if (peripheral)
      ret = PartnerTypeMetric::kTBTPeripheral;
  } else if (dp_present) {
    if (hub)
      ret = PartnerTypeMetric::kDPAltHub;
    else if (peripheral)
      ret = PartnerTypeMetric::kDPAltPeripheral;
  } else if (usb_present) {
    if (hub)
      ret = PartnerTypeMetric::kUSBHub;
    else if (peripheral)
      ret = PartnerTypeMetric::kUSBPeripheral;
  }

  // Edge case of power brick.
  auto product_type_dfp =
      GetIdHeaderVDO() >> kIDHeaderVDOProductTypeDFPBitOffset &
      kIDHeaderVDOProductTypeMask;
  if (product_type_dfp == kIDHeaderVDOProductTypePowerBrick)
    ret = PartnerTypeMetric::kPowerBrick;

  // If we've found a valid category let's return.
  if (ret != PartnerTypeMetric::kOther)
    return ret;

  // If we still haven't been able to categorize the partner, we make a guess
  // based on current port state and hints about partner capabilities.
  if (!port_) {
    LOG(INFO) << "Port pointer not available; can't determine partner type";
    return ret;
  }

  // Grab all the variables together.
  DataRole port_dr = port_->GetDataRole();
  PowerRole port_pr = port_->GetPowerRole();
  bool partner_has_pd = GetSupportsPD();

  // Refer to b/195056095 for details about the selection matrix.
  if (port_pr == PowerRole::kSink) {
    if (partner_has_pd) {
      if (port_dr == DataRole::kHost)
        ret = PartnerTypeMetric::kPDSourcingDevice;
      else if (port_dr == DataRole::kDevice)
        ret = PartnerTypeMetric::kPDPowerSource;
    } else {
      ret = PartnerTypeMetric::kNonPDPowerSource;
    }
  } else if (port_pr == PowerRole::kSource) {
    if (partner_has_pd) {
      if (port_dr == DataRole::kHost)
        ret = PartnerTypeMetric::kPDSink;
      else if (port_dr == DataRole::kDevice)
        ret = PartnerTypeMetric::kPDSinkingHost;
    } else {
      ret = PartnerTypeMetric::kNonPDSink;
    }
  }

  return ret;
}

DataRoleMetric Partner::GetDataRoleMetric() {
  DataRoleMetric ret = DataRoleMetric::kOther;
  DataRole port_dr = port_->GetDataRole();

  if (port_dr == DataRole::kHost)
    ret = DataRoleMetric::kDevice;
  else if (port_dr == DataRole::kDevice)
    ret = DataRoleMetric::kHost;

  return ret;
}

PowerRoleMetric Partner::GetPowerRoleMetric() {
  PowerRoleMetric ret = PowerRoleMetric::kOther;
  PowerRole port_pr = port_->GetPowerRole();

  if (port_pr == PowerRole::kSource)
    ret = PowerRoleMetric::kSink;
  else if (port_pr == PowerRole::kSink)
    ret = PowerRoleMetric::kSource;

  return ret;
}

void Partner::ReportMetrics(Metrics* metrics) {
  if (!metrics || metrics_reported_)
    return;

  if (GetSupportsPD() && !DiscoveryComplete()) {
    LOG(WARNING)
        << "Partner discovery not complete before attempt to report metrics";
    return;
  }

  metrics->ReportPartnerType(GetPartnerTypeMetric());
  metrics->ReportBasicPdDeviceInfo(GetVendorId(), GetProductId(), GetXid(),
                                   GetSupportsPD(), SupportsUsb(), SupportsDp(),
                                   SupportsTbt(), SupportsUsb4(),
                                   GetDataRoleMetric(), GetPowerRoleMetric());

  metrics_reported_ = true;
}

bool Partner::SupportsUsb() {
  // For situations where the device is a "regular" USB peripheral, try to
  // determine whether it at least supports anything other than billboard.
  auto product_type = (GetIdHeaderVDO() >> kIDHeaderVDOProductTypeBitOffset) &
                      kIDHeaderVDOProductTypeMask;
  if (product_type == kIDHeaderVDOProductTypeUFPPeripheral ||
      product_type == kIDHeaderVDOProductTypeUFPHub) {
    auto device_cap = (GetProductTypeVDO1() >> kDeviceCapabilityBitOffset) &
                      kDeviceCapabilityMask;
    if (device_cap != kDeviceCapabilityBillboard)
      return true;
  }
  return false;
}

bool Partner::SupportsDp() {
  for (const auto& [index, mode] : alt_modes_) {
    if ((mode->GetSVID() == kDPAltModeSID) && (mode->GetVDO() & kDPModeSnk))
      return true;
  }
  return false;
}

bool Partner::SupportsTbt() {
  for (const auto& [index, mode] : alt_modes_) {
    if (mode->GetSVID() == kTBTAltModeVID)
      return true;
  }
  return false;
}

bool Partner::SupportsUsb4() {
  // Only PDUSB hub or PDUSB peripheral provide UFP VDO.
  // Otherwise, USB4 is not supported.
  auto product_type = (GetIdHeaderVDO() >> kIDHeaderVDOProductTypeBitOffset) &
                      kIDHeaderVDOProductTypeMask;
  if (product_type != kIDHeaderVDOProductTypeUFPHub &&
      product_type != kIDHeaderVDOProductTypeUFPPeripheral)
    return false;

  // Product Type VDO1 is UFP VDO at this point.
  auto partner_cap = (GetProductTypeVDO1() >> kDeviceCapabilityBitOffset) &
                     kDeviceCapabilityMask;
  return (partner_cap & kDeviceCapabilityUSB4);
}

int Partner::GetVendorId() {
  return GetIdHeaderVDO() & kIdHeaderVDOVidMask;
}

int Partner::GetProductId() {
  return (GetProductVDO() >> kProductVDOPidBitOffset) & kProductVDOPidMask;
}

int Partner::GetXid() {
  return GetCertStateVDO();
}

}  // namespace typecd
