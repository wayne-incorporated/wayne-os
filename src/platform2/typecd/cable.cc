// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/cable.h"

#include <string>

#include <base/files/file_enumerator.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

#include "typecd/pd_vdo_constants.h"

namespace {

constexpr char kSOPPrimeAltModeRegex[] = R"(port(\d+)-plug0.(\d+))";

}  // namespace

namespace typecd {

void Cable::RegisterCablePlug(const base::FilePath& syspath) {
  // Search for all alt modes which were already registered prior to daemon
  // init.
  base::FileEnumerator iter(syspath, false, base::FileEnumerator::DIRECTORIES);
  for (auto path = iter.Next(); !path.empty(); path = iter.Next())
    AddAltMode(path);

  if (GetNumAltModes() != -1)
    return;

  auto num_altmodes_path = syspath.Append("number_of_alternate_modes");

  std::string val_str;
  if (!base::ReadFileToString(num_altmodes_path, &val_str)) {
    LOG(WARNING) << "Number of alternate modes not available for syspath "
                 << syspath;
    return;
  }

  base::TrimWhitespaceASCII(val_str, base::TRIM_TRAILING, &val_str);

  int num_altmodes;
  if (!base::StringToInt(val_str, &num_altmodes)) {
    LOG(ERROR) << "Couldn't parse num_altmodes from string: " << val_str;
    return;
  }

  SetNumAltModes(num_altmodes);
}

bool Cable::AddAltMode(const base::FilePath& mode_syspath) {
  int port, index;
  if (!RE2::FullMatch(mode_syspath.BaseName().value(), kSOPPrimeAltModeRegex,
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
  LOG(INFO) << "Added SOP' alt mode for port " << port << " index " << index;

  return true;
}

void Cable::RemoveAltMode(const base::FilePath& mode_syspath) {
  int port, index;
  if (!RE2::FullMatch(mode_syspath.BaseName().value(), kSOPPrimeAltModeRegex,
                      &port, &index)) {
    LOG(ERROR) << "Couldn't parse alt mode index from syspath " << mode_syspath;
    return;
  }

  auto it = alt_modes_.find(index);
  if (it == alt_modes_.end()) {
    LOG(INFO) << "Trying to delete non-existent SOP' alt mode " << index;
    return;
  }

  alt_modes_.erase(it);

  LOG(INFO) << "Removed SOP' alt mode for port " << port << " index " << index;
}

bool Cable::IsAltModePresent(int index) {
  auto it = alt_modes_.find(index);
  if (it != alt_modes_.end()) {
    return true;
  }

  LOG(INFO) << "SOP' Alt mode not found at index " << index;
  return false;
}

bool Cable::IsAltModeSVIDPresent(uint16_t altmode_sid) {
  for (const auto& [index, mode] : alt_modes_) {
    if (mode->GetSVID() == altmode_sid)
      return true;
  }

  return false;
}

AltMode* Cable::GetAltMode(int index) {
  if (!IsAltModePresent(index))
    return nullptr;

  return alt_modes_.find(index)->second.get();
}

// Ref:
//   USB Type-C Connector Spec, release 2.0
//   Figure F-1.
bool Cable::TBT3PDIdentityCheck() {
  // If the cable is active, we don't need to check for speed.
  auto product_type = GetIdHeaderVDO() >> kIDHeaderVDOProductTypeBitOffset &
                      kIDHeaderVDOProductTypeMask;
  if (product_type & kIDHeaderVDOProductTypeCableActive) {
    if (IsAltModeSVIDPresent(kTBTAltModeVID)) {
      LOG(INFO) << "Active cable detected, TBT3 supported.";
      return true;
    }
    LOG(INFO) << "Active cable detected, TBT3 not supported.";
    return false;
  }

  if (!(product_type & kIDHeaderVDOProductTypeCablePassive)) {
    LOG(ERROR) << "Cable has unsupported product type.";
    return false;
  }

  auto usb_speed = GetProductTypeVDO1() & kUSBSpeedBitMask;
  if (GetPDRevision() == PDRevision::k30) {
    return usb_speed == kUSBSuperSpeed32Gen1 ||
           usb_speed == kUSBSuperSpeed32Or40Gen2 ||
           usb_speed == kUSB40SuperSpeedGen3;
  }

  // For PD 2.0 the check is similar, but let's make it explicit.
  return usb_speed == kUSBSuperSpeed31Gen1 || usb_speed == kUSBSuperSpeed31Gen2;
}

bool Cable::USB4PDIdentityCheck() {
  auto cable_type = (GetIdHeaderVDO() >> kIDHeaderVDOProductTypeBitOffset) &
                    kIDHeaderVDOProductTypeMask;
  if (cable_type == kIDHeaderVDOProductTypeCableActive) {
    auto vdo_version =
        (GetProductTypeVDO1() >> kActiveCableVDO1VDOVersionOffset) &
        kActiveCableVDO1VDOVersionBitMask;

    // For VDO version == 1.3, check if Active Cable VDO2 supports USB4.
    // NOTE: The meaning of this field is inverted; the bit field being set
    // means USB4 is *not* supported.
    if (vdo_version == kActiveCableVDO1VDOVersion13) {
      if (GetProductTypeVDO2() & kActiveCableVDO2USB4SupportedBitField)
        return false;
      else
        return true;
    }

    // For VDO version != 1.3, don't enable USB4 if the cable:
    // - doesn't support modal operation, or
    // - doesn't have an Intel SVID Alt mode, or
    // - doesn't have rounded support.
    if (!(GetIdHeaderVDO() & kIDHeaderVDOModalOperationBitField))
      return false;

    if (!IsAltModeSVIDPresent(kTBTAltModeVID))
      return false;

    // Go through cable alt modes and check for rounded support in the TBT VDO.
    auto num_altmodes = GetNumAltModes();
    for (int i = 0; i < num_altmodes; i++) {
      AltMode* altmode = GetAltMode(i);
      if (!altmode || altmode->GetSVID() != kTBTAltModeVID)
        continue;
      auto rounded_support =
          altmode->GetVDO() >> kTBT3CableDiscModeVDORoundedSupportOffset &
          kTBT3CableDiscModeVDORoundedSupportMask;
      if (rounded_support == kTBT3CableDiscModeVDO_3_4_Gen_Rounded_Non_Rounded)
        return true;
    }
    return false;
  } else if (cable_type == kIDHeaderVDOProductTypeCablePassive) {
    // Apart from USB2.0, USB4 is supported for all other speeds.
    auto speed = GetProductTypeVDO1() & kUSBSpeedBitMask;
    if (speed != kUSBSpeed20)
      return true;
    else
      return false;
  }
  return false;
}

bool Cable::DiscoveryComplete() {
  return num_alt_modes_ == alt_modes_.size();
}

CableSpeedMetric Cable::GetCableSpeedMetric() {
  CableSpeedMetric ret = CableSpeedMetric::kOther;

  // If we can't identify a valid cable in the ID Header, return early.
  auto cable_type = (GetIdHeaderVDO() >> kIDHeaderVDOProductTypeBitOffset) &
                    kIDHeaderVDOProductTypeMask;
  if (!(cable_type == kIDHeaderVDOProductTypeCableActive ||
        cable_type == kIDHeaderVDOProductTypeCablePassive))
    return ret;

  // Parse the speed field in the Cable VDO.
  auto cable_vdo = GetProductTypeVDO1();
  uint32_t speed = cable_vdo & kUSBSpeedBitMask;
  switch (speed) {
    case kUSBSpeed20:
      ret = CableSpeedMetric::kUSB2_0;
      break;
    case kUSBSuperSpeed32Gen1:
      ret = CableSpeedMetric::kUSB3_2Gen1;
      break;
    case kUSBSuperSpeed32Or40Gen2:
      ret = CableSpeedMetric::kUSB3_2USB4Gen2;
      break;
    case kUSB40SuperSpeedGen3:
      ret = CableSpeedMetric::kUSB4Gen3;
      break;
    default:
      ret = CableSpeedMetric::kOther;
      break;
  }

  // Add special handling for the PD 2.0 Cable VDO speed.
  if (GetPDRevision() == PDRevision::k20) {
    if (speed == kUSBSuperSpeed31Gen1) {
      ret = CableSpeedMetric::kUSB3_1Gen1;
    } else if (speed == kUSBSuperSpeed31Gen2) {
      ret = CableSpeedMetric::kUSB3_1Gen1Gen2;
    }
  }

  if (ret != CableSpeedMetric::kUSB2_0)
    return ret;

  // Finally, handle TBT-only cables (only if the VDOs claim to only
  // support USB 2.0 speeds).
  for (const auto& [index, mode] : alt_modes_) {
    if (mode->GetSVID() != kTBTAltModeVID)
      continue;

    uint32_t tbt_vdo = mode->GetVDO();

    // If rounded support is there, we should continue.
    auto rounded_support =
        (tbt_vdo >> kTBT3CableDiscModeVDORoundedSupportOffset) &
        kTBT3CableDiscModeVDORoundedSupportMask;
    if (rounded_support == kTBT3CableDiscModeVDO_3_4_Gen_Rounded_Non_Rounded)
      continue;

    auto speed = (tbt_vdo >> kTBT3CableDiscModeVDOSpeedOffset) &
                 kTBT3CableDiscModeVDOSpeedMask;
    if (speed == kTBT3CableDiscModeVDOSpeed10G20G)
      ret = CableSpeedMetric::kTBTOnly10G20G;
  }

  return ret;
}

void Cable::ReportMetrics(Metrics* metrics) {
  if (!metrics || metrics_reported_)
    return;

  if (!DiscoveryComplete()) {
    LOG(WARNING)
        << "Cable discovery not complete before attempt to report metrics";
    return;
  }

  metrics->ReportCableSpeed(GetCableSpeedMetric());

  metrics_reported_ = true;
}

}  // namespace typecd
