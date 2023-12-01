// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_PD_VDO_CONSTANTS_H_
#define TYPECD_PD_VDO_CONSTANTS_H_

// Declare fields/values associated with Power Delivery (PD) discovery. These
// are used during various USB Type C mode entry checks.
namespace typecd {

// USB PD spec rev 3.0, v 2.0.
// Table 6-29 ID Header VDO.
// Modal operation bit field.
constexpr uint32_t kIDHeaderVDOModalOperationBitField = (1 << 26);
// Bit Masks for Cable type.
constexpr uint8_t kIDHeaderVDOProductTypeBitOffset = 27;
constexpr uint8_t kIDHeaderVDOProductTypeDFPBitOffset = 23;
constexpr uint8_t kIDHeaderVDOProductTypeMask = 0x7;
constexpr uint8_t kIDHeaderVDOProductTypeCablePassive = 0x3;
constexpr uint8_t kIDHeaderVDOProductTypeCableActive = 0x4;
constexpr uint8_t kIDHeaderVDOProductTypeUFPHub = 0x1;
constexpr uint8_t kIDHeaderVDOProductTypeUFPPeripheral = 0x2;
constexpr uint8_t kIDHeaderVDOProductTypeUFPAMA = 0x5;
constexpr uint8_t kIDHeaderVDOProductTypePowerBrick = 0x3;
constexpr uint32_t kIdHeaderVDOVidMask = 0x0000ffff;

// Bit Masks for Product VDO
// USB PD spec rev 3.0, v 2.0.
// Table 6-34 Product VDO
constexpr uint32_t kProductVDOPidBitOffset = 16;
constexpr uint32_t kProductVDOPidMask = 0x0000ffff;
constexpr uint32_t kProductVDOPidMaskWithOffset = 0xffff0000;

// Bit Masks for Product Type VDOs
// USB PD spec rev 3.0, v 2.0.
// Table 6-35 UFP VDO 1
constexpr uint32_t kDeviceCapabilityBitOffset = 24;
constexpr uint8_t kDeviceCapabilityMask = 0xF;
constexpr uint8_t kDeviceCapabilityBillboard = 0x2;
constexpr uint8_t kDeviceCapabilityUSB4 = 0x8;
constexpr uint32_t kUSBSpeedBitMask = 0x7;
constexpr uint32_t kUSBSpeed20 = 0x0;
constexpr uint32_t kUSBSuperSpeed32Gen1 = 0x1;
constexpr uint32_t kUSBSuperSpeed32Or40Gen2 = 0x2;
constexpr uint32_t kUSB40SuperSpeedGen3 = 0x3;
// Speed values for PD rev 2.0
constexpr uint32_t kUSBSuperSpeed31Gen1 = 0x1;
constexpr uint32_t kUSBSuperSpeed31Gen2 = 0x2;

// Bit Masks for Active Cable VDO1
// USB PD spec rev 3.0, v 2.0.
// Table 6-39 Active Cable VDO1
constexpr uint8_t kActiveCableVDO1VDOVersionOffset = 21;
constexpr uint8_t kActiveCableVDO1VDOVersionBitMask = 0x7;
constexpr uint8_t kActiveCableVDO1VDOVersion13 = 0x3;

//  Bit Masks for Active Cable VDO2
//  US PD spec rev 3.0, v 2.0.
//  Table 6-40 Active Cable VDO2
constexpr uint32_t kActiveCableVDO2USB4SupportedBitField = (1 << 8);

// Bit Masks for TBT3 Cables
// USB Type-C Cable & Connector spec release 2.0
// Table F-11 TBT3 Cable Discover Mode VDO Responses
constexpr uint8_t kTBT3CableDiscModeVDORoundedSupportOffset = 19;
constexpr uint8_t kTBT3CableDiscModeVDORoundedSupportMask = 0x3;
constexpr uint8_t kTBT3CableDiscModeVDO_3_4_Gen_Rounded_Non_Rounded = 0x1;
constexpr uint8_t kTBT3CableDiscModeVDOSpeedOffset = 16;
constexpr uint8_t kTBT3CableDiscModeVDOSpeedMask = 0x7;
constexpr uint8_t kTBT3CableDiscModeVDOSpeed10G20G = 0x3;
// USB Type-C Cable & Connector spec release 2.1
// Table F-11 TBT3 Cable Discover Mode VDO Responses
constexpr uint8_t kTBT3CableDiscModeVDOModeOffset = 0;
constexpr uint16_t kTBT3CableDiscModeVDOModeMask = 0xffff;
constexpr uint16_t kTBT3CableDiscModeVDOModeTBT = 0x1;

// Standard and Vendor Indentifications commonly expected in cables and partners
constexpr uint16_t kDPAltModeSID = 0xff01;
// DP altmode VDO capabilities.
// NOTE: We only include the bit fields we are interested in.
constexpr uint32_t kDPModeSnk = 0x1;
constexpr uint32_t kDPModeReceptacle = 0x40;

constexpr uint16_t kTBTAltModeVID = 0x8087;

// Bit Masks for Alternate Mode Adapter (AMA) VDO
// USB PD spec rev 3.0, v 2.0.
// Table 6-41 AMA VDO
constexpr uint32_t kAMAVDOUSBSpeedBitMask = 0x7;
constexpr uint32_t kAMAVDOUSBSpeedBillboard = 0x3;

// Bit Masks for Fields in Active and Passive Cable VDO1
// USB PD spec rev 3.1, v 1.2.
// Table 6-41 Passive Cable VDO
// Table 6-42 Active Cable VDO1
constexpr uint8_t kCableVDO1VDOPlugTypeOffset = 18;
constexpr uint8_t kCableVDO1VDOPlugTypeBitMask = 0x3;
constexpr uint8_t kCableVDO1VDOPlugTypeCaptive = 0x3;

}  // namespace typecd

#endif  // TYPECD_PD_VDO_CONSTANTS_H_
