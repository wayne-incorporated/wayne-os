// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_IEEE80211_H_
#define SHILL_NET_IEEE80211_H_

#include <stdint.h>

#include <string>

#include "shill/net/shill_export.h"

namespace shill {

namespace IEEE_80211 {
// Information Element Ids from IEEE 802.11-2016 Table 9-77.
const uint8_t kElemIdBSSMaxIdlePeriod = 0x5a;
const uint8_t kElemIdChannels = 0x24;
const uint8_t kElemIdChallengeText = 0x10;
const uint8_t kElemIdCountry = 0x07;
const uint8_t kElemIdDSParameterSet = 0x03;
const uint8_t kElemIdErp = 0x2a;
const uint8_t kElemIdExtendedCap = 0x7f;
const uint8_t kElemIdExtendedRates = 0x32;
const uint8_t kElemIdHTCap = 0x2d;
const uint8_t kElemIdHTInfo = 0x3d;
const uint8_t kElemIdMDE = 0x36;
const uint8_t kElemIdPowerCapability = 0x21;
const uint8_t kElemIdPowerConstraint = 0x20;
const uint8_t kElemIdRequest = 0x0a;
const uint8_t kElemIdRmEnabledCap = 0x46;
const uint8_t kElemIdRSN = 0x30;
const uint8_t kElemIdSsid = 0x00;
const uint8_t kElemIdSupportedRates = 0x01;
const uint8_t kElemIdTpcReport = 0x23;
const uint8_t kElemIdVendor = 0xdd;
const uint8_t kElemIdVHTCap = 0xbf;
const uint8_t kElemIdVHTOperation = 0xc0;
const uint8_t kElemIdMeshId = 0x72;
const uint8_t kElemIdExt = 0xff;

// Element Id Extensions from P802.11ax/D4.0 Section 9.4.2.1.
const uint8_t kElemIdExtHECap = 0x23;
const uint8_t kElemIdExtHEOperation = 0x24;

const unsigned int kMaxSSIDLen = 32;

const unsigned int kWEP40AsciiLen = 5;
const unsigned int kWEP40HexLen = 10;
const unsigned int kWEP104AsciiLen = 13;
const unsigned int kWEP104HexLen = 26;

const unsigned int kWPAAsciiMinLen = 8;
const unsigned int kWPAAsciiMaxLen = 63;
const unsigned int kWPAHexLen = 64;

const uint32_t kOUIVendorEpigram = 0x00904c;
const uint32_t kOUIVendorMicrosoft = 0x0050f2;

const uint8_t kOUIMicrosoftWPA = 1;
const uint8_t kOUIMicrosoftWPS = 4;
const uint16_t kWPSElementManufacturer = 0x1021;
const uint16_t kWPSElementModelName = 0x1023;
const uint16_t kWPSElementModelNumber = 0x1024;
const uint16_t kWPSElementDeviceName = 0x1011;

const uint32_t kOUIVendorWiFiAlliance = 0x506f9a;
const uint32_t kOUITypeWiFiAllianceHS20Indicator = 0x10;
const uint32_t kOUITypeWiFiAllianceMBO = 0x16;

const uint32_t kOUIVendorCiscoAironet = 0x004096;
const uint32_t kOUITypeCiscoExtendedCapabilitiesIE = 0x0b;
const uint8_t kCiscoExtendedCapabilitiesAdaptiveFT = 0x40;

const int kRSNIEVersionLen = 2;
const int kRSNIESelectorLen = 4;
const int kRSNIECipherCountOffset = kRSNIEVersionLen + kRSNIESelectorLen;
const int kRSNIECipherCountLen = 2;
const int kRSNIENumCiphers = 2;
const int kRSNIECapabilitiesLen = 2;
const int kRSNIEAuthKeyCiphers = 1;
const uint16_t kRSNCapabilityPreAuth = 0x0001;
const uint16_t kRSNCapabilityPairwise = 0x0002;
const uint16_t kRSNCapabilityPTKSA = 0x000c;
const uint16_t kRSNCapabilityGTKSA = 0x0030;
const uint16_t kRSNCapabilityFrameProtectionRequired = 0x0040;
const uint16_t kRSNCapabilityFrameProtectionCapable = 0x0080;
const uint16_t kRSNCapabilityPeerKey = 0x0200;

// Little endian representations of FT cipher suites.
const uint32_t kRSNAuthType8021XFT = 0x03ac0f00;
const uint32_t kRSNAuthTypePSKFT = 0x04ac0f00;
const uint32_t kRSNAuthTypeSAEFT = 0x09ac0f00;

// MD Element constants
const int kMDEFTCapabilitiesLen = 3;
const int kMDEIDLen = 2;
const uint8_t kMDEOTDSCapability = 0x01;

// Extended Capabilities element masks.
const uint8_t kExtendedCapBit6 = 0x40;
const uint8_t kExtendedCapBit5 = 0x20;
const uint8_t kExtendedCapBit3 = 0x08;
const uint8_t kExtendedCapBit2 = 0x04;
const uint8_t kExtendedCapBit0 = 0x01;

/* 802.11n HT capabilities masks (for cap_info) */
const uint16_t kHTCapMaskLdpcCoding = 0x0001;
const uint16_t kHTCapMaskSupWidth2040 = 0x0002;
const uint16_t kHTCapMaskSmPs = 0x000c;
const uint16_t kHTCapMaskSmPsShift = 2;
const uint16_t kHTCapMaskGrnFld = 0x0010;
const uint16_t kHTCapMaskSgi20 = 0x0020;
const uint16_t kHTCapMaskSgi40 = 0x0040;
const uint16_t kHTCapMaskTxStbc = 0x0080;
const uint16_t kHTCapMaskRxStbc = 0x0300;
const uint16_t kHTCapMaskRxStbcShift = 8;
const uint16_t kHTCapMaskDelayBA = 0x0400;
const uint16_t kHTCapMaskMaxAmsdu = 0x0800;
const uint16_t kHTCapMaskDsssCck40 = 0x1000;
const uint16_t kHTCapMask40MHzIntolerant = 0x4000;
const uint16_t kHTCapMaskLsigTxopProt = 0x8000;

// Beacon and Probe Response Capability Information field masks from
// IEEE 802.11-2012 Section 8.4.1.4
const uint16_t kWlanCapMaskEss = 0x0001;
const uint16_t kWlanCapMaskIbss = 0x0002;
const uint16_t kWlanCapMaskContentionFreePollable = 0x0004;
const uint16_t kWlanCapMaskContentionFreePollRequest = 0x0008;
const uint16_t kWlanCapMaskPrivacy = 0x0010;
const uint16_t kWlanCapMaskShortPreamble = 0x0020;
const uint16_t kWlanCapMaskPbcc = 0x0040;
const uint16_t kWlanCapMaskChannelAgility = 0x0080;
const uint16_t kWlanCapMaskSpectrumMgmt = 0x0100;
const uint16_t kWlanCapMaskQoS = 0x0200;
const uint16_t kWlanCapMaskShortSlotTime = 0x0400;
const uint16_t kWlanCapMaskApsd = 0x0800;
const uint16_t kWlanCapMaskRadioMeasurement = 0x1000;
const uint16_t kWlanCapMaskDsssOfdm = 0x2000;
const uint16_t kWlanCapMaskDelayedBlockAck = 0x4000;
const uint16_t kWlanCapMaskImmediateBlockAck = 0x8000;

// This structure is incomplete.  Fields will be added as necessary.
//
// NOTE: the uint16_t stuff is in little-endian format so conversions are
// required.
struct ieee80211_frame {
  struct {
    uint16_t frame_control;
    uint16_t duration_usec;
    uint8_t destination_mac[6];
    uint8_t source_mac[6];
    uint8_t address[6];
    uint16_t sequence_control;
  } __attribute__((packed)) hdr;
  union {
    struct {
      uint16_t reserved_1;
      uint16_t reserved_2;
      uint16_t status_code;
    } __attribute__((packed)) authentiate_message;
    struct {
      uint16_t reason_code;
    } __attribute__((packed)) deauthentiate_message;
    struct {
      uint16_t reserved_1;
      uint16_t status_code;
    } __attribute__((packed)) associate_response;
  };
} __attribute__((packed));

// Enum for the Capabilities bit field of the Extended Capabilities element.
enum ExtendedCapOctet {
  kExtendedCapOctet2 = 2,
  kExtendedCapOctet3 = 3,
  kExtendedCapOctet6 = 6,
  kExtendedCapOctet7 = 7,
  kExtendedCapOctet10 = 10,

  kExtendedCapOctetMax
};

// Status/reason code returned by nl80211 messages: Authenticate,
// Deauthenticate, Associate, and Reassociate.
enum WiFiReasonCode : uint16_t {
  kReasonCodeReserved0 = 0,  // 0 is reserved.
  kReasonCodeUnspecified = 1,
  kReasonCodePreviousAuthenticationInvalid = 2,
  kReasonCodeSenderHasLeft = 3,
  kReasonCodeInactivity = 4,
  kReasonCodeTooManySTAs = 5,
  kReasonCodeNonAuthenticated = 6,
  kReasonCodeNonAssociated = 7,
  kReasonCodeDisassociatedHasLeft = 8,
  kReasonCodeReassociationNotAuthenticated = 9,
  kReasonCodeUnacceptablePowerCapability = 10,
  kReasonCodeUnacceptableSupportedChannelInfo = 11,
  kReasonCodeReserved12 = 12,  // 12 is reserved.
  kReasonCodeInvalidInfoElement = 13,
  kReasonCodeMICFailure = 14,
  kReasonCode4WayTimeout = 15,
  kReasonCodeGroupKeyHandshakeTimeout = 16,
  kReasonCodeDifferenIE = 17,
  kReasonCodeGroupCipherInvalid = 18,
  kReasonCodePairwiseCipherInvalid = 19,
  kReasonCodeAkmpInvalid = 20,
  kReasonCodeUnsupportedRsnIeVersion = 21,
  kReasonCodeInvalidRsnIeCaps = 22,
  kReasonCode8021XAuth = 23,
  kReasonCodeCipherSuiteRejected = 24,
  kReasonCodeReservedBegin25 = 25,  // 25-31 are reserved.
  kReasonCodeReservedEnd31 = 31,
  kReasonCodeUnspecifiedQoS = 32,
  kReasonCodeQoSBandwidth = 33,
  kReasonCodeiPoorConditions = 34,
  kReasonCodeOutsideTxop = 35,
  kReasonCodeStaLeaving = 36,
  kReasonCodeUnacceptableMechanism = 37,
  kReasonCodeSetupRequired = 38,
  kReasonCodeTimeout = 39,
  kReasonCodeReservedBegin40 = 40,  // 40-44 are reserved.
  kReasonCodeReservedEnd44 = 44,
  kReasonCodeCipherSuiteNotSupported = 45,
  kReasonCodeMax,
  kReasonCodeInvalid = UINT16_MAX
};

enum WiFiStatusCode : uint16_t {
  kStatusCodeSuccessful = 0,
  kStatusCodeFailure = 1,
  // 2-9 are reserved.
  kStatusCodeAllCapabilitiesNotSupported = 10,
  kStatusCodeCantConfirmAssociation = 11,
  kStatusCodeAssociationDenied = 12,
  kStatusCodeAuthenticationUnsupported = 13,
  kStatusCodeOutOfSequence = 14,
  kStatusCodeChallengeFailure = 15,
  kStatusCodeFrameTimeout = 16,
  kStatusCodeMaxSta = 17,
  kStatusCodeDataRateUnsupported = 18,
  kStatusCodeShortPreambleUnsupported = 19,
  kStatusCodePbccUnsupported = 20,
  kStatusCodeChannelAgilityUnsupported = 21,
  kStatusCodeNeedSpectrumManagement = 22,
  kStatusCodeUnacceptablePowerCapability = 23,
  kStatusCodeUnacceptableSupportedChannelInfo = 24,
  kStatusCodeShortTimeSlotRequired = 25,
  kStatusCodeDssOfdmRequired = 26,
  // 27-31 are reserved.
  kStatusCodeQosFailure = 32,
  kStatusCodeInsufficientBandwithForQsta = 33,
  kStatusCodePoorConditions = 34,
  kStatusCodeQosNotSupported = 35,
  // 36 is reserved.
  kStatusCodeDeclined = 37,
  kStatusCodeInvalidParameterValues = 38,
  kStatusCodeCannotBeHonored = 39,
  kStatusCodeInvalidInfoElement = 40,
  kStatusCodeGroupCipherInvalid = 41,
  kStatusCodePairwiseCipherInvalid = 42,
  kStatusCodeAkmpInvalid = 43,
  kStatusCodeUnsupportedRsnIeVersion = 44,
  kStatusCodeInvalidRsnIeCaps = 45,
  kStatusCodeCipherSuiteRejected = 46,
  kStatusCodeTsDelayNotMet = 47,
  kStatusCodeDirectLinkIllegal = 48,
  kStatusCodeStaNotInBss = 49,
  kStatusCodeStaNotInQsta = 50,
  kStatusCodeExcessiveListenInterval = 51,
  kStatusCodeMax,
  kStatusCodeInvalid = UINT16_MAX
};

// Returns a string representing the specified |reason|, which is an integer
// value corresponding to the NL80211_ATTR_REASON_CODE attribute acquired from
// the kernel.
SHILL_EXPORT std::string ReasonToString(WiFiReasonCode reason);

// Returns a string representing the specified |status|, which is an integer
// value corresponding to the NL80211_ATTR_STATUS_CODE attribute acquired from
// the kernel.
SHILL_EXPORT std::string StatusToString(WiFiStatusCode status);

}  // namespace IEEE_80211

}  // namespace shill

#endif  // SHILL_NET_IEEE80211_H_
