// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/ieee80211.h"

#include <base/strings/stringprintf.h>

namespace shill {
namespace IEEE_80211 {

std::string ReasonToString(WiFiReasonCode reason) {
  switch (reason) {
    case kReasonCodeUnspecified:
      return "Unspecified reason";
    case kReasonCodePreviousAuthenticationInvalid:
      return "Previous authentication no longer valid";
    case kReasonCodeSenderHasLeft:
      return "Deauthenticated because sending STA is leaving (or has left) "
             "IBSS "
             "or ESS";
    case kReasonCodeInactivity:
      return "Disassociated due to inactivity";
    case kReasonCodeTooManySTAs:
      return "Disassociated because AP is unable to handle all currently "
             "associated STAs";
    case kReasonCodeNonAuthenticated:
      return "Class 2 frame received from nonauthenticated STA";
    case kReasonCodeNonAssociated:
      return "Class 3 frame received from nonassociated STA";
    case kReasonCodeDisassociatedHasLeft:
      return "Disassociated because sending STA is leaving (or has left) BSS";
    case kReasonCodeReassociationNotAuthenticated:
      return "STA requesting (re)association is not authenticated with "
             "responding STA";
    case kReasonCodeUnacceptablePowerCapability:
      return "Disassociated because the information in the Power Capability "
             "element is unacceptable";
    case kReasonCodeUnacceptableSupportedChannelInfo:
      return "Disassociated because the information in the Supported Channels "
             "element is unacceptable";
    case kReasonCodeInvalidInfoElement:
      return "Invalid information element, i.e., an information element "
             "defined in this standard for which the content does not meet the "
             "specifications in Clause 7";
    case kReasonCodeMICFailure:
      return "Message integrity code (MIC) failure";
    case kReasonCode4WayTimeout:
      return "4-Way Handshake timeout";
    case kReasonCodeGroupKeyHandshakeTimeout:
      return "Group Key Handshake timeout";
    case kReasonCodeDifferenIE:
      return "Information element in 4-Way Handshake different from "
             "(Re)Association Request/Probe Response/Beacon frame";
    case kReasonCodeGroupCipherInvalid:
      return "Invalid group cipher";
    case kReasonCodePairwiseCipherInvalid:
      return "Invalid pairwise cipher";
    case kReasonCodeAkmpInvalid:
      return "Invalid AKMP";
    case kReasonCodeUnsupportedRsnIeVersion:
      return "Unsupported RSN information element version";
    case kReasonCodeInvalidRsnIeCaps:
      return "Invalid RSN information element capabilities";
    case kReasonCode8021XAuth:
      return "IEEE 802.1X authentication failed";
    case kReasonCodeCipherSuiteRejected:
      return "Cipher suite rejected because of the security policy";
    case kReasonCodeUnspecifiedQoS:
      return "Disassociated for unspecified, QoS-related reason";
    case kReasonCodeQoSBandwidth:
      return "Disassociated because QoS AP lacks sufficient bandwidth for this "
             "QoS STA";
    case kReasonCodeiPoorConditions:
      return "Disassociated because excessive number of frames need to be "
             "acknowledged, but are not acknowledged due to AP transmissions "
             "and/or poor channel conditions";
    case kReasonCodeOutsideTxop:
      return "Disassociated because STA is transmitting outside the limits of "
             "its TXOPs";
    case kReasonCodeStaLeaving:
      return "Requested from peer STA as the STA is leaving the BSS (or "
             "resetting)";
    case kReasonCodeUnacceptableMechanism:
      return "Requested from peer STA as it does not want to use the mechanism";
    case kReasonCodeSetupRequired:
      return "Requested from peer STA as the STA received frames using the "
             "mechanism for which a setup is required";
    case kReasonCodeTimeout:
      return "Requested from peer STA due to timeout";
    case kReasonCodeCipherSuiteNotSupported:
      return "Peer STA does not support the requested cipher suite";
    case kReasonCodeInvalid:
      return "<INVALID REASON>";
    default:
      if (reason < kReasonCodeMax) {
        return base::StringPrintf("<Reserved Reason:%u>", reason);
      }
      return base::StringPrintf("<Unknown Reason:%u>", reason);
  }
}

std::string StatusToString(WiFiStatusCode status) {
  switch (status) {
    case kStatusCodeSuccessful:
      return "Successful";
    case kStatusCodeFailure:
      return "Unspecified failure";
    case kStatusCodeAllCapabilitiesNotSupported:
      return "Cannot support all requested capabilities in the capability "
             "information field";
    case kStatusCodeCantConfirmAssociation:
      return "Reassociation denied due to inability to confirm that "
             "association exists";
    case kStatusCodeAssociationDenied:
      return "Association denied due to reason outside the scope of this "
             "standard";
    case kStatusCodeAuthenticationUnsupported:
      return "Responding station does not support the specified authentication "
             "algorithm";
    case kStatusCodeOutOfSequence:
      return "Received an authentication frame with authentication transaction "
             "sequence number out of expected sequence";
    case kStatusCodeChallengeFailure:
      return "Authentication rejected because of challenge failure";
    case kStatusCodeFrameTimeout:
      return "Authentication rejected due to timeout waiting for next frame in "
             "sequence";
    case kStatusCodeMaxSta:
      return "Association denied because AP is unable to handle additional "
             "associated STA";
    case kStatusCodeDataRateUnsupported:
      return "Association denied due to requesting station not supporting all "
             "of the data rates in the BSSBasicRateSet parameter";
    case kStatusCodeShortPreambleUnsupported:
      return "Association denied due to requesting station not supporting the "
             "short preamble option";
    case kStatusCodePbccUnsupported:
      return "Association denied due to requesting station not supporting the "
             "PBCC modulation option";
    case kStatusCodeChannelAgilityUnsupported:
      return "Association denied due to requesting station not supporting the "
             "channel agility option";
    case kStatusCodeNeedSpectrumManagement:
      return "Association request rejected because Spectrum Management "
             "capability is required";
    case kStatusCodeUnacceptablePowerCapability:
      return "Association request rejected because the information in the "
             "Power Capability element is unacceptable";
    case kStatusCodeUnacceptableSupportedChannelInfo:
      return "Association request rejected because the information in the "
             "Supported Channels element is unacceptable";
    case kStatusCodeShortTimeSlotRequired:
      return "Association request rejected due to requesting station not "
             "supporting the Short Slot Time option";
    case kStatusCodeDssOfdmRequired:
      return "Association request rejected due to requesting station not "
             "supporting the DSSS-OFDM option";
    case kStatusCodeQosFailure:
      return "Unspecified, QoS related failure";
    case kStatusCodeInsufficientBandwithForQsta:
      return "Association denied due to QAP having insufficient bandwidth to "
             "handle another QSTA";
    case kStatusCodePoorConditions:
      return "Association denied due to poor channel conditions";
    case kStatusCodeQosNotSupported:
      return "Association (with QoS BSS) denied due to requesting station not "
             "supporting the QoS facility";
    case kStatusCodeDeclined:
      return "The request has been declined";
    case kStatusCodeInvalidParameterValues:
      return "The request has not been successful as one or more parameters "
             "have invalid values";
    case kStatusCodeCannotBeHonored:
      return "The TS has not been created because the request cannot be "
             "honored. However, a suggested Tspec is provided so that the "
             "initiating QSTA may attempt to send another TS with the "
             "suggested changes to the TSpec";
    case kStatusCodeInvalidInfoElement:
      return "Invalid Information Element";
    case kStatusCodeGroupCipherInvalid:
      return "Invalid Group Cipher";
    case kStatusCodePairwiseCipherInvalid:
      return "Invalid Pairwise Cipher";
    case kStatusCodeAkmpInvalid:
      return "Invalid AKMP";
    case kStatusCodeUnsupportedRsnIeVersion:
      return "Unsupported RSN Information Element version";
    case kStatusCodeInvalidRsnIeCaps:
      return "Invalid RSN Information Element Capabilities";
    case kStatusCodeCipherSuiteRejected:
      return "Cipher suite is rejected per security policy";
    case kStatusCodeTsDelayNotMet:
      return "The TS has not been created. However, the HC may be capable of "
             "creating a TS, in response to a request, after the time "
             "indicated in the TS Delay element";
    case kStatusCodeDirectLinkIllegal:
      return "Direct link is not allowed in the BSS by policy";
    case kStatusCodeStaNotInBss:
      return "Destination STA is not present within this BSS";
    case kStatusCodeStaNotInQsta:
      return "The destination STA is not a QoS STA";
    case kStatusCodeExcessiveListenInterval:
      return "Association denied because Listen Interval is too large";
    case kStatusCodeInvalid:
      return "<INVALID STATUS>";
    default:
      if (status < kStatusCodeMax) {
        return base::StringPrintf("<Reserved Status:%u>", status);
      }
      return base::StringPrintf("<Unknown Status:%u>", status);
  }
}

}  // namespace IEEE_80211
}  // namespace shill
