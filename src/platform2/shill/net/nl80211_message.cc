// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This code is derived from the 'iw' source code.  The copyright and license
// of that code is as follows:
//
// Copyright (c) 2007, 2008  Johannes Berg
// Copyright (c) 2007  Andy Lutomirski
// Copyright (c) 2007  Mike Kershaw
// Copyright (c) 2008-2009  Luis R. Rodriguez
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#include "shill/net/nl80211_message.h"

#include <iomanip>
#include <limits>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <endian.h>

#include "shill/net/attribute_list.h"
#include "shill/net/ieee80211.h"
#include "shill/net/netlink_attribute.h"
#include "shill/net/netlink_packet.h"
#include "shill/net/nl80211_attribute.h"  // For Nl80211AttributeMac

namespace shill {

const uint8_t Nl80211Frame::kFrameTypeMask = 0xfc;

const char Nl80211Message::kMessageTypeString[] = "nl80211";
uint16_t Nl80211Message::nl80211_message_type_ = kIllegalMessageType;

// static
uint16_t Nl80211Message::GetMessageType() {
  return nl80211_message_type_;
}

// static
void Nl80211Message::SetMessageType(uint16_t message_type) {
  if (message_type == NetlinkMessage::kIllegalMessageType) {
    LOG(FATAL) << "Absolutely need a legal message type for Nl80211 messages.";
  }
  nl80211_message_type_ = message_type;
}

bool Nl80211Message::InitFromPacket(NetlinkPacket* packet,
                                    NetlinkMessage::MessageContext context) {
  if (!packet) {
    LOG(ERROR) << "Null |packet| parameter";
    return false;
  }

  if (!InitAndStripHeader(packet)) {
    return false;
  }

  return packet->ConsumeAttributes(
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          context),
      attributes_);
}

Nl80211Frame::Nl80211Frame(const ByteString& raw_frame)
    : frame_type_(kIllegalFrameType),
      reason_(std::numeric_limits<uint16_t>::max()),
      status_(std::numeric_limits<uint16_t>::max()),
      frame_(raw_frame) {
  const IEEE_80211::ieee80211_frame* frame =
      reinterpret_cast<const IEEE_80211::ieee80211_frame*>(
          frame_.GetConstData());

  if (frame_.GetLength() < sizeof(frame->hdr))
    return;

  mac_from_ =
      Nl80211AttributeMac::StringFromMacAddress(&frame->hdr.destination_mac[0]);
  mac_to_ =
      Nl80211AttributeMac::StringFromMacAddress(&frame->hdr.source_mac[0]);
  frame_type_ = le16toh(frame->hdr.frame_control & kFrameTypeMask);

  // Parse the body, if available.
  switch (frame_type_) {
    case kAssocResponseFrameType:
    case kReassocResponseFrameType:
      if (frame_.GetLength() <
          sizeof(frame->hdr) + sizeof(frame->associate_response)) {
        frame_type_ = kIllegalFrameType;
        break;
      }
      status_ = le16toh(frame->associate_response.status_code);
      break;

    case kAuthFrameType:
      if (frame_.GetLength() <
          sizeof(frame->hdr) + sizeof(frame->authentiate_message)) {
        frame_type_ = kIllegalFrameType;
        break;
      }
      status_ = le16toh(frame->authentiate_message.status_code);
      break;

    case kDisassocFrameType:
    case kDeauthFrameType:
      if (frame_.GetLength() <
          sizeof(frame->hdr) + sizeof(frame->deauthentiate_message)) {
        frame_type_ = kIllegalFrameType;
        break;
      }
      reason_ = le16toh(frame->deauthentiate_message.reason_code);
      break;

    default:
      break;
  }
}

std::string Nl80211Frame::ToString() const {
  if (frame_.IsEmpty()) {
    return "[no frame]";
  }

  std::string output;
  if (frame_.GetLength() < sizeof(IEEE_80211::ieee80211_frame().hdr)) {
    output.append("[invalid frame: ");
  } else {
    base::StringAppendF(&output, "%s -> %s", mac_from_.c_str(),
                        mac_to_.c_str());

    switch (frame_type_) {
      case kAssocResponseFrameType:
        base::StringAppendF(
            &output, "; AssocResponse status: %u: %s", status_,
            IEEE_80211::StatusToString(
                static_cast<IEEE_80211::WiFiStatusCode>(status_))
                .c_str());
        break;
      case kReassocResponseFrameType:
        base::StringAppendF(
            &output, "; ReassocResponse status: %u: %s", status_,
            IEEE_80211::StatusToString(
                static_cast<IEEE_80211::WiFiStatusCode>(status_))
                .c_str());
        break;
      case kAuthFrameType:
        base::StringAppendF(
            &output, "; Auth status: %u: %s", status_,
            IEEE_80211::StatusToString(
                static_cast<IEEE_80211::WiFiStatusCode>(status_))
                .c_str());
        break;

      case kDisassocFrameType:
        base::StringAppendF(
            &output, "; Disassoc reason %u: %s", reason_,
            IEEE_80211::ReasonToString(
                static_cast<IEEE_80211::WiFiReasonCode>(reason_))
                .c_str());
        break;
      case kDeauthFrameType:
        base::StringAppendF(
            &output, "; Deauth reason %u: %s", reason_,
            IEEE_80211::ReasonToString(
                static_cast<IEEE_80211::WiFiReasonCode>(reason_))
                .c_str());
        break;

      default:
        break;
    }
    output.append(" [frame: ");
  }

  const unsigned char* frame = frame_.GetConstData();
  for (size_t i = 0; i < frame_.GetLength(); ++i) {
    base::StringAppendF(&output, "%02x, ", frame[i]);
  }
  output.append("]");

  return output;
}

bool Nl80211Frame::IsEqual(const Nl80211Frame& other) const {
  return frame_.Equals(other.frame_);
}

//
// Specific Nl80211Message types.
//

const uint8_t AssociateMessage::kCommand = NL80211_CMD_ASSOCIATE;
const char AssociateMessage::kCommandString[] = "NL80211_CMD_ASSOCIATE";

const uint8_t AuthenticateMessage::kCommand = NL80211_CMD_AUTHENTICATE;
const char AuthenticateMessage::kCommandString[] = "NL80211_CMD_AUTHENTICATE";

const uint8_t CancelRemainOnChannelMessage::kCommand =
    NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL;
const char CancelRemainOnChannelMessage::kCommandString[] =
    "NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL";

const uint8_t ConnectMessage::kCommand = NL80211_CMD_CONNECT;
const char ConnectMessage::kCommandString[] = "NL80211_CMD_CONNECT";

const uint8_t DeauthenticateMessage::kCommand = NL80211_CMD_DEAUTHENTICATE;
const char DeauthenticateMessage::kCommandString[] =
    "NL80211_CMD_DEAUTHENTICATE";

const uint8_t DelInterfaceMessage::kCommand = NL80211_CMD_DEL_INTERFACE;
const char DelInterfaceMessage::kCommandString[] = "NL80211_CMD_DEL_INTERFACE";

const uint8_t DeleteStationMessage::kCommand = NL80211_CMD_DEL_STATION;
const char DeleteStationMessage::kCommandString[] = "NL80211_CMD_DEL_STATION";

const uint8_t DelWiphyMessage::kCommand = NL80211_CMD_DEL_WIPHY;
const char DelWiphyMessage::kCommandString[] = "NL80211_CMD_DEL_WIPHY";

const uint8_t DisassociateMessage::kCommand = NL80211_CMD_DISASSOCIATE;
const char DisassociateMessage::kCommandString[] = "NL80211_CMD_DISASSOCIATE";

const uint8_t DisconnectMessage::kCommand = NL80211_CMD_DISCONNECT;
const char DisconnectMessage::kCommandString[] = "NL80211_CMD_DISCONNECT";

const uint8_t FrameTxStatusMessage::kCommand = NL80211_CMD_FRAME_TX_STATUS;
const char FrameTxStatusMessage::kCommandString[] =
    "NL80211_CMD_FRAME_TX_STATUS";

const uint8_t GetRegMessage::kCommand = NL80211_CMD_GET_REG;
const char GetRegMessage::kCommandString[] = "NL80211_CMD_GET_REG";

GetRegMessage::GetRegMessage() : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_WIPHY,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t ReqSetRegMessage::kCommand = NL80211_CMD_REQ_SET_REG;
const char ReqSetRegMessage::kCommandString[] = "NL80211_CMD_REQ_SET_REG";

ReqSetRegMessage::ReqSetRegMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateU32Attribute(NL80211_ATTR_USER_REG_HINT_TYPE,
                                   "NL80211_ATTR_USER_REG_HINT_TYPE");
  attributes()->CreateAttribute(
      NL80211_ATTR_REG_ALPHA2,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t GetStationMessage::kCommand = NL80211_CMD_GET_STATION;
const char GetStationMessage::kCommandString[] = "NL80211_CMD_GET_STATION";

GetStationMessage::GetStationMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
  attributes()->CreateAttribute(
      NL80211_ATTR_MAC,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t SetWakeOnWiFiMessage::kCommand = NL80211_CMD_SET_WOWLAN;
const char SetWakeOnWiFiMessage::kCommandString[] = "NL80211_CMD_SET_WOWLAN";

const uint8_t GetWakeOnWiFiMessage::kCommand = NL80211_CMD_GET_WOWLAN;
const char GetWakeOnWiFiMessage::kCommandString[] = "NL80211_CMD_GET_WOWLAN";

const uint8_t GetWiphyMessage::kCommand = NL80211_CMD_GET_WIPHY;
const char GetWiphyMessage::kCommandString[] = "NL80211_CMD_GET_WIPHY";

GetWiphyMessage::GetWiphyMessage() : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
  attributes()->CreateFlagAttribute(NL80211_ATTR_SPLIT_WIPHY_DUMP,
                                    "Split wiphy dump");
  attributes()->CreateAttribute(
      NL80211_ATTR_WIPHY,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t JoinIbssMessage::kCommand = NL80211_CMD_JOIN_IBSS;
const char JoinIbssMessage::kCommandString[] = "NL80211_CMD_JOIN_IBSS";

const uint8_t MichaelMicFailureMessage::kCommand =
    NL80211_CMD_MICHAEL_MIC_FAILURE;
const char MichaelMicFailureMessage::kCommandString[] =
    "NL80211_CMD_MICHAEL_MIC_FAILURE";

const uint8_t NewMeshPathMessage::kCommand = NL80211_CMD_NEW_MPATH;
const char NewMeshPathMessage::kCommandString[] = "NL80211_CMD_NEW_MPATH";

const uint8_t NewScanResultsMessage::kCommand = NL80211_CMD_NEW_SCAN_RESULTS;
const char NewScanResultsMessage::kCommandString[] =
    "NL80211_CMD_NEW_SCAN_RESULTS";

const uint8_t NewStationMessage::kCommand = NL80211_CMD_NEW_STATION;
const char NewStationMessage::kCommandString[] = "NL80211_CMD_NEW_STATION";

const uint8_t NewWiphyMessage::kCommand = NL80211_CMD_NEW_WIPHY;
const char NewWiphyMessage::kCommandString[] = "NL80211_CMD_NEW_WIPHY";

const uint8_t NotifyCqmMessage::kCommand = NL80211_CMD_NOTIFY_CQM;
const char NotifyCqmMessage::kCommandString[] = "NL80211_CMD_NOTIFY_CQM";

const uint8_t PmksaCandidateMessage::kCommand = NL80211_ATTR_PMKSA_CANDIDATE;
const char PmksaCandidateMessage::kCommandString[] =
    "NL80211_ATTR_PMKSA_CANDIDATE";

const uint8_t ProbeMeshLinkMessage::kCommand = NL80211_CMD_PROBE_MESH_LINK;
const char ProbeMeshLinkMessage::kCommandString[] =
    "NL80211_CMD_PROBE_MESH_LINK";

ProbeMeshLinkMessage::ProbeMeshLinkMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
  attributes()->CreateAttribute(
      NL80211_ATTR_MAC,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
  attributes()->CreateAttribute(
      NL80211_ATTR_FRAME,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t RegBeaconHintMessage::kCommand = NL80211_CMD_REG_BEACON_HINT;
const char RegBeaconHintMessage::kCommandString[] =
    "NL80211_CMD_REG_BEACON_HINT";

const uint8_t RegChangeMessage::kCommand = NL80211_CMD_REG_CHANGE;
const char RegChangeMessage::kCommandString[] = "NL80211_CMD_REG_CHANGE";

RegChangeMessage::RegChangeMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t RemainOnChannelMessage::kCommand = NL80211_CMD_REMAIN_ON_CHANNEL;
const char RemainOnChannelMessage::kCommandString[] =
    "NL80211_CMD_REMAIN_ON_CHANNEL";

const uint8_t RoamMessage::kCommand = NL80211_CMD_ROAM;
const char RoamMessage::kCommandString[] = "NL80211_CMD_ROAM";

const uint8_t ScanAbortedMessage::kCommand = NL80211_CMD_SCAN_ABORTED;
const char ScanAbortedMessage::kCommandString[] = "NL80211_CMD_SCAN_ABORTED";

const uint8_t GetScanMessage::kCommand = NL80211_CMD_GET_SCAN;
const char GetScanMessage::kCommandString[] = "NL80211_CMD_GET_SCAN";

GetScanMessage::GetScanMessage() : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t TriggerScanMessage::kCommand = NL80211_CMD_TRIGGER_SCAN;
const char TriggerScanMessage::kCommandString[] = "NL80211_CMD_TRIGGER_SCAN";

TriggerScanMessage::TriggerScanMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t UnprotDeauthenticateMessage::kCommand =
    NL80211_CMD_UNPROT_DEAUTHENTICATE;
const char UnprotDeauthenticateMessage::kCommandString[] =
    "NL80211_CMD_UNPROT_DEAUTHENTICATE";

const uint8_t UnprotDisassociateMessage::kCommand =
    NL80211_CMD_UNPROT_DISASSOCIATE;
const char UnprotDisassociateMessage::kCommandString[] =
    "NL80211_CMD_UNPROT_DISASSOCIATE";

const uint8_t WiphyRegChangeMessage::kCommand = NL80211_CMD_WIPHY_REG_CHANGE;
const char WiphyRegChangeMessage::kCommandString[] =
    "NL80211_CMD_WIPHY_REG_CHANGE";

WiphyRegChangeMessage::WiphyRegChangeMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

GetInterfaceMessage::GetInterfaceMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t GetInterfaceMessage::kCommand = NL80211_CMD_GET_INTERFACE;
const char GetInterfaceMessage::kCommandString[] = "NL80211_CMD_GET_INTERFACE";

const uint8_t NewInterfaceMessage::kCommand = NL80211_CMD_NEW_INTERFACE;
const char NewInterfaceMessage::kCommandString[] = "NL80211_CMD_NEW_INTERFACE";

const uint8_t GetSurveyMessage::kCommand = NL80211_CMD_GET_SURVEY;
const char GetSurveyMessage::kCommandString[] = "NL80211_CMD_GET_SURVEY";

GetSurveyMessage::GetSurveyMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
  AddFlag(NLM_F_DUMP);
}

const uint8_t SurveyResultsMessage::kCommand = NL80211_CMD_NEW_SURVEY_RESULTS;
const char SurveyResultsMessage::kCommandString[] =
    "NL80211_CMD_NEW_SURVEY_RESULTS";

const uint8_t GetMeshPathInfoMessage::kCommand = NL80211_CMD_GET_MPATH;
const char GetMeshPathInfoMessage::kCommandString[] = "NL80211_CMD_GET_MPATH";

GetMeshPathInfoMessage::GetMeshPathInfoMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
  attributes()->CreateAttribute(
      NL80211_ATTR_MAC,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t GetMeshProxyPathMessage::kCommand = NL80211_CMD_GET_MPP;
const char GetMeshProxyPathMessage::kCommandString[] = "NL80211_CMD_GET_MPP";

GetMeshProxyPathMessage::GetMeshProxyPathMessage()
    : Nl80211Message(kCommand, kCommandString) {
  attributes()->CreateAttribute(
      NL80211_ATTR_IFINDEX,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
  attributes()->CreateAttribute(
      NL80211_ATTR_MAC,
      base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                          NetlinkMessage::MessageContext()));
}

const uint8_t NewPeerCandidateMessage::kCommand =
    NL80211_CMD_NEW_PEER_CANDIDATE;
const char NewPeerCandidateMessage::kCommandString[] =
    "NL80211_CMD_NEW_PEER_CANDIDATE";

const uint8_t ControlPortFrameTxStatusMessage::kCommand =
    NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS;
const char ControlPortFrameTxStatusMessage::kCommandString[] =
    "NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS";

// static
std::unique_ptr<NetlinkMessage> Nl80211Message::CreateMessage(
    const NetlinkPacket& packet) {
  genlmsghdr header;
  if (!packet.GetGenlMsgHdr(&header)) {
    LOG(ERROR) << "Could not read genl header.";
    return nullptr;
  }

  switch (header.cmd) {
    case AssociateMessage::kCommand:
      return std::make_unique<AssociateMessage>();
    case AuthenticateMessage::kCommand:
      return std::make_unique<AuthenticateMessage>();
    case CancelRemainOnChannelMessage::kCommand:
      return std::make_unique<CancelRemainOnChannelMessage>();
    case ConnectMessage::kCommand:
      return std::make_unique<ConnectMessage>();
    case DeauthenticateMessage::kCommand:
      return std::make_unique<DeauthenticateMessage>();
    case DelInterfaceMessage::kCommand:
      return std::make_unique<DelInterfaceMessage>();
    case DelWiphyMessage::kCommand:
      return std::make_unique<DelWiphyMessage>();
    case DeleteStationMessage::kCommand:
      return std::make_unique<DeleteStationMessage>();
    case DisassociateMessage::kCommand:
      return std::make_unique<DisassociateMessage>();
    case DisconnectMessage::kCommand:
      return std::make_unique<DisconnectMessage>();
    case FrameTxStatusMessage::kCommand:
      return std::make_unique<FrameTxStatusMessage>();
    case GetInterfaceMessage::kCommand:
      return std::make_unique<GetInterfaceMessage>();
    case GetWakeOnWiFiMessage::kCommand:
      return std::make_unique<GetWakeOnWiFiMessage>();
    case GetRegMessage::kCommand:
      return std::make_unique<GetRegMessage>();
    case GetStationMessage::kCommand:
      return std::make_unique<GetStationMessage>();
    case GetWiphyMessage::kCommand:
      return std::make_unique<GetWiphyMessage>();
    case JoinIbssMessage::kCommand:
      return std::make_unique<JoinIbssMessage>();
    case MichaelMicFailureMessage::kCommand:
      return std::make_unique<MichaelMicFailureMessage>();
    case NewInterfaceMessage::kCommand:
      return std::make_unique<NewInterfaceMessage>();
    case NewMeshPathMessage::kCommand:
      return std::make_unique<NewMeshPathMessage>();
    case NewScanResultsMessage::kCommand:
      return std::make_unique<NewScanResultsMessage>();
    case NewStationMessage::kCommand:
      return std::make_unique<NewStationMessage>();
    case NewWiphyMessage::kCommand:
      return std::make_unique<NewWiphyMessage>();
    case NotifyCqmMessage::kCommand:
      return std::make_unique<NotifyCqmMessage>();
    case PmksaCandidateMessage::kCommand:
      return std::make_unique<PmksaCandidateMessage>();
    case ProbeMeshLinkMessage::kCommand:
      return std::make_unique<ProbeMeshLinkMessage>();
    case RegBeaconHintMessage::kCommand:
      return std::make_unique<RegBeaconHintMessage>();
    case RegChangeMessage::kCommand:
      return std::make_unique<RegChangeMessage>();
    case RemainOnChannelMessage::kCommand:
      return std::make_unique<RemainOnChannelMessage>();
    case RoamMessage::kCommand:
      return std::make_unique<RoamMessage>();
    case SetWakeOnWiFiMessage::kCommand:
      return std::make_unique<SetWakeOnWiFiMessage>();
    case ScanAbortedMessage::kCommand:
      return std::make_unique<ScanAbortedMessage>();
    case TriggerScanMessage::kCommand:
      return std::make_unique<TriggerScanMessage>();
    case UnprotDeauthenticateMessage::kCommand:
      return std::make_unique<UnprotDeauthenticateMessage>();
    case UnprotDisassociateMessage::kCommand:
      return std::make_unique<UnprotDisassociateMessage>();
    case WiphyRegChangeMessage::kCommand:
      return std::make_unique<WiphyRegChangeMessage>();
    case GetSurveyMessage::kCommand:
      return std::make_unique<GetSurveyMessage>();
    case SurveyResultsMessage::kCommand:
      return std::make_unique<SurveyResultsMessage>();
    case GetMeshPathInfoMessage::kCommand:
      return std::make_unique<GetMeshPathInfoMessage>();
    case GetMeshProxyPathMessage::kCommand:
      return std::make_unique<GetMeshProxyPathMessage>();
    case NewPeerCandidateMessage::kCommand:
      return std::make_unique<NewPeerCandidateMessage>();
    case ControlPortFrameTxStatusMessage::kCommand:
      return std::make_unique<ControlPortFrameTxStatusMessage>();
    default:
      LOG(WARNING) << base::StringPrintf(
          "Unknown/unhandled netlink nl80211 message 0x%02x", header.cmd);
      return std::make_unique<UnknownNl80211Message>(header.cmd);
  }
}

}  // namespace shill.
