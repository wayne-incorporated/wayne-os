// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_NL80211_MESSAGE_H_
#define SHILL_NET_NL80211_MESSAGE_H_

#include <map>
#include <memory>
#include <string>

#include <base/no_destructor.h>

#include "shill/net/byte_string.h"
#include "shill/net/generic_netlink_message.h"
#include "shill/net/shill_export.h"

namespace shill {

class NetlinkPacket;

// Class for messages received from the mac80211 drivers by way of the
// cfg80211 kernel module.
class SHILL_EXPORT Nl80211Message : public GenericNetlinkMessage {
 public:
  static const char kMessageTypeString[];

  Nl80211Message(uint8_t command, const char* command_string)
      : GenericNetlinkMessage(nl80211_message_type_, command, command_string) {}
  Nl80211Message(const Nl80211Message&) = delete;
  Nl80211Message& operator=(const Nl80211Message&) = delete;

  ~Nl80211Message() override = default;

  // Gets the family_id / message_type for all Nl80211 messages.
  static uint16_t GetMessageType();

  // Sets the family_id / message_type for all Nl80211 messages.
  static void SetMessageType(uint16_t message_type);

  bool InitFromPacket(NetlinkPacket* packet, MessageContext context) override;

  uint8_t command() const { return command_; }
  const char* command_string() const { return command_string_; }
  uint16_t message_type() const { return message_type_; }
  uint32_t sequence_number() const { return sequence_number_; }
  void set_sequence_number(uint32_t seq) { sequence_number_ = seq; }

  // Message factory for all types of Nl80211 message.
  static std::unique_ptr<NetlinkMessage> CreateMessage(
      const NetlinkPacket& packet);

 private:
  static uint16_t nl80211_message_type_;
};

class SHILL_EXPORT Nl80211Frame {
 public:
  enum Type {
    kAssocResponseFrameType = 0x10,
    kReassocResponseFrameType = 0x30,
    kAssocRequestFrameType = 0x00,
    kReassocRequestFrameType = 0x20,
    kAuthFrameType = 0xb0,
    kDisassocFrameType = 0xa0,
    kDeauthFrameType = 0xc0,
    kIllegalFrameType = 0xff
  };

  explicit Nl80211Frame(const ByteString& init);
  Nl80211Frame(const Nl80211Frame&) = delete;
  Nl80211Frame& operator=(const Nl80211Frame&) = delete;

  std::string ToString() const;
  bool IsEqual(const Nl80211Frame& other) const;
  uint16_t reason() const { return reason_; }
  uint16_t status() const { return status_; }
  uint8_t frame_type() const { return frame_type_; }

 private:
  static const uint8_t kFrameTypeMask;

  std::string mac_from_;
  std::string mac_to_;
  uint8_t frame_type_;
  uint16_t reason_;
  uint16_t status_;
  ByteString frame_;
};

//
// Specific Nl80211Message types.
//

class SHILL_EXPORT AssociateMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  AssociateMessage() : Nl80211Message(kCommand, kCommandString) {}
  AssociateMessage(const AssociateMessage&) = delete;
  AssociateMessage& operator=(const AssociateMessage&) = delete;
};

class SHILL_EXPORT AuthenticateMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  AuthenticateMessage() : Nl80211Message(kCommand, kCommandString) {}
  AuthenticateMessage(const AuthenticateMessage&) = delete;
  AuthenticateMessage& operator=(const AuthenticateMessage&) = delete;
};

class SHILL_EXPORT CancelRemainOnChannelMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  CancelRemainOnChannelMessage() : Nl80211Message(kCommand, kCommandString) {}
  CancelRemainOnChannelMessage(const CancelRemainOnChannelMessage&) = delete;
  CancelRemainOnChannelMessage& operator=(const CancelRemainOnChannelMessage&) =
      delete;
};

class SHILL_EXPORT ConnectMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  ConnectMessage() : Nl80211Message(kCommand, kCommandString) {}
  ConnectMessage(const ConnectMessage&) = delete;
  ConnectMessage& operator=(const ConnectMessage&) = delete;
};

class SHILL_EXPORT DeauthenticateMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  DeauthenticateMessage() : Nl80211Message(kCommand, kCommandString) {}
  DeauthenticateMessage(const DeauthenticateMessage&) = delete;
  DeauthenticateMessage& operator=(const DeauthenticateMessage&) = delete;
};

class SHILL_EXPORT DelInterfaceMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  DelInterfaceMessage() : Nl80211Message(kCommand, kCommandString) {}
  DelInterfaceMessage(const DelInterfaceMessage&) = delete;
  DelInterfaceMessage& operator=(const DelInterfaceMessage&) = delete;
};

class SHILL_EXPORT DeleteStationMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  DeleteStationMessage() : Nl80211Message(kCommand, kCommandString) {}
  DeleteStationMessage(const DeleteStationMessage&) = delete;
  DeleteStationMessage& operator=(const DeleteStationMessage&) = delete;
};

class SHILL_EXPORT DelWiphyMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  DelWiphyMessage() : Nl80211Message(kCommand, kCommandString) {}
  DelWiphyMessage(const DelWiphyMessage&) = delete;
  DelWiphyMessage& operator=(const DelInterfaceMessage&) = delete;
};

class SHILL_EXPORT DisassociateMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  DisassociateMessage() : Nl80211Message(kCommand, kCommandString) {}
  DisassociateMessage(const DisassociateMessage&) = delete;
  DisassociateMessage& operator=(const DisassociateMessage&) = delete;
};

class SHILL_EXPORT DisconnectMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  DisconnectMessage() : Nl80211Message(kCommand, kCommandString) {}
  DisconnectMessage(const DisconnectMessage&) = delete;
  DisconnectMessage& operator=(const DisconnectMessage&) = delete;
};

class SHILL_EXPORT FrameTxStatusMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  FrameTxStatusMessage() : Nl80211Message(kCommand, kCommandString) {}
  FrameTxStatusMessage(const FrameTxStatusMessage&) = delete;
  FrameTxStatusMessage& operator=(const FrameTxStatusMessage&) = delete;
};

class SHILL_EXPORT GetRegMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetRegMessage();
  GetRegMessage(const GetRegMessage&) = delete;
  GetRegMessage& operator=(const GetRegMessage&) = delete;
};

class SHILL_EXPORT ReqSetRegMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  ReqSetRegMessage();
  ReqSetRegMessage(const ReqSetRegMessage&) = delete;
  ReqSetRegMessage& operator=(const ReqSetRegMessage&) = delete;
};

class SHILL_EXPORT GetStationMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetStationMessage();
  GetStationMessage(const GetStationMessage&) = delete;
  GetStationMessage& operator=(const GetStationMessage&) = delete;
};

class SHILL_EXPORT SetWakeOnWiFiMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  SetWakeOnWiFiMessage() : Nl80211Message(kCommand, kCommandString) {}
  SetWakeOnWiFiMessage(const SetWakeOnWiFiMessage&) = delete;
  SetWakeOnWiFiMessage& operator=(const SetWakeOnWiFiMessage&) = delete;
};

class SHILL_EXPORT GetWakeOnWiFiMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetWakeOnWiFiMessage() : Nl80211Message(kCommand, kCommandString) {}
  GetWakeOnWiFiMessage(const GetWakeOnWiFiMessage&) = delete;
  GetWakeOnWiFiMessage& operator=(const GetWakeOnWiFiMessage&) = delete;
};

class SHILL_EXPORT GetWiphyMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetWiphyMessage();
  GetWiphyMessage(const GetWiphyMessage&) = delete;
  GetWiphyMessage& operator=(const GetWiphyMessage&) = delete;
};

class SHILL_EXPORT JoinIbssMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  JoinIbssMessage() : Nl80211Message(kCommand, kCommandString) {}
  JoinIbssMessage(const JoinIbssMessage&) = delete;
  JoinIbssMessage& operator=(const JoinIbssMessage&) = delete;
};

class SHILL_EXPORT MichaelMicFailureMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  MichaelMicFailureMessage() : Nl80211Message(kCommand, kCommandString) {}
  MichaelMicFailureMessage(const MichaelMicFailureMessage&) = delete;
  MichaelMicFailureMessage& operator=(const MichaelMicFailureMessage&) = delete;
};

class SHILL_EXPORT NewMeshPathMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  NewMeshPathMessage() : Nl80211Message(kCommand, kCommandString) {}
  NewMeshPathMessage(const NewMeshPathMessage&) = delete;
  NewMeshPathMessage& operator=(const NewMeshPathMessage&) = delete;
};

class SHILL_EXPORT NewScanResultsMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  NewScanResultsMessage() : Nl80211Message(kCommand, kCommandString) {}
  NewScanResultsMessage(const NewScanResultsMessage&) = delete;
  NewScanResultsMessage& operator=(const NewScanResultsMessage&) = delete;
};

class SHILL_EXPORT NewStationMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  NewStationMessage() : Nl80211Message(kCommand, kCommandString) {}
  NewStationMessage(const NewStationMessage&) = delete;
  NewStationMessage& operator=(const NewStationMessage&) = delete;
};

class SHILL_EXPORT NewWiphyMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  NewWiphyMessage() : Nl80211Message(kCommand, kCommandString) {}
  NewWiphyMessage(const NewWiphyMessage&) = delete;
  NewWiphyMessage& operator=(const NewWiphyMessage&) = delete;
};

class SHILL_EXPORT NotifyCqmMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  NotifyCqmMessage() : Nl80211Message(kCommand, kCommandString) {}
  NotifyCqmMessage(const NotifyCqmMessage&) = delete;
  NotifyCqmMessage& operator=(const NotifyCqmMessage&) = delete;
};

class SHILL_EXPORT PmksaCandidateMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  PmksaCandidateMessage() : Nl80211Message(kCommand, kCommandString) {}
  PmksaCandidateMessage(const PmksaCandidateMessage&) = delete;
  PmksaCandidateMessage& operator=(const PmksaCandidateMessage&) = delete;
};

class SHILL_EXPORT ProbeMeshLinkMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  ProbeMeshLinkMessage();
  ProbeMeshLinkMessage(const ProbeMeshLinkMessage&) = delete;
  ProbeMeshLinkMessage& operator=(const ProbeMeshLinkMessage&) = delete;
};

class SHILL_EXPORT RegBeaconHintMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  RegBeaconHintMessage() : Nl80211Message(kCommand, kCommandString) {}
  RegBeaconHintMessage(const RegBeaconHintMessage&) = delete;
  RegBeaconHintMessage& operator=(const RegBeaconHintMessage&) = delete;
};

class SHILL_EXPORT RegChangeMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  RegChangeMessage();
  RegChangeMessage(const RegChangeMessage&) = delete;
  RegChangeMessage& operator=(const RegChangeMessage&) = delete;
};

class SHILL_EXPORT RemainOnChannelMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  RemainOnChannelMessage() : Nl80211Message(kCommand, kCommandString) {}
  RemainOnChannelMessage(const RemainOnChannelMessage&) = delete;
  RemainOnChannelMessage& operator=(const RemainOnChannelMessage&) = delete;
};

class SHILL_EXPORT RoamMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  RoamMessage() : Nl80211Message(kCommand, kCommandString) {}
  RoamMessage(const RoamMessage&) = delete;
  RoamMessage& operator=(const RoamMessage&) = delete;
};

class SHILL_EXPORT ScanAbortedMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  ScanAbortedMessage() : Nl80211Message(kCommand, kCommandString) {}
  ScanAbortedMessage(const ScanAbortedMessage&) = delete;
  ScanAbortedMessage& operator=(const ScanAbortedMessage&) = delete;
};

class SHILL_EXPORT GetScanMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetScanMessage();
  GetScanMessage(const GetScanMessage&) = delete;
  GetScanMessage& operator=(const GetScanMessage&) = delete;
};

class SHILL_EXPORT TriggerScanMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  TriggerScanMessage();
  TriggerScanMessage(const TriggerScanMessage&) = delete;
  TriggerScanMessage& operator=(const TriggerScanMessage&) = delete;
};

class SHILL_EXPORT UnknownNl80211Message : public Nl80211Message {
 public:
  explicit UnknownNl80211Message(uint8_t command)
      : Nl80211Message(command, "<UNKNOWN NL80211 MESSAGE>") {}
  UnknownNl80211Message(const UnknownNl80211Message&) = delete;
  UnknownNl80211Message& operator=(const UnknownNl80211Message&) = delete;
};

class SHILL_EXPORT UnprotDeauthenticateMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  UnprotDeauthenticateMessage() : Nl80211Message(kCommand, kCommandString) {}
  UnprotDeauthenticateMessage(const UnprotDeauthenticateMessage&) = delete;
  UnprotDeauthenticateMessage& operator=(const UnprotDeauthenticateMessage&) =
      delete;
};

class SHILL_EXPORT UnprotDisassociateMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  UnprotDisassociateMessage() : Nl80211Message(kCommand, kCommandString) {}
  UnprotDisassociateMessage(const UnprotDisassociateMessage&) = delete;
  UnprotDisassociateMessage& operator=(const UnprotDisassociateMessage&) =
      delete;
};

class SHILL_EXPORT WiphyRegChangeMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  WiphyRegChangeMessage();
  WiphyRegChangeMessage(const WiphyRegChangeMessage&) = delete;
  WiphyRegChangeMessage& operator=(const WiphyRegChangeMessage&) = delete;
};

class SHILL_EXPORT GetInterfaceMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetInterfaceMessage();
  GetInterfaceMessage(const GetInterfaceMessage&) = delete;
  GetInterfaceMessage& operator=(const GetInterfaceMessage&) = delete;
};

class SHILL_EXPORT NewInterfaceMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  NewInterfaceMessage() : Nl80211Message(kCommand, kCommandString) {}
  NewInterfaceMessage(const NewInterfaceMessage&) = delete;
  NewInterfaceMessage& operator=(const NewInterfaceMessage&) = delete;
};

class SHILL_EXPORT GetSurveyMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetSurveyMessage();
  GetSurveyMessage(const GetSurveyMessage&) = delete;
  GetSurveyMessage& operator=(const GetSurveyMessage&) = delete;
};

class SHILL_EXPORT SurveyResultsMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  SurveyResultsMessage() : Nl80211Message(kCommand, kCommandString) {}
  SurveyResultsMessage(const SurveyResultsMessage&) = delete;
  SurveyResultsMessage& operator=(const SurveyResultsMessage&) = delete;
};

class SHILL_EXPORT GetMeshPathInfoMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetMeshPathInfoMessage();
  GetMeshPathInfoMessage(const GetMeshPathInfoMessage&) = delete;
  GetMeshPathInfoMessage& operator=(const GetMeshPathInfoMessage&) = delete;
};

class SHILL_EXPORT GetMeshProxyPathMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetMeshProxyPathMessage();
  GetMeshProxyPathMessage(const GetMeshProxyPathMessage&) = delete;
  GetMeshProxyPathMessage& operator=(const GetMeshProxyPathMessage&) = delete;
};

class SHILL_EXPORT NewPeerCandidateMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  NewPeerCandidateMessage() : Nl80211Message(kCommand, kCommandString) {}
  NewPeerCandidateMessage(const NewPeerCandidateMessage&) = delete;
  NewPeerCandidateMessage& operator=(const NewPeerCandidateMessage&) = delete;
};

class SHILL_EXPORT ControlPortFrameTxStatusMessage : public Nl80211Message {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  ControlPortFrameTxStatusMessage()
      : Nl80211Message(kCommand, kCommandString) {}
  ControlPortFrameTxStatusMessage(const ControlPortFrameTxStatusMessage&) =
      delete;
  ControlPortFrameTxStatusMessage& operator=(
      const ControlPortFrameTxStatusMessage&) = delete;
};

}  // namespace shill

#endif  // SHILL_NET_NL80211_MESSAGE_H_
