// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_NETLINK_MESSAGE_H_
#define SHILL_NET_NETLINK_MESSAGE_H_

#include <linux/netlink.h>

#include <map>
#include <memory>
#include <string>

#include <base/functional/bind.h>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST.

#include "shill/net/byte_string.h"
#include "shill/net/shill_export.h"

struct nlmsghdr;

namespace shill {

// Netlink messages are sent over netlink sockets to talk between user-space
// programs (like shill) and kernel modules (like the cfg80211 module).  Each
// kernel module that talks netlink potentially adds its own family header to
// the nlmsghdr (the top-level netlink message header) and, potentially, uses a
// different payload format.  The NetlinkMessage class represents that which
// is common between the different types of netlink message.
//
// The common portions of Netlink Messages start with a |nlmsghdr|.  Those
// messages look something like the following:
//
//         |<--------------NetlinkPacket::GetLength()------------->|
//         |       |<--NetlinkPacket::GetPayload().GetLength() --->|
//         |       |                                               |
//    -----+-----+-+---------------------------------------------+-+----
//     ... |     | |                 netlink payload             | |
//         |     | +------------+-+------------------------------+ |
//         | nl  | |            | |                              | | nl
//         | msg |p| (optional) |p|                              |p| msg ...
//         | hdr |a| family     |a|        family payload        |a| hdr
//         |     |d| header     |d|                              |d|
//         |     | |            | |                              | |
//    -----+-----+-+------------+-+------------------------------+-+----
//                  ^
//                  |
//                  +-- nlmsg payload (NetlinkPacket::GetPayload())
//
// All NetlinkMessages sent to the kernel need a valid message type (which is
// found in the nlmsghdr structure) and all NetlinkMessages received from the
// kernel have a valid message type.  Some message types (NLMSG_NOOP,
// NLMSG_ERROR, and GENL_ID_CTRL, for example) are allocated statically; for
// those, the |message_type_| is assigned directly.
//
// Other message types ("nl80211", for example), are assigned by the kernel
// dynamically.  To get the message type, pass a closure to assign the
// message_type along with the sting to NetlinkManager::GetFamily:
//
//  nl80211_type = netlink_manager->GetFamily(Nl80211Message::kMessageType);
//
// Do all of this before you start to create NetlinkMessages so that
// NetlinkMessage can be instantiated with a valid |message_type_|.

class NetlinkPacket;

class SHILL_EXPORT NetlinkMessage {
 public:
  // Describes the context of the netlink message for parsing purposes.
  struct MessageContext {
    MessageContext() : nl80211_cmd(0), is_broadcast(false) {}

    size_t nl80211_cmd;
    bool is_broadcast;
  };

  static const uint32_t kBroadcastSequenceNumber;
  static const uint16_t kIllegalMessageType;

  explicit NetlinkMessage(uint16_t message_type)
      : flags_(0),
        message_type_(message_type),
        sequence_number_(kBroadcastSequenceNumber) {}
  NetlinkMessage(const NetlinkMessage&) = delete;
  NetlinkMessage& operator=(const NetlinkMessage&) = delete;

  virtual ~NetlinkMessage() = default;

  // Returns a string of bytes representing the message (with it headers) and
  // any necessary padding.  These bytes are appropriately formatted to be
  // written to a netlink socket.
  virtual ByteString Encode(uint32_t sequence_number) = 0;

  // Initializes the |NetlinkMessage| from a complete and legal message
  // (potentially received from the kernel via a netlink socket).
  virtual bool InitFromPacket(NetlinkPacket* packet, MessageContext context);

  uint16_t message_type() const { return message_type_; }
  void AddFlag(uint16_t new_flag) { flags_ |= new_flag; }
  void AddAckFlag() { flags_ |= NLM_F_ACK; }
  uint16_t flags() const { return flags_; }
  uint32_t sequence_number() const { return sequence_number_; }

  virtual std::string ToString() const = 0;
  // Logs the message.  Allows a different log level (presumably more
  // stringent) for the body of the message than the header.
  virtual void Print(int header_log_level, int detail_log_level) const;

  // Logs the message's raw bytes (with minimal interpretation).
  static void PrintBytes(int log_level,
                         const unsigned char* buf,
                         size_t num_bytes);

  // Logs a netlink message (with minimal interpretation).
  static void PrintPacket(int log_level, const NetlinkPacket& packet);

 protected:
  friend class NetlinkManagerTest;

  // Returns a string of bytes representing an |nlmsghdr|, filled-in, and its
  // padding.
  virtual ByteString EncodeHeader(uint32_t sequence_number);
  // Reads the |nlmsghdr|.  Subclasses may read additional data from the
  // payload.
  virtual bool InitAndStripHeader(NetlinkPacket* packet);

  uint16_t flags_;
  uint16_t message_type_;
  uint32_t sequence_number_;

 private:
  static void PrintHeader(int log_level, const nlmsghdr* header);
  static void PrintPayload(int log_level,
                           const unsigned char* buf,
                           size_t num_bytes);
};

// The Error and Ack messages are received from the kernel and are combined,
// here, because they look so much alike (the only difference is that the
// error code is 0 for the Ack messages).  Error messages are received from
// the kernel in response to a sent message when there's a problem (such as
// a malformed message or a busy kernel module).  Ack messages are received
// from the kernel when a sent message has the NLM_F_ACK flag set, indicating
// that an Ack is requested.
class SHILL_EXPORT ErrorAckMessage : public NetlinkMessage {
 public:
  static const uint16_t kMessageType;

  ErrorAckMessage() : NetlinkMessage(kMessageType), error_(0) {}
  explicit ErrorAckMessage(uint32_t err)
      : NetlinkMessage(kMessageType), error_(err) {}
  ErrorAckMessage(const ErrorAckMessage&) = delete;
  ErrorAckMessage& operator=(const ErrorAckMessage&) = delete;

  static uint16_t GetMessageType() { return kMessageType; }
  bool InitFromPacket(NetlinkPacket* packet, MessageContext context) override;
  ByteString Encode(uint32_t sequence_number) override;
  std::string ToString() const override;
  uint32_t error() const { return -error_; }

 private:
  uint32_t error_;
};

class SHILL_EXPORT NoopMessage : public NetlinkMessage {
 public:
  static const uint16_t kMessageType;

  NoopMessage() : NetlinkMessage(kMessageType) {}
  NoopMessage(const NoopMessage&) = delete;
  NoopMessage& operator=(const NoopMessage&) = delete;

  static uint16_t GetMessageType() { return kMessageType; }
  ByteString Encode(uint32_t sequence_number) override;
  std::string ToString() const override;
};

class SHILL_EXPORT DoneMessage : public NetlinkMessage {
 public:
  static const uint16_t kMessageType;

  DoneMessage() : NetlinkMessage(kMessageType) {}
  DoneMessage(const DoneMessage&) = delete;
  DoneMessage& operator=(const DoneMessage&) = delete;

  static uint16_t GetMessageType() { return kMessageType; }
  ByteString Encode(uint32_t sequence_number) override;
  std::string ToString() const override;
};

class SHILL_EXPORT OverrunMessage : public NetlinkMessage {
 public:
  static const uint16_t kMessageType;

  OverrunMessage() : NetlinkMessage(kMessageType) {}
  OverrunMessage(const OverrunMessage&) = delete;
  OverrunMessage& operator=(const OverrunMessage&) = delete;

  static uint16_t GetMessageType() { return kMessageType; }
  ByteString Encode(uint32_t sequence_number) override;
  std::string ToString() const override;
};

class SHILL_EXPORT UnknownMessage : public NetlinkMessage {
 public:
  UnknownMessage(uint16_t message_type, ByteString message_body)
      : NetlinkMessage(message_type), message_body_(message_body) {}
  UnknownMessage(const UnknownMessage&) = delete;
  UnknownMessage& operator=(const UnknownMessage&) = delete;

  ByteString Encode(uint32_t sequence_number) override;
  std::string ToString() const override;
  void Print(int header_log_level, int detail_log_level) const override;

 private:
  ByteString message_body_;
};

//
// Factory class.
//

class SHILL_EXPORT NetlinkMessageFactory {
 public:
  using FactoryMethod = base::RepeatingCallback<std::unique_ptr<NetlinkMessage>(
      const NetlinkPacket& packet)>;

  NetlinkMessageFactory() = default;
  NetlinkMessageFactory(const NetlinkMessageFactory&) = delete;
  NetlinkMessageFactory& operator=(const NetlinkMessageFactory&) = delete;

  // Adds a message factory for a specific message_type.  Intended to be used
  // at initialization.
  bool AddFactoryMethod(uint16_t message_type, FactoryMethod factory);

  std::unique_ptr<NetlinkMessage> CreateMessage(
      NetlinkPacket* packet, NetlinkMessage::MessageContext context) const;

 private:
  std::map<uint16_t, FactoryMethod> factories_;
};

}  // namespace shill

#endif  // SHILL_NET_NETLINK_MESSAGE_H_
