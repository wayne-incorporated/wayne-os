// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_NETLINK_PACKET_H_
#define SHILL_NET_NETLINK_PACKET_H_

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include <memory>

#include "shill/net/attribute_list.h"
#include "shill/net/shill_export.h"

namespace shill {

class ByteString;

class SHILL_EXPORT NetlinkPacket {
 public:
  NetlinkPacket(const unsigned char* buf, size_t len);
  NetlinkPacket(const NetlinkPacket&) = delete;
  NetlinkPacket& operator=(const NetlinkPacket&) = delete;

  virtual ~NetlinkPacket();

  // Returns whether a packet was properly retrieved in the constructor.
  bool IsValid() const;

  // Returns the entire packet length (including the nlmsghdr).  Callers
  // can consider this to be the number of bytes consumed from |buf| in the
  // constructor.  This value will not change as data is consumed -- use
  // GetRemainingLength() instead for this.
  size_t GetLength() const;

  // Get the message type from the header.
  uint16_t GetMessageType() const;

  // Get the sequence number from the header.
  uint32_t GetMessageSequence() const;

  // Returns the remaining (un-consumed) payload length.
  size_t GetRemainingLength() const;

  // Returns the payload data.  It is a fatal error to call this method
  // on an invalid packet.
  const ByteString& GetPayload() const;

  // Consume netlink attributes from the remaining payload.
  bool ConsumeAttributes(const AttributeList::NewFromIdMethod& factory,
                         const AttributeListRefPtr& attributes);

  // Consume |len| bytes out of the payload, and place them in |data|.
  // Any trailing alignment padding in |payload| is also consumed.  Returns
  // true if there is enough data, otherwise returns false and does not
  // modify |data|.
  bool ConsumeData(size_t len, void* data);

  // Copies the initial part of the payload to |header| without
  // consuming any data.  Returns true if this operation succeeds (there
  // is enough data in the payload), false otherwise.
  bool GetGenlMsgHdr(genlmsghdr* header) const;

  // Returns the nlmsghdr associated with the packet.  It is a fatal error
  // to call this method on an invalid packet.
  const nlmsghdr& GetNlMsgHeader() const;

 protected:
  // These getters are protected so that derived classes may allow
  // the packet contents to be modified.
  nlmsghdr* mutable_header() { return &header_; }
  ByteString* mutable_payload() { return payload_.get(); }
  void set_consumed_bytes(size_t consumed_bytes) {
    consumed_bytes_ = consumed_bytes;
  }

 private:
  friend class NetlinkPacketTest;

  nlmsghdr header_;
  std::unique_ptr<ByteString> payload_;
  size_t consumed_bytes_;
};

// Mutable Netlink packets are used in unit tests where it is convenient
// to modify the header and payload of a packet before passing it to the
// NetlinkMessage subclasses or NetlinkManager.
class SHILL_EXPORT MutableNetlinkPacket : public NetlinkPacket {
 public:
  MutableNetlinkPacket(const unsigned char* buf, size_t len);
  MutableNetlinkPacket(const MutableNetlinkPacket&) = delete;
  MutableNetlinkPacket& operator=(const MutableNetlinkPacket&) = delete;

  virtual ~MutableNetlinkPacket();

  // Reset consumed_bytes_ as if this packet never underwent processing.
  // This is useful for unit tests that wish to re-send a previously
  // processed packet.
  void ResetConsumedBytes();

  // Returns mutable references to the header and payload.
  nlmsghdr* GetMutableHeader();
  ByteString* GetMutablePayload();

  // Set the message type in the header.
  void SetMessageType(uint16_t type);

  // Set the sequence number in the header.
  void SetMessageSequence(uint32_t sequence);
};

}  // namespace shill

#endif  // SHILL_NET_NETLINK_PACKET_H_
