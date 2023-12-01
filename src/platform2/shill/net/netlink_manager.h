// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This software provides an abstracted interface to the netlink socket
// interface.  In its current implementation it is used, primarily, to
// communicate with the cfg80211 kernel module and mac80211 drivers:
//
//         [shill]--[nl80211 library]
//            |
//     (netlink socket)
//            |
// [cfg80211 kernel module]
//            |
//    [mac80211 drivers]
//
// In order to send a message and handle it's response, do the following:
// - Create a handler (it'll want to verify that it's the kind of message you
//   want, cast it to the appropriate type, and get attributes from the cast
//   message):
//
//    #include "nl80211_message.h"
//    class SomeClass {
//      static void MyMessageHandler(const NetlinkMessage& raw) {
//        if (raw.message_type() != ControlNetlinkMessage::kMessageType)
//          return;
//        const ControlNetlinkMessage* message =
//          reinterpret_cast<const ControlNetlinkMessage*>(&raw);
//        if (message.command() != NewFamilyMessage::kCommand)
//          return;
//        uint16_t my_attribute;
//        message->const_attributes()->GetU16AttributeValue(
//          CTRL_ATTR_FAMILY_ID, &my_attribute);
//      }  // MyMessageHandler.
//    }  // class SomeClass.
//
// - Instantiate a message:
//
//    #include "nl80211_message.h"
//    GetFamilyMessage msg;
//
// - And set attributes:
//
//    msg.attributes()->SetStringAttributeValue(CTRL_ATTR_FAMILY_NAME, "foo");
//
// - Then send the message, passing-in a closure to the handler you created:
//
//    NetlinkManager* netlink_manager = NetlinkManager::GetInstance();
//    netlink_manager->SendMessage(&msg, Bind(&SomeClass::MyMessageHandler));
//
// NetlinkManager will then save your handler and send your message.  When a
// response to your message arrives, it'll call your handler.
//

#ifndef SHILL_NET_NETLINK_MANAGER_H_
#define SHILL_NET_NETLINK_MANAGER_H_

#include <list>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <string>

#include <base/cancelable_callback.h>
#include <base/functional/bind.h>
#include <base/lazy_instance.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/net/generic_netlink_message.h"
#include "shill/net/io_handler_factory_container.h"
#include "shill/net/netlink_message.h"
#include "shill/net/netlink_socket.h"
#include "shill/net/shill_export.h"
#include "shill/net/shill_time.h"

namespace shill {

class ControlNetlinkMessage;
struct InputData;
class NetlinkPacket;
class Nl80211Message;

// NetlinkManager is a singleton that coordinates sending netlink messages to,
// and receiving netlink messages from, the kernel.  The first use of this is
// to communicate between user-space and the cfg80211 module that manages wifi
// drivers.  Bring NetlinkManager up as follows:
//  NetlinkManager* netlink_manager_ = NetlinkManager::GetInstance();
//  netlink_manager_->Init();  // Initialize the socket.
//  // Get message types for all dynamic message types.
//  Nl80211Message::SetMessageType(
//      netlink_manager_->GetFamily(Nl80211Message::kMessageTypeString,
//                              Bind(&Nl80211Message::CreateMessage)));
//  netlink_manager_->Start();
class SHILL_EXPORT NetlinkManager {
 public:
  enum AuxiliaryMessageType {
    kDone,
    kErrorFromKernel,
    kTimeoutWaitingForResponse,
    kUnexpectedResponseType
  };
  using NetlinkMessageHandler =
      base::RepeatingCallback<void(const NetlinkMessage&)>;
  using ControlNetlinkMessageHandler =
      base::RepeatingCallback<void(const ControlNetlinkMessage&)>;
  using Nl80211MessageHandler =
      base::RepeatingCallback<void(const Nl80211Message&)>;
  // NetlinkAuxiliaryMessageHandler handles netlink error messages, things
  // like the DoneMessage at the end of a multi-part message, and any errors
  // discovered by |NetlinkManager| (which are passed as NULL pointers because
  // there is no way to reserve a part of the ErrorAckMessage space for
  // non-netlink errors).
  using NetlinkAuxiliaryMessageHandler = base::RepeatingCallback<void(
      AuxiliaryMessageType type, const NetlinkMessage*)>;
  // NetlinkAckHandler handles netlink Ack messages, which are a special type
  // of netlink error message carrying an error code of 0. Since Ack messages
  // contain no useful data (other than the error code of 0 to differentiate
  // it from an actual error message), the handler is not passed a message.
  // as an argument. The boolean value filled in by the handler (via the
  // pointer) indicates whether or not the callbacks registered for the message
  // (identified by sequence number) that this handler was invoked for should be
  // removed after this callback is executed. This allows a sender of an NL80211
  // message to handle both an Ack and another response message, rather than
  // handle only the first response received.
  using NetlinkAckHandler = base::RepeatingCallback<void(bool*)>;

  // ResponseHandlers provide a polymorphic context for the
  // base::RepeatingCallback message handlers so that handlers for different
  // types of messages can be kept in the same container (namely,
  // |message_handlers_|).
  class NetlinkResponseHandler
      : public base::RefCounted<NetlinkResponseHandler> {
   public:
    NetlinkResponseHandler(const NetlinkAckHandler& ack_handler,
                           const NetlinkAuxiliaryMessageHandler& error_handler);
    virtual ~NetlinkResponseHandler();
    // Calls wrapper-type-specific callback for |netlink_message|.  Returns
    // false if |netlink_message| is not the correct type.  Calls callback
    // (which is declared in the private area of derived classes) with
    // properly cast version of |netlink_message|.
    virtual bool HandleMessage(const NetlinkMessage& netlink_message) const = 0;
    void HandleError(AuxiliaryMessageType type,
                     const NetlinkMessage* netlink_message) const;
    virtual bool HandleAck() const;
    void set_delete_after(const timeval& time) { delete_after_ = time; }
    const struct timeval& delete_after() const { return delete_after_; }

   protected:
    NetlinkResponseHandler();
    NetlinkResponseHandler(const NetlinkResponseHandler&) = delete;
    NetlinkResponseHandler& operator=(const NetlinkResponseHandler&) = delete;

    NetlinkAckHandler ack_handler_;

   private:
    NetlinkAuxiliaryMessageHandler error_handler_;
    struct timeval delete_after_;
  };

  // Encapsulates all the different things we know about a specific message
  // type like its name, and its id.
  struct MessageType {
    MessageType();

    uint16_t family_id;

    // Multicast groups supported by the family.  The string and mapping to
    // a group id are extracted from the CTRL_CMD_NEWFAMILY message.
    std::map<std::string, uint32_t> groups;
  };

  // Various kinds of events to which we can subscribe (and receive) from
  // cfg80211.
  static const char kEventTypeConfig[];
  static const char kEventTypeScan[];
  static const char kEventTypeRegulatory[];
  static const char kEventTypeMlme[];

  // NetlinkManager is a singleton and this is the way to access it.
  static NetlinkManager* GetInstance();

  virtual ~NetlinkManager();

  // Performs non-trivial object initialization of the NetlinkManager singleton.
  virtual bool Init();

  // Passes the job of waiting for, and the subsequent reading from, the
  // netlink socket to the current message loop.
  virtual void Start();

  // The following methods deal with the network family table.  This table
  // associates netlink family names with family_ids (also called message
  // types).  Note that some families have static ids assigned to them but
  // others require the kernel to resolve a string describing the family into
  // a dynamically-determined id.

  // Returns the family_id (message type) associated with |family_name|,
  // calling the kernel if needed.  Returns
  // |NetlinkMessage::kIllegalMessageType| if the message type could not be
  // determined.  May block so |GetFamily| should be called before entering the
  // event loop.
  virtual uint16_t GetFamily(
      const std::string& family_name,
      const NetlinkMessageFactory::FactoryMethod& message_factory);

  // Install a NetlinkManager NetlinkMessageHandler.  The handler is a
  // user-supplied object to be called by the system for user-bound messages
  // that do not have a corresponding message-specific callback.
  // |AddBroadcastHandler| should be called before |SubscribeToEvents| since
  // the result of this call are used for that call.
  virtual bool AddBroadcastHandler(
      const NetlinkMessageHandler& message_handler);

  // Uninstall a NetlinkMessage Handler.
  virtual bool RemoveBroadcastHandler(
      const NetlinkMessageHandler& message_handler);

  // Determines whether a handler is in the list of broadcast handlers.
  bool FindBroadcastHandler(const NetlinkMessageHandler& message_handler) const;

  // Uninstall all broadcast netlink message handlers.
  void ClearBroadcastHandlers();

  // Sends a netlink message to the kernel using the NetlinkManager socket after
  // installing a handler to deal with the kernel's response to the message.
  // TODO(wdg): Eventually, this should also include a timeout and a callback
  // to call in case of timeout.
  virtual bool SendControlMessage(
      ControlNetlinkMessage* message,
      const ControlNetlinkMessageHandler& message_handler,
      const NetlinkAckHandler& ack_handler,
      const NetlinkAuxiliaryMessageHandler& error_handler);
  virtual bool SendNl80211Message(
      Nl80211Message* message,
      const Nl80211MessageHandler& message_handler,
      const NetlinkAckHandler& ack_handler,
      const NetlinkAuxiliaryMessageHandler& error_handler);

  // Get string version of NetlinkMessage for logging purposes
  static std::string GetRawMessage(const NetlinkMessage* raw_message);

  // Generic erroneous message handler everyone can use.
  static void OnNetlinkMessageError(AuxiliaryMessageType type,
                                    const NetlinkMessage* raw_message);

  // Generic Ack handler that does nothing. Other callbacks registered for the
  // message are not deleted after this function is executed.
  static void OnAckDoNothing(bool* remove_callbacks) {
    *remove_callbacks = false;
  }

  // Uninstall the handler for a specific netlink message.
  bool RemoveMessageHandler(const NetlinkMessage& message);

  // Sign-up to receive and log multicast events of a specific type. These
  // events are processed by message handlers added with |AddBroadcastHandler|.
  virtual bool SubscribeToEvents(const std::string& family,
                                 const std::string& group);

  // Gets the next sequence number for a NetlinkMessage to be sent over
  // NetlinkManager's netlink socket.
  uint32_t GetSequenceNumber();

 protected:
  NetlinkManager();
  NetlinkManager(const NetlinkManager&) = delete;
  NetlinkManager& operator=(const NetlinkManager&) = delete;

 private:
  friend base::LazyInstanceTraitsBase<NetlinkManager>;
  friend class NetlinkManagerTest;
  friend class NetlinkMessageTest;
  FRIEND_TEST(NetlinkManagerTest, BroadcastHandler);
  FRIEND_TEST(NetlinkManagerTest, GetFamilyOneInterstitialMessage);
  FRIEND_TEST(NetlinkManagerTest, GetFamilyTimeout);
  FRIEND_TEST(NetlinkManagerTest, MessageHandler);
  FRIEND_TEST(NetlinkManagerTest, AckHandler);
  FRIEND_TEST(NetlinkManagerTest, ErrorHandler);
  FRIEND_TEST(NetlinkManagerTest, MultipartMessageHandler);
  FRIEND_TEST(NetlinkManagerTest, OnInvalidRawNlMessageReceived);
  FRIEND_TEST(NetlinkManagerTest, TimeoutResponseHandlers);
  FRIEND_TEST(NetlinkManagerTest, PendingDump);
  FRIEND_TEST(NetlinkManagerTest, PendingDump_Timeout);
  FRIEND_TEST(NetlinkManagerTest, PendingDump_Retry);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_ASSOCIATE);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_AUTHENTICATE);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_CONNECT);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_DEAUTHENTICATE);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_DISASSOCIATE);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_DISCONNECT);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_NEW_SCAN_RESULTS);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_NEW_STATION);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_NOTIFY_CQM);
  FRIEND_TEST(NetlinkMessageTest, Parse_NL80211_CMD_TRIGGER_SCAN);

  using NetlinkResponseHandlerRefPtr = scoped_refptr<NetlinkResponseHandler>;

  // Container for information we need to send a netlink message out on a
  // netlink socket.
  struct NetlinkPendingMessage {
    NetlinkPendingMessage(uint32_t sequence_number_arg,
                          bool is_dump_request_arg,
                          ByteString message_string_arg,
                          NetlinkResponseHandlerRefPtr handler_arg)
        : retries_left(kMaxNlMessageRetries),
          sequence_number(sequence_number_arg),
          is_dump_request(is_dump_request_arg),
          message_string(message_string_arg),
          handler(handler_arg) {}

    int retries_left;
    uint32_t sequence_number;
    bool is_dump_request;
    ByteString message_string;
    NetlinkResponseHandlerRefPtr handler;
    uint32_t last_received_error;
  };

  // These need to be member variables, even though they're only used once in
  // the code, since they're needed for unittests.
  static const long kMaximumNewFamilyWaitSeconds;       // NOLINT
  static const long kMaximumNewFamilyWaitMicroSeconds;  // NOLINT
  static const long kResponseTimeoutSeconds;            // NOLINT
  static const long kResponseTimeoutMicroSeconds;       // NOLINT
  static constexpr base::TimeDelta kPendingDumpTimeout = base::Seconds(1);
  static constexpr base::TimeDelta kNlMessageRetryDelay =
      base::Milliseconds(300);
  static const int kMaxNlMessageRetries;                // NOLINT

  // Returns the file descriptor of socket used to read wifi data.
  int file_descriptor() const;

  // MessageLoop calls this when data is available on our socket.  This
  // method passes each, individual, message in the input to
  // |OnNlMessageReceived|.  Each part of a multipart message gets handled,
  // individually, by this method.
  void OnRawNlMessageReceived(InputData* data);

  // This method processes a message from |OnRawNlMessageReceived| by passing
  // the message to either the NetlinkManager callback that matches the sequence
  // number of the message or, if there isn't one, to all of the default
  // NetlinkManager callbacks in |broadcast_handlers_|.
  void OnNlMessageReceived(NetlinkPacket* packet);

  // Sends the pending dump message, and decrement the message's retry count if
  // it was resent successfully.
  void ResendPendingDumpMessage();

  // If a NetlinkResponseHandler registered for the message identified by
  // |sequence_number| exists, calls the error handler with the arguments |type|
  // and |netlink_message|, then erases the NetlinkResponseHandler from
  // |message_handlers_|.
  void CallErrorHandler(uint32_t sequence_number,
                        AuxiliaryMessageType type,
                        const NetlinkMessage* netlink_message);

  // Called by InputHandler on exceptional events.
  void OnReadError(const std::string& error_msg);

  // Utility function that posts a task to the message loop to call
  // NetlinkManager::ResendPendingDumpMessage kNlMessageRetryDelay from now.
  void ResendPendingDumpMessageAfterDelay();

  // Just for tests, this method turns off WiFi and clears the subscribed
  // events list. If |full| is true, also clears state set by Init.
  void Reset(bool full);

  // Handles a CTRL_CMD_NEWFAMILY message from the kernel.
  void OnNewFamilyMessage(const ControlNetlinkMessage& message);

  // Sends a netlink message if |pending_dump_| is false. Otherwise, post
  // a message to |pending_messages_| to be sent later.
  bool SendOrPostMessage(
      NetlinkMessage* message,
      NetlinkResponseHandler* message_wrapper);  // Passes ownership.

  // Install a handler to deal with kernel's response to the message contained
  // in |pending_message|, then sends the message by calling
  // NetlinkManager::SendMessageInternal.
  bool RegisterHandlersAndSendMessage(
      const NetlinkPendingMessage& pending_message);

  // Sends the netlink message whose bytes are contained in |pending_message| to
  // the kernel using the NetlinkManager socket. If |pending_message| is a dump
  // request and the message is sent successfully, a timeout timer is started to
  // limit the amount of time we wait for responses to that message. Adds a
  // serial number to |message| before it is sent.
  bool SendMessageInternal(const NetlinkPendingMessage& pending_message);

  // Given a netlink packet |packet|, infers the context of this netlink
  // message (for message parsing purposes) and returns a MessageContext
  // describing this context.
  NetlinkMessage::MessageContext InferMessageContext(
      const NetlinkPacket& packet);

  // Called when we time out waiting for a response to a netlink dump message.
  // Invokes the error handler with kTimeoutWaitingForResponse, deletes the
  // error handler, then calls NetlinkManager::OnPendingDumpComplete.
  void OnPendingDumpTimeout();

  // Cancels |pending_dump_timeout_callback_|, deletes the currently pending
  // dump request message from the front of |pending_messages_| since we have
  // finished waiting for replies, then sends the next message in
  // |pending_messages_| (if any).
  void OnPendingDumpComplete();

  // Returns true iff there we are waiting for replies to a netlink dump
  // message, false otherwise.
  bool IsDumpPending();

  // Returns the sequence number of the pending netlink dump request message iff
  // there is a pending dump. Otherwise, returns 0.
  uint32_t PendingDumpSequenceNumber();

  // NetlinkManager Handlers, OnRawNlMessageReceived invokes each of these
  // User-supplied callback object when _it_ gets called to read netlink data.
  std::list<NetlinkMessageHandler> broadcast_handlers_;

  // Message-specific callbacks, mapped by message ID.
  std::map<uint32_t, NetlinkResponseHandlerRefPtr> message_handlers_;

  // Netlink messages due to be sent to the kernel. If a dump is pending,
  // the first element in this queue will contain the netlink dump request
  // message that we are waiting on replies for.
  std::queue<NetlinkPendingMessage> pending_messages_;

  base::WeakPtrFactory<NetlinkManager> weak_ptr_factory_;
  base::CancelableOnceClosure pending_dump_timeout_callback_;
  base::CancelableOnceClosure resend_dump_message_callback_;
  std::unique_ptr<IOHandler> dispatcher_handler_;

  std::unique_ptr<NetlinkSocket> sock_;
  std::map<const std::string, MessageType> message_types_;
  NetlinkMessageFactory message_factory_;
  Time* time_;
  IOHandlerFactory* io_handler_factory_;
  bool dump_pending_;
};

}  // namespace shill

#endif  // SHILL_NET_NETLINK_MANAGER_H_
