// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/rtnl_handler.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <limits>
#include <utility>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "shill/net/io_handler.h"
#include "shill/net/ip_address.h"
#include "shill/net/ndisc.h"
#include "shill/net/netlink_fd.h"
#include "shill/net/sockets.h"

namespace shill {

const uint32_t RTNLHandler::kRequestLink = 1;
const uint32_t RTNLHandler::kRequestAddr = 2;
const uint32_t RTNLHandler::kRequestRoute = 4;
const uint32_t RTNLHandler::kRequestRule = 8;
const uint32_t RTNLHandler::kRequestRdnss = 16;
const uint32_t RTNLHandler::kRequestNeighbor = 32;
const uint32_t RTNLHandler::kRequestBridgeNeighbor = 64;

const int RTNLHandler::kErrorWindowSize = 16;
const uint32_t RTNLHandler::kStoredRequestWindowSize = 32;

namespace {
base::LazyInstance<RTNLHandler>::DestructorAtExit g_rtnl_handler =
    LAZY_INSTANCE_INITIALIZER;

// Increasing buffer size to avoid overflows on IPV6 routing events.
constexpr int kReceiveBufferBytes = 3 * 1024 * 1024;
}  // namespace

RTNLHandler::RTNLHandler()
    : sockets_(new Sockets()),
      in_request_(false),
      rtnl_socket_(Sockets::kInvalidFileDescriptor),
      netlink_groups_mask_(0),
      request_flags_(0),
      request_sequence_(0),
      last_dump_sequence_(0),
      io_handler_factory_(
          IOHandlerFactoryContainer::GetInstance()->GetIOHandlerFactory()) {
  error_mask_window_.resize(kErrorWindowSize);
  VLOG(2) << "RTNLHandler created";
}

RTNLHandler::~RTNLHandler() {
  VLOG(2) << "RTNLHandler removed";
  Stop();
}

RTNLHandler* RTNLHandler::GetInstance() {
  return g_rtnl_handler.Pointer();
}

void RTNLHandler::Start(uint32_t netlink_groups_mask) {
  netlink_groups_mask_ = netlink_groups_mask;
  if (rtnl_socket_ != Sockets::kInvalidFileDescriptor)
    return;

  rtnl_socket_ =
      OpenNetlinkSocketFD(sockets_.get(), NETLINK_ROUTE, netlink_groups_mask_);
  if (rtnl_socket_ < 0) {
    return;
  }

  SetReceiverBufferSize(kReceiveBufferBytes);

  rtnl_handler_.reset(io_handler_factory_->CreateIOInputHandler(
      rtnl_socket_,
      base::BindRepeating(&RTNLHandler::ParseRTNL, base::Unretained(this)),
      base::BindRepeating(&RTNLHandler::OnReadError, base::Unretained(this))));

  NextRequest(last_dump_sequence_);
  VLOG(2) << "RTNLHandler started";
}

void RTNLHandler::SetReceiverBufferSize(int bytes) {
  CHECK(rtnl_socket_ != Sockets::kInvalidFileDescriptor)
      << "Invalid socket descriptor: " << rtnl_socket_;

  if (sockets_->SetReceiveBuffer(rtnl_socket_, bytes) < 0)
    PLOG(WARNING) << "Failed to increase receive buffer size to " << bytes
                  << "b";
}

void RTNLHandler::Stop() {
  rtnl_handler_.reset();
  // Close the socket if it is currently open.
  if (rtnl_socket_ != Sockets::kInvalidFileDescriptor) {
    sockets_->Close(rtnl_socket_);
    rtnl_socket_ = Sockets::kInvalidFileDescriptor;
  }
  in_request_ = false;
  request_flags_ = 0;
  request_sequence_ = 0;
  last_dump_sequence_ = 0;
  stored_requests_.clear();
  oldest_request_sequence_ = 0;

  VLOG(2) << "RTNLHandler stopped";
}

void RTNLHandler::AddListener(RTNLListener* to_add) {
  listeners_.AddObserver(to_add);
  VLOG(2) << "RTNLHandler added listener";
}

void RTNLHandler::RemoveListener(RTNLListener* to_remove) {
  listeners_.RemoveObserver(to_remove);
  VLOG(2) << "RTNLHandler removed listener";
}

void RTNLHandler::SetInterfaceFlags(int interface_index,
                                    unsigned int flags,
                                    unsigned int change) {
  if (rtnl_socket_ == Sockets::kInvalidFileDescriptor) {
    LOG(ERROR) << __func__
               << " called while not started.  "
                  "Assuming we are in unit tests.";
    return;
  }

  auto msg = std::make_unique<RTNLMessage>(
      RTNLMessage::kTypeLink, RTNLMessage::kModeAdd, NLM_F_REQUEST,
      0,  // sequence to be filled in by RTNLHandler::SendMessage().
      0,  // pid.
      interface_index, IPAddress::kFamilyUnknown);

  msg->set_link_status(RTNLMessage::LinkStatus(ARPHRD_VOID, flags, change));

  ErrorMask error_mask;
  if ((flags & IFF_UP) == 0) {
    error_mask.insert(ENODEV);
  }

  SendMessageWithErrorMask(std::move(msg), error_mask, nullptr);
}

void RTNLHandler::SetInterfaceMTU(int interface_index, unsigned int mtu) {
  auto msg = std::make_unique<RTNLMessage>(
      RTNLMessage::kTypeLink, RTNLMessage::kModeAdd, NLM_F_REQUEST,
      0,  // sequence to be filled in by RTNLHandler::SendMessage().
      0,  // pid.
      interface_index, IPAddress::kFamilyUnknown);

  msg->SetAttribute(IFLA_MTU, ByteString(reinterpret_cast<unsigned char*>(&mtu),
                                         sizeof(mtu)));

  CHECK(SendMessage(std::move(msg), nullptr));
}

void RTNLHandler::SetInterfaceMac(int interface_index,
                                  const ByteString& mac_address) {
  SetInterfaceMac(interface_index, mac_address, ResponseCallback());
}

void RTNLHandler::SetInterfaceMac(int interface_index,
                                  const ByteString& mac_address,
                                  ResponseCallback response_callback) {
  auto msg = std::make_unique<RTNLMessage>(
      RTNLMessage::kTypeLink, RTNLMessage::kModeAdd, NLM_F_REQUEST | NLM_F_ACK,
      0,  // sequence to be filled in by RTNLHandler::SendMessage().
      0,  // pid.
      interface_index, IPAddress::kFamilyUnknown);

  msg->SetAttribute(IFLA_ADDRESS, mac_address);

  uint32_t seq;
  CHECK(SendMessage(std::move(msg), &seq));
  if (!response_callback.is_null()) {
    response_callbacks_[seq] = std::move(response_callback);
  }
}

void RTNLHandler::RequestDump(uint32_t request_flags) {
  if (rtnl_socket_ == Sockets::kInvalidFileDescriptor) {
    LOG(ERROR) << __func__
               << " called while not started.  "
                  "Assuming we are in unit tests.";
    return;
  }

  request_flags_ |= request_flags;

  VLOG(2) << base::StringPrintf("RTNLHandler got request to dump 0x%x",
                                request_flags);

  if (!in_request_) {
    NextRequest(last_dump_sequence_);
  }
}

void RTNLHandler::DispatchEvent(int type, const RTNLMessage& msg) {
  for (RTNLListener& listener : listeners_) {
    listener.NotifyEvent(type, msg);
  }
}

void RTNLHandler::NextRequest(uint32_t seq) {
  uint32_t flag = 0;
  RTNLMessage::Type type;

  VLOG(2) << base::StringPrintf("RTNLHandler nextrequest %d %d 0x%x", seq,
                                last_dump_sequence_, request_flags_);

  if (seq != last_dump_sequence_)
    return;

  IPAddress::Family family = IPAddress::kFamilyUnknown;
  if ((request_flags_ & kRequestAddr) != 0) {
    type = RTNLMessage::kTypeAddress;
    flag = kRequestAddr;
  } else if ((request_flags_ & kRequestRoute) != 0) {
    type = RTNLMessage::kTypeRoute;
    flag = kRequestRoute;
  } else if ((request_flags_ & kRequestRule) != 0) {
    type = RTNLMessage::kTypeRule;
    flag = kRequestRule;
  } else if ((request_flags_ & kRequestLink) != 0) {
    type = RTNLMessage::kTypeLink;
    flag = kRequestLink;
  } else if ((request_flags_ & kRequestNeighbor) != 0) {
    type = RTNLMessage::kTypeNeighbor;
    flag = kRequestNeighbor;
  } else if ((request_flags_ & kRequestBridgeNeighbor) != 0) {
    type = RTNLMessage::kTypeNeighbor;
    flag = kRequestBridgeNeighbor;
    family = AF_BRIDGE;
  } else {
    VLOG(2) << "Done with requests";
    in_request_ = false;
    return;
  }

  auto msg = std::make_unique<RTNLMessage>(type, RTNLMessage::kModeGet, 0, 0, 0,
                                           0, family);
  uint32_t msg_seq;
  CHECK(SendMessage(std::move(msg), &msg_seq));

  last_dump_sequence_ = msg_seq;
  request_flags_ &= ~flag;
  in_request_ = true;
}

void RTNLHandler::ParseRTNL(InputData* data) {
  const unsigned char* buf = data->buf;
  const unsigned char* end = buf + data->len;

  while (buf < end) {
    const struct nlmsghdr* hdr = reinterpret_cast<const struct nlmsghdr*>(buf);
    if (!NLMSG_OK(hdr, static_cast<unsigned int>(end - buf)))
      break;

    const uint8_t* payload = reinterpret_cast<const uint8_t*>(hdr);
    VLOG(5) << __func__ << "RTNL received payload length " << hdr->nlmsg_len
            << ": \"" << ByteString(payload, hdr->nlmsg_len).HexEncode()
            << "\"";

    // Swapping out of |stored_requests_| here ensures that the RTNLMessage will
    // be destructed regardless of the control flow below.
    std::unique_ptr<RTNLMessage> request_msg = PopStoredRequest(hdr->nlmsg_seq);

    RTNLMessage msg;
    if (!msg.Decode(payload, hdr->nlmsg_len)) {
      VLOG(5) << __func__ << ": rtnl packet type " << hdr->nlmsg_type
              << " length " << hdr->nlmsg_len << " sequence " << hdr->nlmsg_seq;

      switch (hdr->nlmsg_type) {
        case NLMSG_NOOP:
        case NLMSG_OVERRUN:
          break;
        case NLMSG_DONE:
          GetAndClearErrorMask(hdr->nlmsg_seq);  // Clear any queued error mask.
          NextRequest(hdr->nlmsg_seq);
          break;
        case NLMSG_ERROR: {
          if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
            VLOG(5) << "invalid error message header: length "
                    << hdr->nlmsg_len;
            break;
          }

          const struct nlmsgerr* hdrErr =
              reinterpret_cast<nlmsgerr*>(NLMSG_DATA(hdr));
          std::string request_str;
          RTNLMessage::Mode mode = RTNLMessage::kModeUnknown;
          if (request_msg) {
            request_str = " (" + request_msg->ToString() + ")";
            mode = request_msg->mode();
          } else {
            const uint8_t* error_payload =
                reinterpret_cast<const uint8_t*>(&(hdrErr->msg));
            if (NLMSG_OK(&(hdrErr->msg),
                         static_cast<unsigned int>(end - error_payload))) {
              RTNLMessage msgErr;
              if (msgErr.Decode(error_payload, hdrErr->msg.nlmsg_len)) {
                request_str = " (" + msgErr.ToString() + ")";
                mode = msgErr.mode();
              }
            }
          }

          if (request_str.empty()) {
            request_str = "(Request Unavailable)";
          }

          int error_number = hdrErr->error;
          if (error_number == 0) {
            VLOG(3) << base::StringPrintf("sequence %d%s received success",
                                          hdr->nlmsg_seq, request_str.c_str());
          } else if ((error_number > 0 ||
                      error_number == std::numeric_limits<int>::min())) {
            LOG(ERROR) << base::StringPrintf(
                "sequence %d%s received invalid error %d", hdr->nlmsg_seq,
                request_str.c_str(), error_number);
          } else {
            error_number = -error_number;
            std::string error_msg = base::StringPrintf(
                "sequence %d%s received error %d (%s)", hdr->nlmsg_seq,
                request_str.c_str(), error_number, strerror(error_number));
            if (base::Contains(GetAndClearErrorMask(hdr->nlmsg_seq),
                               error_number) ||
                (error_number == EEXIST && mode == RTNLMessage::kModeAdd) ||
                (mode == RTNLMessage::kModeDelete &&
                 (error_number == ENOENT || error_number == ESRCH ||
                  error_number == ENODEV || error_number == EADDRNOTAVAIL))) {
              // EEXIST for create requests and ENOENT, ESRCH, ENODEV,
              // EADDRNOTAVAIL for delete requests do not really indicate an
              // error condition.
              VLOG(2) << error_msg;
            } else {
              LOG(ERROR) << error_msg;
            }
          }

          auto response_callback_iter =
              response_callbacks_.find(hdr->nlmsg_seq);
          if (response_callback_iter != response_callbacks_.end()) {
            std::move(response_callback_iter->second).Run(error_number);
            response_callbacks_.erase(response_callback_iter);
          }

          break;
        }
        default:
          LOG(ERROR) << "Unknown NL message type: " << hdr->nlmsg_type;
      }
    } else {
      switch (msg.type()) {
        case RTNLMessage::kTypeLink:
          DispatchEvent(kRequestLink, msg);
          break;
        case RTNLMessage::kTypeAddress:
          DispatchEvent(kRequestAddr, msg);
          break;
        case RTNLMessage::kTypeRoute:
          DispatchEvent(kRequestRoute, msg);
          break;
        case RTNLMessage::kTypeRule:
          DispatchEvent(kRequestRule, msg);
          break;
        case RTNLMessage::kTypeRdnss:
          DispatchEvent(kRequestRdnss, msg);
          break;
        case RTNLMessage::kTypeNeighbor:
          DispatchEvent(kRequestNeighbor, msg);
          break;
        case RTNLMessage::kTypeDnssl:
          // DNSSL support is not implemented. Just ignore it.
          break;
        default:
          LOG(ERROR) << "Unknown RTNL message type: " << msg.type();
      }
    }
    buf += NLMSG_ALIGN(hdr->nlmsg_len);
  }
}

bool RTNLHandler::AddressRequest(int interface_index,
                                 RTNLMessage::Mode mode,
                                 int flags,
                                 const IPAddress& local,
                                 const std::optional<IPAddress>& broadcast) {
  auto msg = std::make_unique<RTNLMessage>(RTNLMessage::kTypeAddress, mode,
                                           NLM_F_REQUEST | flags, 0, 0,
                                           interface_index, local.family());

  msg->set_address_status(RTNLMessage::AddressStatus(local.prefix(), 0, 0));

  msg->SetAttribute(IFA_LOCAL, local.address());
  if (broadcast && !broadcast->IsDefault()) {
    CHECK_EQ(broadcast->family(), local.family());
    msg->SetAttribute(IFA_BROADCAST, broadcast->address());
  }

  return SendMessage(std::move(msg), nullptr);
}

bool RTNLHandler::AddInterfaceAddress(int interface_index,
                                      const IPAddress& local,
                                      const IPAddress& broadcast) {
  return AddressRequest(interface_index, RTNLMessage::kModeAdd,
                        NLM_F_CREATE | NLM_F_EXCL | NLM_F_ECHO, local,
                        broadcast);
}

bool RTNLHandler::RemoveInterfaceAddress(int interface_index,
                                         const IPAddress& local) {
  return AddressRequest(interface_index, RTNLMessage::kModeDelete, NLM_F_ECHO,
                        local, std::nullopt);
}

bool RTNLHandler::RemoveInterface(int interface_index) {
  auto msg = std::make_unique<RTNLMessage>(
      RTNLMessage::kTypeLink, RTNLMessage::kModeDelete, NLM_F_REQUEST, 0, 0,
      interface_index, IPAddress::kFamilyUnknown);
  return SendMessage(std::move(msg), nullptr);
}

int RTNLHandler::GetInterfaceIndex(const std::string& interface_name) {
  if (interface_name.empty()) {
    LOG(ERROR) << "Empty interface name -- unable to obtain index.";
    return -1;
  }
  struct ifreq ifr;
  if (interface_name.size() >= sizeof(ifr.ifr_name)) {
    LOG(ERROR) << "Interface name too long: " << interface_name.size()
               << " >= " << sizeof(ifr.ifr_name);
    return -1;
  }
  int socket = sockets_->Socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (socket < 0) {
    PLOG(ERROR) << "Unable to open INET socket";
    return -1;
  }
  ScopedSocketCloser socket_closer(sockets_.get(), socket);
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));
  if (sockets_->Ioctl(socket, SIOCGIFINDEX, &ifr) < 0) {
    PLOG(ERROR) << "SIOCGIFINDEX error for " << interface_name;
    return -1;
  }
  return ifr.ifr_ifindex;
}

bool RTNLHandler::AddInterface(const std::string& interface_name,
                               const std::string& link_kind,
                               const ByteString& link_info_data,
                               ResponseCallback response_callback) {
  if (interface_name.length() >= IFNAMSIZ) {
    LOG(DFATAL) << "Interface name is too long: " << interface_name;
    return false;
  }

  auto msg = std::make_unique<RTNLMessage>(
      shill::RTNLMessage::kTypeLink, shill::RTNLMessage::kModeAdd,
      NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, 0 /* seq */,
      0 /* pid */, 0 /* if_index */, IPAddress::kFamilyUnknown);
  msg->SetAttribute(IFLA_IFNAME, {interface_name, true});
  msg->SetIflaInfoKind(link_kind, link_info_data);

  uint32_t seq;
  if (!SendMessage(std::move(msg), &seq)) {
    LOG(WARNING) << "Failed to send add link message for " << interface_name;
    return false;
  }

  if (!response_callback.is_null()) {
    response_callbacks_[seq] = std::move(response_callback);
  }
  return true;
}

bool RTNLHandler::SendMessage(std::unique_ptr<RTNLMessage> message,
                              uint32_t* msg_seq) {
  ErrorMask error_mask;
  if (message->mode() == RTNLMessage::kModeAdd) {
    error_mask = {EEXIST};
  } else if (message->mode() == RTNLMessage::kModeDelete) {
    error_mask = {ESRCH, ENODEV};
    if (message->type() == RTNLMessage::kTypeAddress) {
      error_mask.insert(EADDRNOTAVAIL);
    }
  }
  return SendMessageWithErrorMask(std::move(message), error_mask, msg_seq);
}

bool RTNLHandler::SendMessageWithErrorMask(std::unique_ptr<RTNLMessage> message,
                                           const ErrorMask& error_mask,
                                           uint32_t* msg_seq) {
  VLOG(5) << __func__ << " sequence " << request_sequence_ << " message type "
          << message->type() << " mode " << message->mode()
          << " with error mask size " << error_mask.size();

  SetErrorMask(request_sequence_, error_mask);
  message->set_seq(request_sequence_);
  ByteString msgdata = message->Encode();

  if (msgdata.GetLength() == 0) {
    return false;
  }

  VLOG(5) << "RTNL sending payload with request sequence " << request_sequence_
          << ", length " << msgdata.GetLength() << ": \"" << msgdata.HexEncode()
          << "\"";

  request_sequence_++;

  if (sockets_->Send(rtnl_socket_, msgdata.GetConstData(), msgdata.GetLength(),
                     0) < 0) {
    PLOG(ERROR) << "RTNL send failed";
    return false;
  }

  if (msg_seq)
    *msg_seq = message->seq();
  StoreRequest(std::move(message));
  return true;
}

void RTNLHandler::OnReadError(const std::string& error_msg) {
  LOG(ERROR) << "RTNL Socket read returns error: " << error_msg;
  ResetSocket();
}

void RTNLHandler::ResetSocket() {
  auto it = response_callbacks_.begin();
  while (it != response_callbacks_.end()) {
    std::move(it->second).Run(EIO);
    response_callbacks_.erase(it);
  }
  Stop();
  Start(netlink_groups_mask_);
}

bool RTNLHandler::IsSequenceInErrorMaskWindow(uint32_t sequence) {
  return (request_sequence_ - sequence) < kErrorWindowSize;
}

void RTNLHandler::SetErrorMask(uint32_t sequence, const ErrorMask& error_mask) {
  if (IsSequenceInErrorMaskWindow(sequence)) {
    error_mask_window_[sequence % kErrorWindowSize] = error_mask;
  }
}

RTNLHandler::ErrorMask RTNLHandler::GetAndClearErrorMask(uint32_t sequence) {
  ErrorMask error_mask;
  if (IsSequenceInErrorMaskWindow(sequence)) {
    error_mask.swap(error_mask_window_[sequence % kErrorWindowSize]);
  }
  return error_mask;
}

void RTNLHandler::StoreRequest(std::unique_ptr<RTNLMessage> request) {
  auto seq = request->seq();

  if (stored_requests_.empty()) {
    oldest_request_sequence_ = seq;
  }

  // Note that this will update an existing stored request of the same sequence
  // number, removing the original RTNLMessage.
  stored_requests_[seq] = std::move(request);
  while (CalculateStoredRequestWindowSize() > kStoredRequestWindowSize) {
    auto old_request = PopStoredRequest(oldest_request_sequence_);
    CHECK(old_request) << "PopStoredRequest returned nullptr but "
                       << "the calculated window size is greater than 0. "
                       << "This is a bug in RTNLHandler.";
    VLOG(2) << "Removing stored RTNLMessage of sequence " << old_request->seq()
            << " (" << old_request->ToString()
            << ") without receiving a response for this sequence";
  }
}

std::unique_ptr<RTNLMessage> RTNLHandler::PopStoredRequest(uint32_t seq) {
  auto seq_request = stored_requests_.find(seq);
  if (seq_request == stored_requests_.end()) {
    return nullptr;
  }

  std::unique_ptr<RTNLMessage> res;
  res.swap(seq_request->second);
  if (seq == oldest_request_sequence_) {
    auto next_oldest_seq_request = std::next(seq_request);
    // Seq overflow could have occurred between the oldest and second oldest
    // stored requests.
    if (next_oldest_seq_request == stored_requests_.end()) {
      next_oldest_seq_request = stored_requests_.begin();
    }
    // Note that this condition means |oldest_request_sequence_| will not be
    // changed when the last stored request is popped. This does not pose any
    // correctness issues.
    if (next_oldest_seq_request != seq_request) {
      oldest_request_sequence_ = next_oldest_seq_request->first;
    }
  }
  stored_requests_.erase(seq_request);
  return res;
}

uint32_t RTNLHandler::CalculateStoredRequestWindowSize() {
  if (stored_requests_.size() <= 1) {
    return stored_requests_.size();
  }

  auto seq_request = stored_requests_.begin();
  if (seq_request->first != oldest_request_sequence_) {
    // If we overflowed, the sequence of the newest request is the
    // greatest sequence less than |oldest_request_sequence_|.
    seq_request = std::prev(stored_requests_.find(oldest_request_sequence_));
  } else {
    seq_request = std::prev(stored_requests_.end());
  }
  return seq_request->first - oldest_request_sequence_ + 1;
}

}  // namespace shill
