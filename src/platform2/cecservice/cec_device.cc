// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cecservice/cec_device.h"

#include <fcntl.h>
#include <linux/cec-funcs.h>
#include <poll.h>
#include <string.h>

#include <deque>
#include <list>
#include <map>
#include <unordered_map>
#include <utility>

#include <base/compiler_specific.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

namespace cecservice {

class StateBase;

class CecDeviceImpl::Impl {
 public:
  // Enum identifiying CEC device states.
  enum class State {
    kStart,  // State when no physical address is known, in this state we
             // are only allowed to send image view on message.
    kNoLogicalAddress,  // The physical address is known but the logical
                        // address is not (yet) configured.
    kProbingTvAddress,  // Obtaining logical address of the TV.
    kReady,     // All is set up, we are free to send any type of messages.
    kDisabled,  // Device is disabled due to previous errors.
  };

  Impl(std::unique_ptr<CecFd> fd, const base::FilePath& device_path);
  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  // Performs object initialization. Returns false if the initialization
  // failed and object is unusable.
  bool Init();

  // Implementation of respective methods from CecDevice:
  void GetTvPowerStatus(CecDevice::GetTvPowerStatusCallback callback);
  void SetStandBy();
  void SetWakeUp();

  // Enters a given state.
  void EnterState(State state);

  // Adds active source message to the queue.
  void EnqueueActiveSourceMessage();

  // Adds Image View On message to the queue.
  void EnqueueImageViewOnMessage();

  // Adds Stand By message to the queue.
  void EnqueueStandByMessage();

  // Enqueues Get Power Status request.
  void EnqueueGetTvPowerStatusMessage(
      CecDevice::GetTvPowerStatusCallback callback);

  // Enqueues a message, returns true if the message was added to the queue.
  bool EnqueueMessage(struct cec_msg msg);

  // Flags that the we didn't manage to find a TV. Will make the object send
  // request to address 0.
  void SetTvProbingCompleted();

  // Attempts to send next queued message, true if successful, false if an
  // unrecoverable error occurred.
  bool SendNextPendingMessage();

  // Sends provided message.
  CecFd::TransmitResult SendMessage(struct cec_msg* msg);

  // Get path to device node (for logging purposes).
  const std::string& GetDevicePathString() const;

  // Processes report physical address message. If that message
  // comes from a TV, updates a TV address.
  void ProcessReportPhysicalAddress(const struct cec_msg& msg);

  // Returns true is we know TV address.
  bool HasTvAddress() const;

  // Sets the current TV address to invalid.
  void ResetTvAddress();

  // Set assumed TV address.
  void SetAssumedTVAddress(uint8_t address);

  // Returns true if there are any queued messages.
  bool MessagesInOutputQueue() const;

  // Returns true if next scheduled message is directed to a TV.
  bool NeedsToQueryTvAddress() const;

  // Returns true if this is a message directed to the TV
  // and should be send to whatever is the current TV's
  // logical address.
  bool IsMessageDirectedToTv(const struct cec_msg& msg) const;

 private:
  // Represents 'get TV power request' that either is to be sent or has been
  // sent and awaits response.
  struct RequestInFlight {
    // The callback to invoke when the request completes.
    CecDevice::GetTvPowerStatusCallback callback;

    // Message id assigned by CEC API or 0 if the request has not been sent yet.
    uint32_t sequence_id;
  };

  // Schedules watching for write readiness on the fd (if demanded by the
  // current state).
  void RequestWriteWatch();

  // Processes messages lost event from CEC. Always returns true.
  bool ProcessMessagesLostEvent(const struct cec_event_lost_msgs& event);

  // Acts on process update event from CEC core. If this method returns false
  // then an unexpected error was encountered and the object should be disabled.
  bool ProcessStateChangeEvent(const struct cec_event_state_change& event);

  // Processes incoming events. If false is returned, then unexpected failure
  // occurred and the object should be disabled.
  bool ProcessEvents();

  // Attempts to read incoming data from the fd. If false is returned, then
  // an unexpected failure occurred and the object should be disabled.
  bool ProcessRead();

  // Called when the fd is ready to be written to. Delegates the write
  // operation to the current state. False is returned in case of unrecoverable
  // error occurred.
  bool ProcessWrite();

  // Processes response received to get power status request. Returns false if
  // the message is not a response to a previously sent request.
  bool ProcessPowerStatusResponse(const struct cec_msg& msg);

  // Handles responses to previously sent requests.
  void ProcessSentMessage(const struct cec_msg& msg);

  // Handles messages directed to us.
  void ProcessIncomingMessage(struct cec_msg* msg);

  // Sets the type of logical address on the adapter (if it has not been yet
  // configured), returns false if the operation failed. Here we are only
  // choosing the type of the address, the kernel will then do the probing and
  // try to allocate first free address of the chosen type. The address type
  // selection is permanent and survives device reconnects (every time EDID
  // shows up, kernel will redo the probing and potentially can end up selecting
  // different logical address). Since this selection is permanent it is
  // sufficient to do it only once when we create the device.
  bool SetLogicalAddress();

  // Handles fd event.
  void OnFdEvent(CecFd::EventType event);

  // Immediately responds to all currently ongoing queries.
  void RespondToAllQueries(TvPowerStatus response);

  // Disables device.
  void DisableDevice();

  // Instances of all states.
  std::unordered_map<State, std::unique_ptr<StateBase>> states_;

  // Current state.
  StateBase* state_;

  // The descriptor associated with the device.
  std::unique_ptr<CecFd> fd_;

  // Path to the device, for logging purposes only.
  const base::FilePath device_path_;

  // Current physical address.
  uint16_t physical_address_ = CEC_PHYS_ADDR_INVALID;

  // Current logical address.
  uint8_t logical_address_ = CEC_LOG_ADDR_INVALID;

  // TV logical address.
  uint8_t tv_logical_address_ = CEC_LOG_ADDR_INVALID;

  // In case we don't get a proper response from any tried TV addresses
  // (0 or 14), we will fall back on that address.
  uint8_t assummed_tv_logical_address_ = CEC_LOG_ADDR_TV;

  // Queue of messages we are about to send.
  std::deque<struct cec_msg> message_queue_;

  // Queue of requests that are in flight.
  std::list<RequestInFlight> requests_;

  // Flag indicating if we believe we are the active source.
  bool active_source_ = false;

  // Flag saying if we should probe the TV address if it is unknown.
  bool probe_tv_address_if_unknown_ = true;

  base::WeakPtrFactory<Impl> weak_factory_{this};
};

// Maximum size of a cec device's queue with outgoing messages, roughly
// 10 secs of continus flow of messages.
//
// Extern to make it avaiable to UTs.
extern const size_t kCecDeviceMaxTxQueueSize = 250;

namespace {
struct cec_msg CreateMessage(uint8_t destination_address) {
  struct cec_msg message;
  cec_msg_init(&message, CEC_LOG_ADDR_UNREGISTERED, destination_address);
  return message;
}

void SetMessageSourceAddress(uint8_t source_address, struct cec_msg* msg) {
  if (source_address == CEC_LOG_ADDR_INVALID) {
    source_address = CEC_LOG_ADDR_UNREGISTERED;
  }
  msg->msg[0] = (source_address << 4) | cec_msg_destination(msg);
}

void SetMessageDestinationAddress(uint8_t dest_address, struct cec_msg* msg) {
  msg->msg[0] = (cec_msg_initiator(msg) << 4) | dest_address;
}

TvPowerStatus GetPowerStatus(const struct cec_msg& msg) {
  uint8_t power_status;
  cec_ops_report_power_status(&msg, &power_status);
  switch (power_status) {
    case CEC_OP_POWER_STATUS_ON:
      return kTvPowerStatusOn;
    case CEC_OP_POWER_STATUS_STANDBY:
      return kTvPowerStatusStandBy;
    case CEC_OP_POWER_STATUS_TO_ON:
      return kTvPowerStatusToOn;
    case CEC_OP_POWER_STATUS_TO_STANDBY:
      return kTvPowerStatusToStandBy;
    default:
      return kTvPowerStatusUnknown;
  }
}

}  // namespace

// Bases class for all states the CecDevice object can be in.
class StateBase {
 public:
  // Assigned the device imp object to object.
  void Init(CecDeviceImpl::Impl* device);
  // Called when the state is being entered.
  virtual void Enter();
  // Called when 'get TV power status' request is made by a user.
  virtual void GetTvPowerStatus(
      CecDevice::GetTvPowerStatusCallback callback) = 0;
  // Called to learn if the state wants to write sth out on the fd.
  virtual bool NeedsWrite() = 0;
  // Called when Stand By request is made by a user.
  virtual void SetStandBy() = 0;
  // Called when Stand By request is made by a user.
  virtual void SetWakeUp() = 0;
  // Called when a message is sent (or response received),
  // should return true if the message was handled by the state and false
  // otherwise.
  virtual bool ProcessResponse(const cec_msg& msg);
  // Called whenever fd is available for writing.
  virtual bool ProcessWrite();
  // Called whenever an event saying that the kernel is dropping messages is
  // recevied.
  virtual void ProcessMessagesLostEvent();

  StateBase();

  StateBase(const StateBase&) = delete;
  StateBase& operator=(const StateBase&) = delete;

  virtual ~StateBase();

 protected:
  CecDeviceImpl::Impl* device_;
};

// The state the object transitions to whenever an unrecoverable
// error is encountered. We do nothing in this state.
class DisabledState : public StateBase {
 public:
  // StateBase overrides:
  void GetTvPowerStatus(CecDevice::GetTvPowerStatusCallback callback) override;
  bool NeedsWrite() override;
  void SetStandBy() override;
  void SetWakeUp() override;
  bool ProcessWrite() override;
};

// The state when we don't have a physical address. The only action performed
// by this state is an attempt to send 'image view on' request when requested
// to set wake up.
class StartState : public StateBase {
 public:
  // StateBase overrides:
  void GetTvPowerStatus(CecDevice::GetTvPowerStatusCallback callback) override;
  bool NeedsWrite() override;
  void SetStandBy() override;
  void SetWakeUp() override;
};

// The state where we don't have a logical address yet. All requests received
// in this state are queued up.
class NoLogicalAddressState : public StateBase {
 public:
  // StateBase overrides:
  void GetTvPowerStatus(CecDevice::GetTvPowerStatusCallback callback) override;
  bool NeedsWrite() override;
  void SetStandBy() override;
  void SetWakeUp() override;
};

// The state where we probe TV's address. All requests are being queued up.
class ProbingTvAddressState : public StateBase {
 public:
  // StateBase overrides:
  void Enter() override;
  void GetTvPowerStatus(CecDevice::GetTvPowerStatusCallback callback) override;
  bool NeedsWrite() override;
  void SetStandBy() override;
  void SetWakeUp() override;
  bool ProcessResponse(const cec_msg& msg) override;
  bool ProcessWrite() override;
  void ProcessMessagesLostEvent() override;

 private:
  // Completes probing, setting appropriate assumed address (if needed).
  void CompleteProbing();

  // Represent state TV address querying op.
  enum class SubState {
    kStart,              // Inital state.
    kProbing0,           // The probe for address 0 was sent.
    kProbing0Completed,  // The probe for address 0 is completed.
    kProbing14,          // The probe for address 14 was sent.
  } subState_ = SubState::kStart;

  // Sequence id of the ongoing transaction.
  uint32_t sequence_id_;

  // In case a device has not responded but still ACKd our request, use that
  // info to make a guess.
  bool address_0_acked_ = false;
  bool address_14_acked_ = false;
};

class ReadyState : public StateBase {
 public:
  // StateBase overrides:
  void GetTvPowerStatus(CecDevice::GetTvPowerStatusCallback callback) override;
  bool NeedsWrite() override;
  void SetStandBy() override;
  void SetWakeUp() override;
  bool ProcessResponse(const cec_msg& msg) override;
  bool ProcessWrite() override;
};

void CecDeviceImpl::Impl::EnqueueActiveSourceMessage() {
  struct cec_msg msg = CreateMessage(CEC_LOG_ADDR_BROADCAST);
  cec_msg_active_source(&msg, physical_address_);
  EnqueueMessage(msg);
}

void CecDeviceImpl::Impl::EnqueueImageViewOnMessage() {
  struct cec_msg msg = CreateMessage(CEC_LOG_ADDR_TV);
  cec_msg_image_view_on(&msg);
  EnqueueMessage(msg);
}

void CecDeviceImpl::Impl::EnqueueStandByMessage() {
  struct cec_msg msg = CreateMessage(CEC_LOG_ADDR_TV);
  cec_msg_standby(&msg);
  EnqueueMessage(msg);
}

void CecDeviceImpl::Impl::EnqueueGetTvPowerStatusMessage(
    CecDevice::GetTvPowerStatusCallback callback) {
  struct cec_msg msg = CreateMessage(CEC_LOG_ADDR_TV);
  cec_msg_give_device_power_status(&msg, 1);
  if (EnqueueMessage(msg)) {
    requests_.push_back({std::move(callback), 0});
  } else {
    std::move(callback).Run(kTvPowerStatusError);
  }
}

bool CecDeviceImpl::Impl::EnqueueMessage(struct cec_msg msg) {
  if (message_queue_.size() < kCecDeviceMaxTxQueueSize) {
    message_queue_.push_back(msg);
    return true;
  } else {
    LOG(ERROR) << base::StringPrintf(
        "Output queue size too large, message 0x%x not enqueued",
        cec_msg_opcode(&msg));
    return false;
  }
}

void CecDeviceImpl::Impl::SetTvProbingCompleted() {
  probe_tv_address_if_unknown_ = false;
}

CecDeviceImpl::CecDeviceImpl(std::unique_ptr<CecFd> fd,
                             const base::FilePath& device_path)
    : impl_(std::make_unique<Impl>(std::move(fd), device_path)) {}

CecDeviceImpl::~CecDeviceImpl() = default;

bool CecDeviceImpl::Init() {
  return impl_->Init();
}

void CecDeviceImpl::GetTvPowerStatus(
    CecDevice::GetTvPowerStatusCallback callback) {
  impl_->GetTvPowerStatus(std::move(callback));
}

void CecDeviceImpl::SetStandBy() {
  impl_->SetStandBy();
}

void CecDeviceImpl::SetWakeUp() {
  impl_->SetWakeUp();
}

CecDeviceImpl::Impl::Impl(std::unique_ptr<CecFd> fd,
                          const base::FilePath& device_path)
    : fd_(std::move(fd)), device_path_(device_path) {
  states_[State::kStart] = std::make_unique<StartState>();
  states_[State::kNoLogicalAddress] = std::make_unique<NoLogicalAddressState>();
  states_[State::kProbingTvAddress] = std::make_unique<ProbingTvAddressState>();
  states_[State::kReady] = std::make_unique<ReadyState>();
  states_[State::kDisabled] = std::make_unique<DisabledState>();

  for (auto& kv : states_) {
    kv.second->Init(this);
  }

  EnterState(State::kStart);
}

bool CecDeviceImpl::Impl::Init() {
  if (!fd_->SetEventCallback(base::BindRepeating(
          &CecDeviceImpl::Impl::OnFdEvent, weak_factory_.GetWeakPtr()))) {
    DisableDevice();
    return false;
  }

  if (!SetLogicalAddress()) {
    DisableDevice();
    return false;
  }

  return true;
}

void CecDeviceImpl::Impl::GetTvPowerStatus(
    CecDevice::GetTvPowerStatusCallback callback) {
  probe_tv_address_if_unknown_ = true;

  state_->GetTvPowerStatus(std::move(callback));
  RequestWriteWatch();
}

void CecDeviceImpl::Impl::SetStandBy() {
  probe_tv_address_if_unknown_ = true;

  active_source_ = false;
  state_->SetStandBy();
  RequestWriteWatch();
}

void CecDeviceImpl::Impl::SetWakeUp() {
  probe_tv_address_if_unknown_ = true;

  active_source_ = true;
  state_->SetWakeUp();
  RequestWriteWatch();
}

void CecDeviceImpl::Impl::RequestWriteWatch() {
  if (!state_->NeedsWrite())
    return;

  if (!fd_->WriteWatch()) {
    LOG(ERROR) << device_path_.value()
               << ": failed to request write watch on fd, disabling device";
    DisableDevice();
  }
}

bool CecDeviceImpl::Impl::ProcessMessagesLostEvent(
    const struct cec_event_lost_msgs& event) {
  LOG(WARNING) << device_path_.value() << ": received event lost message, lost "
               << event.lost_msgs << " messages";

  state_->ProcessMessagesLostEvent();

  // Respond to all ongoing power status queries with an error.
  std::list<RequestInFlight> ongoing;
  std::list<RequestInFlight>::iterator i = requests_.begin();
  while (i != requests_.end()) {
    if (i->sequence_id != 0) {
      ongoing.push_back(std::move(*i));
      i = requests_.erase(i);
    } else {
      i++;
    }
  }
  for (auto& request : ongoing) {
    std::move(request.callback).Run(kTvPowerStatusError);
  }

  return true;
}

bool CecDeviceImpl::Impl::ProcessStateChangeEvent(
    const struct cec_event_state_change& event) {
  physical_address_ = event.phys_addr;

  logical_address_ = CEC_LOG_ADDR_INVALID;
  if (event.log_addr_mask) {
    logical_address_ = ffs(event.log_addr_mask) - 1;
  }

  LOG(INFO) << base::StringPrintf(
      "%s: state update, physical address: 0x%x logical address: 0x%x",
      device_path_.value().c_str(), static_cast<uint32_t>(physical_address_),
      static_cast<uint32_t>(logical_address_));

  if (physical_address_ == CEC_PHYS_ADDR_INVALID) {
    message_queue_.clear();

    tv_logical_address_ = CEC_LOG_ADDR_INVALID;
    assummed_tv_logical_address_ = CEC_LOG_ADDR_TV;

    RespondToAllQueries(kTvPowerStatusAdapterNotConfigured);

    EnterState(State::kStart);
  } else if (logical_address_ == CEC_LOG_ADDR_INVALID) {
    EnterState(State::kNoLogicalAddress);
  } else {
    EnterState(State::kReady);
  }

  return true;
}

bool CecDeviceImpl::Impl::ProcessEvents() {
  struct cec_event event;

  if (!fd_->ReceiveEvent(&event)) {
    return false;
  }

  switch (event.event) {
    case CEC_EVENT_LOST_MSGS:
      return ProcessMessagesLostEvent(event.lost_msgs);
      break;
    case CEC_EVENT_STATE_CHANGE:
      return ProcessStateChangeEvent(event.state_change);
    default:
      LOG(WARNING) << base::StringPrintf("%s: unexpected cec event type: 0x%x",
                                         device_path_.value().c_str(),
                                         event.event);
      return true;
  }
}

bool CecDeviceImpl::Impl::ProcessRead() {
  struct cec_msg msg;
  if (!fd_->ReceiveMessage(&msg)) {
    return false;
  }

  if (msg.sequence) {
    ProcessSentMessage(msg);
  } else {
    ProcessIncomingMessage(&msg);
  }
  return true;
}

bool CecDeviceImpl::Impl::MessagesInOutputQueue() const {
  return !message_queue_.empty();
}

bool CecDeviceImpl::Impl::SendNextPendingMessage() {
  CHECK(!message_queue_.empty());

  struct cec_msg message = message_queue_.front();
  if (IsMessageDirectedToTv(message)) {
    uint8_t address = tv_logical_address_;
    if (address == CEC_LOG_ADDR_INVALID) {
      address = assummed_tv_logical_address_;
      VLOG(1) << base::StringPrintf(
          "%s: Unknown TV logical address, falling back to: 0x%x",
          device_path_.value().c_str(), static_cast<uint32_t>(address));
    }

    SetMessageDestinationAddress(address, &message);
  }

  CecFd::TransmitResult ret = SendMessage(&message);
  if (ret == CecFd::TransmitResult::kBusy) {
    return true;
  }

  if (cec_msg_opcode(&message) == CEC_MSG_GIVE_DEVICE_POWER_STATUS) {
    auto iterator = std::find_if(requests_.begin(), requests_.end(),
                                 [](const RequestInFlight& request) {
                                   return request.sequence_id == 0;
                                 });
    CHECK(iterator != requests_.end());

    if (ret == CecFd::TransmitResult::kOk) {
      iterator->sequence_id = message.sequence;
    } else {
      std::move(iterator->callback).Run(kTvPowerStatusError);
      requests_.erase(iterator);
    }
  }

  message_queue_.pop_front();

  return ret != CecFd::TransmitResult::kError;
}

bool CecDeviceImpl::Impl::ProcessPowerStatusResponse(
    const struct cec_msg& msg) {
  auto iterator = std::find_if(requests_.begin(), requests_.end(),
                               [&](const RequestInFlight& request) {
                                 return request.sequence_id == msg.sequence;
                               });
  if (iterator == requests_.end()) {
    return false;
  }

  TvPowerStatus status;
  if (cec_msg_status_is_ok(&msg) &&
      cec_msg_opcode(&msg) == CEC_MSG_REPORT_POWER_STATUS) {
    status = GetPowerStatus(msg);
  } else {
    LOG(INFO) << base::StringPrintf(
        "%s: power status query failed, rx_status: 0x%x tx_status: 0x%x",
        device_path_.value().c_str(), static_cast<uint32_t>(msg.rx_status),
        static_cast<uint32_t>(msg.tx_status));
    if (msg.tx_status & CEC_TX_STATUS_NACK) {
      status = kTvPowerStatusNoTv;
    } else {
      status = kTvPowerStatusError;
    }
  }

  std::move(iterator->callback).Run(status);
  requests_.erase(iterator);

  return true;
}

void CecDeviceImpl::Impl::ProcessReportPhysicalAddress(
    const struct cec_msg& msg) {
  uint16_t phys_addr;
  uint8_t prim_devtype;
  cec_ops_report_physical_addr(&msg, &phys_addr, &prim_devtype);
  if (phys_addr != 0 || prim_devtype != CEC_OP_PRIM_DEVTYPE_TV) {
    return;
  }

  tv_logical_address_ = cec_msg_initiator(&msg);
  VLOG(1) << device_path_.value()
          << ": TV's logical address: " << uint32_t(tv_logical_address_);
}

bool CecDeviceImpl::Impl::HasTvAddress() const {
  return tv_logical_address_ != CEC_LOG_ADDR_INVALID;
}

void CecDeviceImpl::Impl::ResetTvAddress() {
  tv_logical_address_ = CEC_LOG_ADDR_INVALID;
}

void CecDeviceImpl::Impl::SetAssumedTVAddress(uint8_t address) {
  assummed_tv_logical_address_ = address;
}

void CecDeviceImpl::Impl::ProcessSentMessage(const struct cec_msg& msg) {
  if (state_->ProcessResponse(msg)) {
    return;
  }

  if (ProcessPowerStatusResponse(msg)) {
    return;
  }

  if (cec_msg_status_is_ok(&msg)) {
    VLOG(1) << base::StringPrintf("%s: successfully sent message, opcode: 0x%x",
                                  device_path_.value().c_str(),
                                  cec_msg_opcode(&msg));
  } else {
    VLOG(1) << base::StringPrintf(
        "%s: failed to send message, opcode: 0x%x tx_status: 0x%x",
        device_path_.value().c_str(), cec_msg_opcode(&msg),
        static_cast<uint32_t>(msg.tx_status));
  }
}

void CecDeviceImpl::Impl::ProcessIncomingMessage(struct cec_msg* msg) {
  struct cec_msg reply;

  VLOG(1) << base::StringPrintf(
      "%s: received message, opcode:0x%x from:0x%x to:0x%x",
      device_path_.value().c_str(), cec_msg_opcode(msg),
      static_cast<unsigned>(cec_msg_initiator(msg)),
      static_cast<unsigned>(cec_msg_destination(msg)));

  switch (cec_msg_opcode(msg)) {
    case CEC_MSG_REQUEST_ACTIVE_SOURCE:
      if (active_source_) {
        cec_msg_init(&reply, logical_address_, CEC_LOG_ADDR_BROADCAST);
        cec_msg_active_source(&reply, physical_address_);
        EnqueueMessage(std::move(reply));
      }
      break;
    case CEC_MSG_ACTIVE_SOURCE:
      if (active_source_) {
        VLOG(1) << device_path_.value() << ": we ceased to be active source";
        active_source_ = false;
      }
      break;
    case CEC_MSG_GIVE_DEVICE_POWER_STATUS:
      cec_msg_init(&reply, logical_address_, cec_msg_initiator(msg));
      cec_msg_report_power_status(&reply, CEC_OP_POWER_STATUS_ON);
      EnqueueMessage(reply);
      break;
    case CEC_MSG_REPORT_PHYSICAL_ADDR:
      ProcessReportPhysicalAddress(*msg);
      break;
    case CEC_MSG_STANDBY:
      // Ignore standby.
      break;
    case CEC_MSG_FEATURE_ABORT:
      // Ignore.
      break;
    case CEC_MSG_REPORT_POWER_STATUS:
      // This is most likely a delayed response to our power status
      // request. Ingore instead of rejecting.
      break;
    default:
      if (!cec_msg_is_broadcast(msg) &&
          cec_msg_initiator(msg) != CEC_LOG_ADDR_UNREGISTERED) {
        cec_msg_reply_feature_abort(msg, CEC_OP_ABORT_UNRECOGNIZED_OP);
        EnqueueMessage(std::move(*msg));
      }
      break;
  }
}

CecFd::TransmitResult CecDeviceImpl::Impl::SendMessage(struct cec_msg* msg) {
  SetMessageSourceAddress(logical_address_, msg);

  VLOG(1) << base::StringPrintf(
      "%s: transmitting message, opcode:0x%x to:0x%x",
      device_path_.value().c_str(), cec_msg_opcode(msg),
      static_cast<unsigned>(cec_msg_destination(msg)));

  return fd_->TransmitMessage(msg);
}

const std::string& CecDeviceImpl::Impl::GetDevicePathString() const {
  return device_path_.value();
}

bool CecDeviceImpl::Impl::SetLogicalAddress() {
  struct cec_log_addrs addresses = {};

  if (!fd_->GetLogicalAddresses(&addresses)) {
    return false;
  }

  // The address has already been set, so we will reuse it.
  if (addresses.num_log_addrs) {
    return true;
  }

  memset(&addresses, 0, sizeof(addresses));
  addresses.cec_version = CEC_OP_CEC_VERSION_1_4;
  addresses.vendor_id = CEC_VENDOR_ID_NONE;
  base::strlcpy(addresses.osd_name, CECSERVICE_OSD_NAME,
                sizeof(addresses.osd_name));
  addresses.num_log_addrs = 1;
  addresses.log_addr_type[0] = CEC_LOG_ADDR_TYPE_PLAYBACK;
  addresses.primary_device_type[0] = CEC_OP_PRIM_DEVTYPE_PLAYBACK;
  addresses.all_device_types[0] = CEC_OP_ALL_DEVTYPE_PLAYBACK;
  addresses.flags = CEC_LOG_ADDRS_FL_ALLOW_UNREG_FALLBACK;

  return fd_->SetLogicalAddresses(&addresses);
}

void CecDeviceImpl::Impl::OnFdEvent(CecFd::EventType event) {
  bool ret;
  switch (event) {
    case CecFd::EventType::kPriorityRead:
      ret = ProcessEvents();
      break;
    case CecFd::EventType::kRead:
      ret = ProcessRead();
      break;
    case CecFd::EventType::kWrite:
      ret = state_->ProcessWrite();
      break;
  }

  if (!ret) {
    DisableDevice();
    return;
  }

  RequestWriteWatch();
}

bool CecDeviceImpl::Impl::IsMessageDirectedToTv(
    const struct cec_msg& msg) const {
  switch (cec_msg_opcode(&msg)) {
    case CEC_MSG_GIVE_DEVICE_POWER_STATUS:
    case CEC_MSG_STANDBY:
    case CEC_MSG_IMAGE_VIEW_ON:
      return true;
    default:
      return false;
  }
}

bool CecDeviceImpl::Impl::NeedsToQueryTvAddress() const {
  if (HasTvAddress()) {
    return false;
  }

  if (!probe_tv_address_if_unknown_) {
    return false;
  }

  CHECK(!message_queue_.empty());
  return IsMessageDirectedToTv(message_queue_.front());
}

void CecDeviceImpl::Impl::RespondToAllQueries(TvPowerStatus response) {
  std::list<RequestInFlight> requests;
  requests.swap(requests_);

  for (auto& request : requests) {
    std::move(request.callback).Run(response);
  }
}

void CecDeviceImpl::Impl::EnterState(State state) {
  StateBase* new_state = states_[state].get();
  if (new_state == state_) {
    return;
  }

  state_ = new_state;
  state_->Enter();
}

void CecDeviceImpl::Impl::DisableDevice() {
  fd_.reset();
  message_queue_.clear();
  RespondToAllQueries(kTvPowerStatusError);
  EnterState(State::kDisabled);
}

void StateBase::Enter() {}

void StateBase::Init(CecDeviceImpl::Impl* device) {
  device_ = device;
}

bool StateBase::ProcessResponse(const cec_msg& msg) {
  return false;
}

bool StateBase::ProcessWrite() {
  return true;
}

void StateBase::ProcessMessagesLostEvent() {}

StateBase::StateBase() = default;

StateBase::~StateBase() = default;

void DisabledState::GetTvPowerStatus(
    CecDevice::GetTvPowerStatusCallback callback) {
  LOG(WARNING) << device_->GetDevicePathString()
               << ": device is disabled due to errors, unable to query";
  std::move(callback).Run(kTvPowerStatusError);
}

bool DisabledState::NeedsWrite() {
  return false;
}

void DisabledState::SetStandBy() {
  LOG(WARNING) << device_->GetDevicePathString()
               << ": device is disabled due to previous errors, ignoring "
                  "standby request";
}

void DisabledState::SetWakeUp() {
  LOG(WARNING) << device_->GetDevicePathString()
               << ": device in disabled due to previous errors, ignoring wake "
                  "up request";
}

bool DisabledState::ProcessWrite() {
  return false;
}

void StartState::GetTvPowerStatus(
    CecDevice::GetTvPowerStatusCallback callback) {
  VLOG(1) << device_->GetDevicePathString()
          << ": not configured, not querying TV power state";
  std::move(callback).Run(kTvPowerStatusAdapterNotConfigured);
}

bool StartState::NeedsWrite() {
  return false;
}

void StartState::SetStandBy() {
  VLOG(1) << device_->GetDevicePathString()
          << ": ignoring standby request, we are not connected";
}

void StartState::SetWakeUp() {
  struct cec_msg msg = CreateMessage(CEC_LOG_ADDR_TV);
  cec_msg_image_view_on(&msg);
  if (device_->SendMessage(&msg) != CecFd::TransmitResult::kOk) {
    VLOG(1) << device_->GetDevicePathString()
            << ": failed to send image view on message while in start "
               "state, we are not able to wake up this TV";
  } else {
    device_->EnqueueActiveSourceMessage();
  }
}

void NoLogicalAddressState::GetTvPowerStatus(
    CecDevice::GetTvPowerStatusCallback callback) {
  device_->EnqueueGetTvPowerStatusMessage(std::move(callback));
}

bool NoLogicalAddressState::NeedsWrite() {
  return false;
}

void NoLogicalAddressState::SetStandBy() {
  device_->EnqueueStandByMessage();
}

void NoLogicalAddressState::SetWakeUp() {
  device_->EnqueueImageViewOnMessage();
  device_->EnqueueActiveSourceMessage();
}

void ProbingTvAddressState::Enter() {
  subState_ = SubState::kStart;
  address_0_acked_ = false;
  address_14_acked_ = false;
}

bool ProbingTvAddressState::ProcessResponse(const cec_msg& msg) {
  if (msg.sequence != sequence_id_)
    return false;

  if (msg.tx_status == CEC_TX_STATUS_OK) {
    switch (subState_) {
      case SubState::kProbing0:
        address_0_acked_ = true;
        break;
      case SubState::kProbing14:
        address_14_acked_ = true;
        break;
      default:
        break;
    }
  }

  if (cec_msg_status_is_ok(&msg) &&
      cec_msg_opcode(&msg) == CEC_MSG_REPORT_PHYSICAL_ADDR) {
    device_->ProcessReportPhysicalAddress(msg);
  } else {
    VLOG(1) << base::StringPrintf(
        "%s: give physical address status query failed, rx_status: 0x%x "
        "tx_status: 0x%x",
        device_->GetDevicePathString().c_str(),
        static_cast<uint32_t>(msg.rx_status),
        static_cast<uint32_t>(msg.tx_status));
  }

  if (device_->HasTvAddress()) {
    device_->EnterState(CecDeviceImpl::Impl::State::kReady);
    return true;
  }

  switch (subState_) {
    case SubState::kStart:
    case SubState::kProbing0Completed:
      break;
    case SubState::kProbing0:
      subState_ = SubState::kProbing0Completed;
      break;
    case SubState::kProbing14:
      CompleteProbing();
      break;
  }

  return true;
}

bool ProbingTvAddressState::ProcessWrite() {
  struct cec_msg message;
  switch (subState_) {
    case SubState::kStart:
      cec_msg_init(&message, 0, CEC_LOG_ADDR_TV);
      cec_msg_give_physical_addr(&message, 1);
      break;
    case SubState::kProbing0Completed:
      cec_msg_init(&message, 0, CEC_LOG_ADDR_SPECIFIC);
      cec_msg_give_physical_addr(&message, 1);
      break;
    default:
      return true;
  }

  CecFd::TransmitResult ret = device_->SendMessage(&message);
  switch (ret) {
    case CecFd::TransmitResult::kBusy:
      return true;
    case CecFd::TransmitResult::kError:
      return false;
    case CecFd::TransmitResult::kOk:
      sequence_id_ = message.sequence;
      subState_ = (subState_ == SubState::kStart) ? SubState::kProbing0
                                                  : SubState::kProbing14;
      return true;
    default:
      if (subState_ == SubState::kStart) {
        subState_ = SubState::kProbing0Completed;
      } else {
        CompleteProbing();
      }
      return true;
  }
}

void ProbingTvAddressState::CompleteProbing() {
  if (!device_->HasTvAddress()) {
    if (address_0_acked_) {
      device_->SetAssumedTVAddress(CEC_LOG_ADDR_TV);
    } else if (address_14_acked_) {
      device_->SetAssumedTVAddress(CEC_LOG_ADDR_SPECIFIC);
    } else {
      VLOG(1) << device_->GetDevicePathString() << ": failed to find a TV";
    }
  }
  device_->SetTvProbingCompleted();
  device_->EnterState(CecDeviceImpl::Impl::State::kReady);
}

bool ProbingTvAddressState::NeedsWrite() {
  switch (subState_) {
    case SubState::kStart:
    case SubState::kProbing0Completed:
      return true;
    default:
      return false;
  }
}

void ProbingTvAddressState::ProcessMessagesLostEvent() {
  LOG(WARNING) << device_->GetDevicePathString()
               << ": losing messages, giving up on probing TV address";
  device_->SetTvProbingCompleted();
  device_->EnterState(CecDeviceImpl::Impl::State::kReady);
}

void ProbingTvAddressState::GetTvPowerStatus(
    CecDevice::GetTvPowerStatusCallback callback) {
  device_->EnqueueGetTvPowerStatusMessage(std::move(callback));
}

void ProbingTvAddressState::SetStandBy() {
  device_->EnqueueStandByMessage();
}

void ProbingTvAddressState::SetWakeUp() {
  device_->EnqueueImageViewOnMessage();
  device_->EnqueueActiveSourceMessage();
}

void ReadyState::GetTvPowerStatus(
    CecDevice::GetTvPowerStatusCallback callback) {
  device_->EnqueueGetTvPowerStatusMessage(std::move(callback));
}

bool ReadyState::NeedsWrite() {
  return device_->MessagesInOutputQueue();
}

void ReadyState::SetStandBy() {
  device_->EnqueueStandByMessage();
}

void ReadyState::SetWakeUp() {
  device_->EnqueueImageViewOnMessage();
  device_->EnqueueActiveSourceMessage();
}

bool ReadyState::ProcessResponse(const cec_msg& msg) {
  if ((msg.tx_status & CEC_TX_STATUS_NACK) &&
      device_->IsMessageDirectedToTv(msg) && device_->HasTvAddress()) {
    device_->ResetTvAddress();
    LOG(INFO) << device_->GetDevicePathString()
              << ": message directed to TV not acked. "
              << "Setting TV address to unknown";
  }

  return false;
}

bool ReadyState::ProcessWrite() {
  if (!device_->MessagesInOutputQueue()) {
    return true;
  }

  if (device_->NeedsToQueryTvAddress()) {
    device_->EnterState(CecDeviceImpl::Impl::State::kProbingTvAddress);
    return true;
  }

  return device_->SendNextPendingMessage();
}

CecDeviceFactoryImpl::CecDeviceFactoryImpl(const CecFdOpener* cec_fd_opener)
    : cec_fd_opener_(cec_fd_opener) {}

CecDeviceFactoryImpl::~CecDeviceFactoryImpl() = default;

std::unique_ptr<CecDevice> CecDeviceFactoryImpl::Create(
    const base::FilePath& path) const {
  std::unique_ptr<CecFd> fd = cec_fd_opener_->Open(path, O_NONBLOCK);
  if (!fd) {
    return nullptr;
  }

  struct cec_caps caps;
  if (!fd->GetCapabilities(&caps)) {
    return nullptr;
  }

  LOG(INFO) << base::StringPrintf(
      "CEC adapter: %s, driver:%s name:%s caps:0x%x", path.value().c_str(),
      caps.driver, caps.name, caps.capabilities);

  // At the moment the only adapters supported are the ones that:
  // - handle configuration of physical address on their own (i.e. don't have
  // CEC_CAP_PHYS_ADDR flag set)
  // - allow us to configure logical addrresses (i.e. have CEC_CAP_LOG_ADDRS
  // set)
  if ((caps.capabilities & CEC_CAP_PHYS_ADDR) ||
      !(caps.capabilities & CEC_CAP_LOG_ADDRS)) {
    LOG(WARNING) << path.value()
                 << ": device does not have required capabilities to function "
                    "with this service";
    return nullptr;
  }

  uint32_t mode = CEC_MODE_EXCL_INITIATOR | CEC_MODE_EXCL_FOLLOWER;
  if (!fd->SetMode(mode)) {
    LOG(ERROR) << path.value()
               << ": failed to set an exclusive initiator mode on the device";
    return nullptr;
  }

  auto device = std::make_unique<CecDeviceImpl>(std::move(fd), path);
  if (!device->Init()) {
    return nullptr;
  }

  return device;
}

}  // namespace cecservice
