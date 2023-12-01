// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/sys_byteorder.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <trunks/cr50_headers/u2f.h>

#include "u2fd/client/u2f_apdu.h"
#include "u2fd/client/u2f_corp_firmware_version.h"
#include "u2fd/client/user_state.h"
#include "u2fd/client/util.h"
#include "u2fd/u2f_corp_processor_interface.h"
#include "u2fd/u2fhid.h"

namespace {

// Size of the payload for an INIT U2F HID report.
constexpr size_t kInitReportPayloadSize = 57;
// Size of the payload for a Continuation U2F HID report.
constexpr size_t kContReportPayloadSize = 59;

constexpr uint8_t kInterfaceVersion = 2;

constexpr base::TimeDelta kU2fHidTimeout = base::Milliseconds(500);

// Maximum duration one can keep the channel lock as specified by the U2FHID
// specification
constexpr int kMaxLockDurationSeconds = 10;

// HID report descriptor for U2F interface.
constexpr uint8_t kU2fReportDesc[] = {
    0x06, 0xD0, 0xF1, /* Usage Page (FIDO Alliance), FIDO_USAGE_PAGE */
    0x09, 0x01,       /* Usage (U2F HID Auth. Device) FIDO_USAGE_U2FHID */
    0xA1, 0x01,       /* Collection (Application), HID_APPLICATION */
    0x09, 0x20,       /*  Usage (Input Report Data), FIDO_USAGE_DATA_IN */
    0x15, 0x00,       /*  Logical Minimum (0) */
    0x26, 0xFF, 0x00, /*  Logical Maximum (255) */
    0x75, 0x08,       /*  Report Size (8) */
    0x95, 0x40,       /*  Report Count (64), HID_INPUT_REPORT_BYTES */
    0x81, 0x02,       /*  Input (Data, Var, Abs), Usage */
    0x09, 0x21,       /*  Usage (Output Report Data), FIDO_USAGE_DATA_OUT */
    0x15, 0x00,       /*  Logical Minimum (0) */
    0x26, 0xFF, 0x00, /*  Logical Maximum (255) */
    0x75, 0x08,       /*  Report Size (8) */
    0x95, 0x40,       /*  Report Count (64), HID_OUTPUT_REPORT_BYTES */
    0x91, 0x02,       /*  Output (Data, Var, Abs), Usage */
    0xC0              /* End Collection */
};

}  // namespace

namespace u2f {

class U2fHid::HidPacket {
 public:
  explicit HidPacket(const std::string& report);

  bool IsValidFrame() const { return valid_; }

  bool IsInitFrame() const { return (tcs_ & kFrameTypeMask) == kFrameTypeInit; }

  uint32_t ChannelId() const { return cid_; }

  U2fHid::U2fHidCommand Command() const {
    return static_cast<U2fHidCommand>(tcs_ & ~kFrameTypeMask);
  }

  uint8_t SeqNumber() const { return tcs_ & ~kFrameTypeMask; }

  int PayloadIndex() const { return IsInitFrame() ? 8 : 6; }

  size_t MessagePayloadSize() const { return bcnt_; }

 private:
  bool valid_;
  uint32_t cid_;   // Channel Identifier
  uint8_t tcs_;    // type and command or sequence number
  uint16_t bcnt_;  // payload length as defined by U2fHID specification
};

U2fHid::HidPacket::HidPacket(const std::string& report)
    : valid_(false), cid_(0), tcs_(0), bcnt_(0) {
  // the report is prefixed by the report ID (we skip it below).
  if (report.size() != kU2fReportSize + 1) /* Invalid U2FHID report */
    return;

  // U2FHID frame bytes parsing.
  // As defined in the "FIDO U2F HID Protocol Specification":
  // An initialization packet is defined as
  //
  // Offset Length  Mnemonic  Description
  // 0      4       CID       Channel identifier
  // 4      1       CMD       Command identifier (bit 7 always set)
  // 5      1       BCNTH     High part of payload length
  // 6      1       BCNTL     Low part of payload length
  // 7      (s - 7) DATA      Payload data (s is the fixed packet size)
  // The command byte has always the highest bit set to distinguish it
  // from a continuation packet, which is described below.
  //
  // A continuation packet is defined as
  //
  // Offset Length  Mnemonic  Description
  // 0      4       CID       Channel identifier
  // 4      1       SEQ       Packet sequence 0x00..0x7f (bit 7 always cleared)
  // 5      (s - 5) DATA      Payload data (s is the fixed packet size)
  // With this approach, a message with a payload less or equal to (s - 7)
  // may be sent as one packet. A larger message is then divided into one or
  // more continuation packets, starting with sequence number 0 which then
  // increments by one to a maximum of 127.

  // the CID word is not aligned
  memcpy(&cid_, &report[1], sizeof(cid_));
  tcs_ = report[5];

  uint16_t raw_count;
  memcpy(&raw_count, &report[6], sizeof(raw_count));
  bcnt_ = base::NetToHost16(raw_count);

  valid_ = true;
}

class U2fHid::HidMessage {
 public:
  HidMessage(U2fHidCommand cmd, uint32_t cid) : cid_(cid), cmd_(cmd) {}

  // Appends |bytes| to the message payload.
  void AddPayload(const std::string& bytes);

  // Appends the single |byte| to the message payload.
  void AddByte(uint8_t byte);

  // Fills an HID report with the part of the message starting at |offset|.
  // Returns the offset of the remaining unused content in the message.
  int BuildReport(int offset, std::string* report_out);

 private:
  uint32_t cid_;
  U2fHidCommand cmd_;
  std::string payload_;
};

void U2fHid::HidMessage::AddPayload(const std::string& bytes) {
  payload_ += bytes;
}

void U2fHid::HidMessage::AddByte(uint8_t byte) {
  payload_.push_back(byte);
}

int U2fHid::HidMessage::BuildReport(int offset, std::string* report_out) {
  size_t data_size;

  // Serialize one chunk of the message in a 64-byte HID report
  // (see the HID report structure in HidPacket constructor)
  report_out->assign(
      std::string(reinterpret_cast<char*>(&cid_), sizeof(uint32_t)));
  if (offset == 0) {  // INIT message
    uint16_t bcnt = payload_.size();
    report_out->push_back(static_cast<uint8_t>(cmd_) | kFrameTypeInit);
    report_out->push_back(bcnt >> 8);
    report_out->push_back(bcnt & 0xff);
    data_size = kInitReportPayloadSize;
  } else {  // CONT message
    // Insert sequence number.
    report_out->push_back((offset - kInitReportPayloadSize) /
                          kContReportPayloadSize);
    data_size = kContReportPayloadSize;
  }
  data_size = std::min(data_size, payload_.size() - offset);
  *report_out += payload_.substr(offset, data_size);
  // Ensure the report is 64-B long
  report_out->insert(report_out->end(), kU2fReportSize - report_out->size(), 0);
  offset += data_size;

  VLOG(2) << "TX RPT ["
          << base::HexEncode(report_out->data(), report_out->size()) << "]";

  return offset != payload_.size() ? offset : 0;
}

struct U2fHid::Transaction {
  uint32_t cid = 0;
  U2fHidCommand cmd = U2fHidCommand::kError;
  size_t total_size = 0;
  int seq = 0;
  std::string payload;
  base::OneShotTimer timeout;
};

U2fHid::U2fHid(std::unique_ptr<HidInterface> hid,
               U2fCorpFirmwareVersion fw_version,
               std::string dev_id,
               U2fMessageHandlerInterface* msg_handler,
               U2fCorpProcessorInterface* u2f_corp_processor)
    : hid_(std::move(hid)),
      fw_version_(fw_version),
      dev_id_(std::move(dev_id)),
      free_cid_(1),
      locked_cid_(0),
      msg_handler_(msg_handler),
      u2f_corp_processor_(u2f_corp_processor) {
  transaction_ = std::make_unique<Transaction>();
  hid_->SetOutputReportHandler(
      base::BindRepeating(&U2fHid::ProcessReport, base::Unretained(this)));
}

U2fHid::~U2fHid() = default;

bool U2fHid::Init() {
  return hid_->Init(kInterfaceVersion,
                    std::string(reinterpret_cast<const char*>(kU2fReportDesc),
                                sizeof(kU2fReportDesc)));
}

void U2fHid::ReturnError(U2fHidError errcode, uint32_t cid, bool clear) {
  HidMessage msg(U2fHidCommand::kError, cid);

  msg.AddByte(static_cast<uint8_t>(errcode));
  VLOG(1) << "ERROR/" << std::hex << static_cast<int>(errcode)
          << " CID:" << std::hex << cid;
  if (clear)
    transaction_ = std::make_unique<Transaction>();

  std::string report;
  msg.BuildReport(0, &report);
  hid_->SendReport(report);
}

void U2fHid::TransactionTimeout() {
  ReturnError(U2fHidError::kMsgTimeout, transaction_->cid, true);
}

void U2fHid::LockTimeout() {
  if (locked_cid_)
    LOG(WARNING) << "Cancelled lock CID:" << std::hex << locked_cid_;
  locked_cid_ = 0;
}

void U2fHid::ReturnResponse(const std::string& resp) {
  HidMessage msg(transaction_->cmd, transaction_->cid);
  int offset = 0;

  msg.AddPayload(resp);
  // Send all the chunks of the message (split in 64-B HID reports)
  do {
    std::string report;
    offset = msg.BuildReport(offset, &report);
    hid_->SendReport(report);
  } while (offset);
}

void U2fHid::CmdInit(uint32_t cid, const std::string& payload) {
  HidMessage msg(U2fHidCommand::kInit, cid);

  if (payload.size() != kInitNonceSize) {
    VLOG(1) << "Payload size " << payload.size();
    ReturnError(U2fHidError::kInvalidLen, cid, false);
    return;
  }

  VLOG(1) << "INIT CID:" << std::hex << cid << " NONCE "
          << base::HexEncode(payload.data(), payload.size());

  if (cid == kCidBroadcast) {  // Allocate Channel ID
    cid = free_cid_++;
    // Roll-over if needed
    if (free_cid_ == kCidBroadcast)
      free_cid_ = 1;
  }

  // Keep the nonce in the first 8 bytes
  msg.AddPayload(payload);

  std::string serial_cid(reinterpret_cast<char*>(&cid), sizeof(uint32_t));
  msg.AddPayload(serial_cid);

  // Append the versions : interface / major / minor / build
  msg.AddByte(kInterfaceVersion);
  msg.AddByte(0);
  msg.AddByte(0);
  msg.AddByte(0);
  // Append Capability flags
  msg.AddByte(kCapFlagLock);

  std::string report;
  msg.BuildReport(0, &report);
  hid_->SendReport(report);
}

int U2fHid::CmdPing(std::string* resp) {
  VLOG(1) << "PING len " << transaction_->total_size;

  // send back the same content
  *resp = transaction_->payload.substr(0, transaction_->total_size);
  return transaction_->total_size;
}

int U2fHid::CmdLock(std::string* resp) {
  uint8_t duration = static_cast<uint8_t>(transaction_->payload[0]);

  VLOG(1) << "LOCK " << duration << "s CID:" << std::hex << transaction_->cid;

  if (duration > kMaxLockDurationSeconds) {
    duration = kMaxLockDurationSeconds;
  }

  if (!duration) {
    lock_timeout_.Stop();
    locked_cid_ = 0;
  } else {
    locked_cid_ = transaction_->cid;
    lock_timeout_.Start(
        FROM_HERE, base::Seconds(duration),
        base::BindOnce(&U2fHid::LockTimeout, base::Unretained(this)));
  }
  return 0;
}

int U2fHid::CmdSysInfo(std::string* resp) {
  if (u2f_corp_processor_) {
    std::string version = fw_version_.ToString();
    // 8 bytes name + 3 bytes firmware version + 3 bytes applet version.
    *resp = std::string("cr50") + std::string(4, '\x00') + version + version;
    return 0;
  }

  LOG(WARNING) << "Received unsupported SysInfo command";
  ReturnError(U2fHidError::kInvalidCmd, transaction_->cid, true);
  return -EINVAL;
}

int U2fHid::CmdMetrics(std::string* resp) {
  if (u2f_corp_processor_) {
    VLOG(1) << "Received Metrics command";
    *resp = dev_id_;
    return 0;
  }

  LOG(WARNING) << "Received unsupported Metrics command";
  ReturnError(U2fHidError::kInvalidCmd, transaction_->cid, true);
  return -EINVAL;
}

int U2fHid::CmdMsg(std::string* resp) {
  U2fResponseApdu r = msg_handler_->ProcessMsg(transaction_->payload);

  r.ToString(resp);

  return 0;
}

int U2fHid::CmdAtr(std::string* resp) {
  if (u2f_corp_processor_) {
    VLOG(1) << "Received Atr command";
    u2f_corp_processor_->Reset();
    return 0;
  }

  LOG(WARNING) << "Received unsupported Atr command";
  ReturnError(U2fHidError::kInvalidCmd, transaction_->cid, true);
  return -EINVAL;
}

void U2fHid::ExecuteCmd() {
  int rc;
  std::string resp;

  transaction_->timeout.Stop();
  switch (transaction_->cmd) {
    case U2fHidCommand::kPing:
      rc = CmdPing(&resp);
      break;
    case U2fHidCommand::kAtr:
      rc = CmdAtr(&resp);
      break;
    case U2fHidCommand::kMsg:
      rc = CmdMsg(&resp);
      break;
    case U2fHidCommand::kLock:
      rc = CmdLock(&resp);
      break;
    case U2fHidCommand::kVendorSysInfo:
      rc = CmdSysInfo(&resp);
      break;
    case U2fHidCommand::kMetrics:
      rc = CmdMetrics(&resp);
      break;
    default:
      LOG(WARNING) << "Unknown command " << std::hex
                   << static_cast<int>(transaction_->cmd);
      ReturnError(U2fHidError::kInvalidCmd, transaction_->cid, true);
      return;
  }

  if (rc >= 0)
    ReturnResponse(resp);

  // we are done with this transaction
  transaction_ = std::make_unique<Transaction>();
}

void U2fHid::ProcessReport(const std::string& report) {
  HidPacket pkt(report);

  VLOG(2) << "RX RPT/" << report.size() << " ["
          << base::HexEncode(report.data(), report.size()) << "]";
  if (!pkt.IsValidFrame())
    return;  // Invalid report

  // Check frame validity
  if (pkt.ChannelId() == 0) {
    VLOG(1) << "No frame should use channel 0";
    ReturnError(U2fHidError::kInvalidCid, pkt.ChannelId(),
                pkt.ChannelId() == transaction_->cid);
    return;
  }

  if (pkt.IsInitFrame() && pkt.Command() == U2fHidCommand::kInit) {
    if (pkt.ChannelId() == transaction_->cid) {
      // Abort an ongoing multi-packet transaction
      VLOG(1) << "Transaction cancelled on CID:" << std::hex << pkt.ChannelId();
      transaction_ = std::make_unique<Transaction>();
    }
    // special case: INIT should not interrupt other commands
    CmdInit(pkt.ChannelId(), report.substr(pkt.PayloadIndex(), kInitNonceSize));
    return;
  }
  // not an INIT command from here

  if (pkt.IsInitFrame()) {  // INIT frame type (not the INIT command)
    if (pkt.ChannelId() == kCidBroadcast) {
      VLOG(1) << "INIT command not on broadcast CID:" << std::hex
              << pkt.ChannelId();
      ReturnError(U2fHidError::kInvalidCid, pkt.ChannelId(), false);
      return;
    }
    if (locked_cid_ && pkt.ChannelId() != locked_cid_) {
      // somebody else has the lock
      VLOG(1) << "channel locked by CID:" << std::hex << locked_cid_;
      ReturnError(U2fHidError::kChannelBusy, pkt.ChannelId(), false);
      return;
    }
    if (transaction_->cid && (pkt.ChannelId() != transaction_->cid)) {
      VLOG(1) << "channel used by CID:" << std::hex << transaction_->cid;
      ReturnError(U2fHidError::kChannelBusy, pkt.ChannelId(), false);
      return;
    }
    if (transaction_->cid) {
      VLOG(1) << "CONT frame expected";
      ReturnError(U2fHidError::kInvalidSeq, pkt.ChannelId(), true);
      return;
    }
    if (pkt.MessagePayloadSize() > kMaxPayloadSize) {
      VLOG(1) << "Invalid length " << pkt.MessagePayloadSize();
      ReturnError(U2fHidError::kInvalidLen, pkt.ChannelId(), true);
      return;
    }

    transaction_->timeout.Start(
        FROM_HERE, kU2fHidTimeout,
        base::BindOnce(&U2fHid::TransactionTimeout, base::Unretained(this)));

    // record transaction parameters
    transaction_->cid = pkt.ChannelId();
    transaction_->total_size = pkt.MessagePayloadSize();
    transaction_->cmd = pkt.Command();
    transaction_->seq = 0;
    transaction_->payload =
        report.substr(pkt.PayloadIndex(), transaction_->total_size);
  } else {  // CONT Frame
    if (transaction_->cid == 0 || transaction_->cid != pkt.ChannelId()) {
      VLOG(1) << "invalid CONT";
      return;  // just ignore
    }
    if (transaction_->seq != pkt.SeqNumber()) {
      VLOG(1) << "invalid sequence " << static_cast<int>(pkt.SeqNumber())
              << " !=  " << transaction_->seq;
      ReturnError(U2fHidError::kInvalidSeq, pkt.ChannelId(),
                  pkt.ChannelId() == transaction_->cid);
      return;
    }
    // reload timeout
    transaction_->timeout.Start(
        FROM_HERE, kU2fHidTimeout,
        base::BindOnce(&U2fHid::TransactionTimeout, base::Unretained(this)));
    // record the payload
    transaction_->payload += report.substr(pkt.PayloadIndex());
    transaction_->seq++;
  }
  // Are we done with this transaction ?
  if (transaction_->payload.size() >= transaction_->total_size)
    ExecuteCmd();
}

}  // namespace u2f
