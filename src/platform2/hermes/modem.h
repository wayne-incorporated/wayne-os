// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MODEM_H_
#define HERMES_MODEM_H_

#include <deque>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <google-lpa/lpa/card/euicc_card.h>

#include "hermes/apdu.h"
#include "hermes/euicc_interface.h"
#include "hermes/hermes_common.h"
#include "hermes/modem_manager_proxy.h"

namespace hermes {

constexpr int kMaxRetries = 5;
constexpr int kMaxApduLen = 260;

// Delay between a sim change ( for e.g. slot switches or eSIM profile enable)
// and the next message to the modem. If this delay is insufficient, we could
// retry after kInitRetryDelay.
constexpr auto kSimRefreshDelay = base::Seconds(6);
constexpr auto kInitRetryDelay = base::Seconds(10);
constexpr uint8_t kInvalidChannel = 0;

// Schedule an uninhibit 4 seconds after an eSIM operation succeeds. If another
// eSIM operation makes an inhibit call during these 4 seconds, the scheduled
// uninhibit is cancelled.
constexpr auto kUninhibitDelay = base::Seconds(4);

constexpr int kModemSuccess = 0;

constexpr int kDefault3GPPRelease = 11;

// Modem houses code shared by ModemQrtr and ModemMbim
// T is the type of message that the modem implementation uses. For
// QMI, messages are stored in objects of type QmiCmdInterface, and for MBIM,
// messages are stored in objects of type MbimCmd.
template <typename T>
class Modem : public EuiccInterface {
 public:
  Modem(Logger* logger,
        Executor* executor,
        std::unique_ptr<ModemManagerProxyInterface> modem_manager_proxy)
      : euicc_manager_(nullptr),
        logger_(logger),
        executor_(executor),
        retry_count_(0),
        modem_manager_proxy_(std::move(modem_manager_proxy)),
        current_transaction_id_(static_cast<uint16_t>(-1)),
        weak_factory_(this) {
    // Set SGP.22 specification version supported by this implementation (this
    // is not currently constrained by the eUICC we use).
    spec_version_.set_major(2);
    spec_version_.set_minor(2);
    spec_version_.set_revision(0);
  }

  virtual ~Modem() = default;

  // lpa::card::EuiccCard overrides.
  void SendApdus(std::vector<lpa::card::Apdu> apdus,
                 ResponseCallback cb) override;
  // IsSimValidAfter..able() is called by the lpa after profile enable/disable
  bool IsSimValidAfterEnable() override { return true; };
  bool IsSimValidAfterDisable() override { return true; };
  std::string GetImei() override { return imei_; };
  const lpa::proto::EuiccSpecVersion& GetCardVersion() override {
    return spec_version_;
  }
  void SetCardVersion(
      const lpa::proto::EuiccSpecVersion& spec_version) override {
    spec_version_ = spec_version;
  };

  lpa::util::EuiccLog* logger() override { return logger_; }
  lpa::util::Executor* executor() override { return executor_; }

  std::vector<uint8_t> GetUtranSupportedRelease() override {
    return std::vector<uint8_t>{
        kDefault3GPPRelease, 0,
        0};  // Last two bytes are fixed to zero by SGP.22
  }
  std::vector<uint8_t> GetEutranSupportedRelease() override {
    return std::vector<uint8_t>{
        kDefault3GPPRelease, 0,
        0};  // Last two bytes are fixed to zero by SGP.22
  };

  // Used by third party code to send APDU's
  void TransmitApdu(const std::vector<uint8_t>& apduCommand,
                    base::OnceCallback<void(std::vector<uint8_t>)> cb) override;

 protected:
  // Base class for the tx info specific to a certain type of message to the
  // modem.
  // Uim command types that need any additional information should define
  // a child class. An instance of that class should be set to the data pointer
  // in its corresponding TxElement. For e.g. Apdu's require apdu info (thus, we
  // need an ApduTxInfo child class)
  struct TxInfo {
    virtual ~TxInfo() = default;
  };

  struct ApduTxInfo : public TxInfo {
    explicit ApduTxInfo(CommandApdu apdu) : apdu_(std::move(apdu)) {}
    ApduTxInfo(CommandApdu apdu, bool is_source_external)
        : apdu_(std::move(apdu)), is_source_external_(is_source_external) {}
    CommandApdu apdu_;
    // External apps may use TransmitApdu to send APDU's. Such
    // APDU's may need to be treated differently since the header
    // and apdu content are prepopulated by the external app
    bool is_source_external_ = false;
  };

  struct OpenChannelTxInfo : public TxInfo {
    explicit OpenChannelTxInfo(const std::vector<uint8_t>& aid) : aid_(aid) {}
    std::vector<uint8_t> aid_;
  };

  struct TxElement {
    // TxInfo stores any parameters that msg_ takes
    std::unique_ptr<TxInfo> info_;
    uint16_t id_;
    // msg_ stores the type of msg to be sent. For e.g. if TxInfo contains
    // an apdu, then the msg_ should point to UimCmd::UimType::kSendApdu or
    // MbimType::kSendApdu.
    std::unique_ptr<T> msg_;
    // This cb_ maybe called once a response for the msg_ is received.
    // The callback must accept an int which is the return value of the qmi
    // operation
    base::OnceCallback<void(int)> cb_;
  };

  uint16_t AllocateId();
  // The tag is used by TransmitFromQueue to distinguish apdu's from other types
  // of messages in the tx_queue.
  virtual std::unique_ptr<T> GetTagForSendApdu() = 0;
  // Convenience function that runs the lpa callback if err==0
  virtual void SendApdusResponse(ResponseCallback callback, int err);
  // OpenConnectionResponse calls cb with open_channel_raw_response_
  void OpenConnectionResponse(base::OnceCallback<void(std::vector<uint8_t>)> cb,
                              int err);
  // TransmitApduResponse calls cb with responses_[0]
  void TransmitApduResponse(base::OnceCallback<void(std::vector<uint8_t>)> cb,
                            int err);

  // SendApdus will queue APDU's on tx_queue_ and call TransmitFromQueue()
  // In the QMI and MBIM implementations, TransmitFromQueue also processes
  // other messages like reset, close channel, open channel etc.
  virtual void TransmitFromQueue() = 0;
  virtual void Shutdown() = 0;
  void RetryInitialization(ResultCallback cb);
  void RunNextStepOrRetry(
      base::OnceCallback<void(base::OnceCallback<void(int)>)> next_step,
      base::OnceCallback<void(int)> cb,
      int err);
  // List of responses for the oldest SendApdus call that hasn't been completely
  // processed.
  std::vector<ResponseApdu> responses_;
  std::deque<TxElement> tx_queue_;
  std::vector<uint8_t> open_channel_raw_response_;

  // Used to send notifications about eSIM slot changes.
  EuiccManagerInterface* euicc_manager_;

  Logger* logger_;
  Executor* executor_;
  lpa::proto::EuiccSpecVersion spec_version_;
  std::string imei_;
  int retry_count_;
  base::OnceClosure retry_initialization_callback_;
  std::unique_ptr<ModemManagerProxyInterface> modem_manager_proxy_;

 private:
  uint16_t current_transaction_id_;
  base::WeakPtrFactory<Modem<T>> weak_factory_;
};

// Used by google-lpa to queue APDU's
template <typename T>
void Modem<T>::SendApdus(std::vector<lpa::card::Apdu> apdus,
                         ResponseCallback cb) {
  base::OnceCallback<void(int)> callback;
  callback = base::BindOnce(&Modem<T>::SendApdusResponse,
                            weak_factory_.GetWeakPtr(), std::move(cb));
  LOG(INFO) << __func__;
  for (size_t i = 0; i < apdus.size(); ++i) {
    CommandApdu apdu(static_cast<ApduClass>(apdus[i].cla()),
                     static_cast<ApduInstruction>(apdus[i].ins()),
                     /* is_extended_length */ false);
    apdu.AddData(apdus[i].data());
    tx_queue_.push_back({std::make_unique<ApduTxInfo>(std::move(apdu)),
                         AllocateId(), GetTagForSendApdu(),
                         i == apdus.size() - 1
                             ? std::move(callback)
                             : base::BindOnce(&PrintMsgProcessingResult)});
  }
  TransmitFromQueue();
}

// Used by external apps like gemalto eOS updater.
template <typename T>
void Modem<T>::TransmitApdu(const std::vector<uint8_t>& apduCommand,
                            base::OnceCallback<void(std::vector<uint8_t>)> cb) {
  DCHECK(tx_queue_.empty())
      << __func__
      << ": expected tx queue to be empty, size=" << tx_queue_.size();
  LOG(INFO) << __func__ << ": APDU command="
            << base::HexEncode(apduCommand.data(), apduCommand.size());
  DCHECK(apduCommand.size() > 2) << "APDU does not have a header.";
  CommandApdu apdu(apduCommand);
  auto transmit_apdu_resp =
      base::BindOnce(&Modem<T>::TransmitApduResponse,
                     weak_factory_.GetWeakPtr(), std::move(cb));
  tx_queue_.push_back({std::make_unique<ApduTxInfo>(
                           std::move(apdu), true /*is_source_external_*/),
                       AllocateId(), GetTagForSendApdu(),
                       std::move(transmit_apdu_resp)});
  TransmitFromQueue();
}

template <typename T>
void Modem<T>::SendApdusResponse(EuiccInterface::ResponseCallback callback,
                                 int err) {
  std::vector<std::vector<uint8_t>> responses_vec;
  VLOG(2) << __func__;
  for (auto& response : responses_) {
    response.ReleaseStatusBytes();
    responses_vec.push_back(response.Release());
  }
  responses_.clear();
  callback(responses_vec, err);
  // ResponseCallback interface does not indicate a change in ownership of
  // |responses_|, but all callbacks should transfer ownership.
  CHECK(responses_vec.empty());
}

template <typename T>
void Modem<T>::OpenConnectionResponse(
    base::OnceCallback<void(std::vector<uint8_t>)> cb, int err) {
  LOG(INFO) << __func__ << "Open Channel Response: "
            << base::HexEncode(open_channel_raw_response_.data(),
                               open_channel_raw_response_.size());
  DCHECK(!open_channel_raw_response_.empty());
  std::move(cb).Run(std::move(open_channel_raw_response_));
}

template <typename T>
void Modem<T>::TransmitApduResponse(
    base::OnceCallback<void(std::vector<uint8_t>)> cb, int err) {
  if (responses_.size() != 1) {
    LOG(ERROR) << "responses.size != 1";
    std::move(cb).Run(std::vector<uint8_t>());
    return;
  }
  std::vector<uint8_t> response = responses_[0].Release();
  responses_.clear();
  LOG(INFO) << __func__ << ": response="
            << base::HexEncode(response.data(), response.size());
  std::move(cb).Run(std::move(response));
}

template <typename T>
uint16_t Modem<T>::AllocateId() {
  // transaction id cannot be 0 for QMI, but when incrementing by 1, an overflow
  // will result in this method at some point returning 0. Incrementing by 2
  // when transaction_id is initialized as an odd number guarantees us that this
  // method will never return 0 without special-casing the overflow.
  DCHECK_NE(current_transaction_id_, 0);
  current_transaction_id_ += 2;
  return current_transaction_id_;
}

template <typename T>
void Modem<T>::RetryInitialization(ResultCallback cb) {
  Shutdown();
  if (retry_count_ > kMaxRetries) {
    LOG(INFO) << __func__ << ": Max retry count(" << kMaxRetries
              << ") exceeded. Waiting for a new modem object...";
    retry_count_ = 0;
    while (!tx_queue_.empty()) {
      std::move(tx_queue_[0].cb_).Run(kModemMessageProcessingError);
      tx_queue_.pop_front();
    }
    modem_manager_proxy_->RegisterModemAppearedCallback(
        base::BindOnce(&Modem<T>::Initialize, weak_factory_.GetWeakPtr(),
                       euicc_manager_, base::DoNothing()));

    if (!cb.is_null())
      std::move(cb).Run(kModemMessageProcessingError);
    return;
  }
  LOG(INFO) << "Reprobing for eSIM in " << kInitRetryDelay.InSeconds()
            << " seconds";
  retry_initialization_callback_.Reset();
  retry_initialization_callback_ =
      base::BindOnce(&Modem<T>::Initialize, weak_factory_.GetWeakPtr(),
                     euicc_manager_, std::move(cb));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, std::move(retry_initialization_callback_), kInitRetryDelay);
  retry_count_++;
}

template <typename T>
void Modem<T>::RunNextStepOrRetry(
    base::OnceCallback<void(base::OnceCallback<void(int)>)> next_step,
    base::OnceCallback<void(int)> cb,
    int err) {
  if (err) {
    RetryInitialization(std::move(cb));
    return;
  }
  RunNextStep(std::move(next_step), std::move(cb), err);
}

}  // namespace hermes

#endif  // HERMES_MODEM_H_
