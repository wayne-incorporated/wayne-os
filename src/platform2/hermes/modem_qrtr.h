// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MODEM_QRTR_H_
#define HERMES_MODEM_QRTR_H_

#include <deque>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <google-lpa/lpa/card/euicc_card.h>
#include <libqrtr.h>

#include "hermes/dms_cmd.h"
#include "hermes/executor.h"
#include "hermes/hermes_common.h"
#include "hermes/logger.h"
#include "hermes/modem.h"
#include "hermes/socket_qrtr.h"
#include "hermes/uim_cmd.h"

namespace hermes {

// Implementation of EuiccCard using QRTR sockets to send QMI UIM
// messages.
class ModemQrtr : public Modem<QmiCmdInterface> {
 public:
  static std::unique_ptr<ModemQrtr> Create(
      std::unique_ptr<SocketInterface> socket,
      Logger* logger,
      Executor* executor,
      std::unique_ptr<ModemManagerProxy> modem_manager_proxy);
  virtual ~ModemQrtr();

  // EuiccInterface overrides
  void Initialize(EuiccManagerInterface* euicc_manager,
                  ResultCallback cb) override;

  void StoreAndSetActiveSlot(uint32_t physical_slot, ResultCallback cb);
  // ModemControlInterface overrides
  void RestoreActiveSlot(ResultCallback cb) override;
  void ProcessEuiccEvent(EuiccEvent event, ResultCallback cb) override;

  void OpenConnection(
      const std::vector<uint8_t>& aid,
      base::OnceCallback<void(std::vector<uint8_t>)> cb) override;

 private:
  struct SwitchSlotTxInfo : public TxInfo {
    explicit SwitchSlotTxInfo(const uint32_t physical_slot,
                              const uint8_t logical_slot)
        : physical_slot_(physical_slot), logical_slot_(logical_slot) {}
    const uint32_t physical_slot_;
    const uint8_t logical_slot_;
  };

  ModemQrtr(std::unique_ptr<SocketInterface> socket,
            Logger* logger,
            Executor* executor,
            std::unique_ptr<ModemManagerProxy> modem_manager_proxy);
  void InitializeUim();
  void Shutdown() override;

  // Helper methods to create TxElements and add them to the queue.
  void SendReset(ResultCallback cb);
  void SendOpenLogicalChannel(const std::vector<uint8_t>& aid,
                              base::OnceCallback<void(int)> cb);

  // Top-level method to transmit an element from the tx queue. Dispatches to
  // the proper Transmit*CmdFromQueue method based on the service being
  // transmitted to.
  void TransmitFromQueue() override;
  // Transmit*CmdFromQueue methods perform QMI encoding prior to sending
  // data to the socket. Will remove elements from the tx queue as needed.
  void TransmitDmsCmdFromQueue();
  void TransmitUimCmdFromQueue();
  // Creates and sends a SWITCH_SLOT QMI request
  void TransmitQmiSwitchSlot(TxElement* tx_element);
  // Creates and sends OPEN_LOGICAL_CHANNEL QMI request.
  void TransmitQmiOpenLogicalChannel(TxElement* tx_element);

  std::unique_ptr<QmiCmdInterface> GetTagForSendApdu() override;
  // Creates and sends SEND_APDU QMI request.
  void TransmitQmiSendApdu(TxElement* tx_element);

  // Performs QMI encoding and sends data to the QRTR socket.
  bool SendCommand(QmiCmdInterface* qmi_command,
                   uint16_t id,
                   void* c_struct,
                   qmi_elem_info* ei);

  // Top-level method when a packet is read from the socket into |buffer_|. Will
  // perform proper processing based on QRTR packet type. Attempts to transmit
  // the next element in the tx queue when complete.
  void ProcessQrtrPacket(uint32_t node, uint32_t port, int size);
  // Dispatches to proper ReceiveQmi* method based on QMI type.
  void ProcessQmiPacket(const qrtr_packet& packet);
  // Performs decoding for UIM RESET QMI response.
  int ReceiveQmiReset(const qrtr_packet& packet);
  // Performs decoding for SWITCH_SLOT QMI response.
  int ReceiveQmiSwitchSlot(const qrtr_packet& packet);
  // Performs decoding for GET_SLOTS QMI response.
  int ReceiveQmiGetSlots(const qrtr_packet& packet);
  // Performs decoding for OPEN_LOGICAL_CHANNEL QMI response.
  int ReceiveQmiOpenLogicalChannel(const qrtr_packet& packet);
  int ParseQmiOpenLogicalChannel(const qrtr_packet& packet);
  // Performs decoding for SEND_APDU response and calls |on_recv_| with
  // appropriate parameters.
  int ReceiveQmiSendApdu(const qrtr_packet& packet);
  // Performs decoding of GET_DEVICE_SERIAL_NUMBERS response. Parses the IMEI.
  int ReceiveQmiGetSerialNumbers(const qrtr_packet& packet);
  void DisableQmi(base::TimeDelta duration);
  void EnableQmi();

  void OnDataAvailable(SocketInterface* socket);

  // Set the active slot to a euicc so that a channel can be established and
  // profiles can be installed.
  void SetActiveSlot(const uint32_t physical_slot, ResultCallback cb);

  // Request that the Euicc does not send intermediate procedure bytes.
  // Useful in eliminating race between card refresh and profile enable response
  // b/169954635
  enum class ProcedureBytesMode : uint8_t {
    EnableIntermediateBytes = 0,
    DisableIntermediateBytes = 1
  };
  void SetProcedureBytes(ProcedureBytesMode procedure_bytes_mode);
  void AcquireChannelToIsdr(base::OnceCallback<void(int)> cb);
  void AcquireChannel(const std::vector<uint8_t>& aid,
                      base::OnceCallback<void(int)> cb);

  friend class ModemQrtrTest;

  class State {
   public:
    enum Value : uint8_t {
      kUninitialized,
      kInitializeStarted,
      kDmsStarted,
      kUimStarted,
    };

    State() : value_(kUninitialized) {}
    // Transitions to the indicated state. Returns whether or not the transition
    // was successful.
    bool Transition(Value value);

    bool operator==(Value value) const { return value_ == value; }
    bool operator!=(Value value) const { return value_ != value; }
    friend std::ostream& operator<<(std::ostream& os, const State state) {
      switch (state.value_) {
        case kUninitialized:
          os << "Uninitialized";
          break;
        case kInitializeStarted:
          os << "InitializeStarted";
          break;
        case kDmsStarted:
          os << "DmsStarted";
          break;
        case kUimStarted:
          os << "UimStarted";
          break;
      }
      return os;
    }

   private:
    explicit State(Value value) : value_(value) {}

    Value value_;
  };

  State current_state_;
  bool qmi_disabled_;
  base::OnceClosure retry_initialization_callback_;
  int retry_count_;

  ResultCallback init_done_cb_;

  // Indicates that a qmi message has been sent and that a response is expected
  // Set for all known message types except QMI_RESET
  std::unique_ptr<QmiCmdInterface> pending_response_type_;

  // Logical Channel that will be used to communicate with the chip, returned
  // from OPEN_LOGICAL_CHANNEL request sent once the QRTR socket has been
  // opened.
  uint8_t channel_;
  // The slot that the logical channel to the eSIM will be made. Initialized in
  // constructor, hardware specific.
  uint8_t logical_slot_;
  // Store the previous active slot before a switch slot
  std::optional<uint32_t> stored_active_slot_;

  // Ask SendApdu commands to send final result and status words only.
  // If set, intermediate procedure bytes are not sent by the Euicc.
  ProcedureBytesMode procedure_bytes_mode_;

  std::unique_ptr<SocketInterface> socket_;

  // A bimap of {node,port} <-> Service .
  // Stores information similar to output of qrtr-lookup
  class QrtrTable {
    std::unordered_map<QmiCmdInterface::Service, SocketQrtr::PacketMetadata>
        qrtr_metadata_;
    std::unordered_map<SocketQrtr::PacketMetadata, QmiCmdInterface::Service>
        service_from_metadata_;

   public:
    bool ContainsService(QmiCmdInterface::Service service);
    void Insert(QmiCmdInterface::Service service,
                SocketQrtr::PacketMetadata metadata);
    void clear();
    const SocketQrtr::PacketMetadata& GetMetadata(
        QmiCmdInterface::Service service);
    const QmiCmdInterface::Service& GetService(
        SocketQrtr::PacketMetadata metadata);
  };
  QrtrTable qrtr_table_;

  // Buffer for storing data from the QRTR socket
  std::vector<uint8_t> buffer_;

  std::map<std::pair<QmiCmdInterface::Service, uint16_t>,
           base::RepeatingCallback<int(const qrtr_packet&)>>
      qmi_rx_callbacks_;

  base::WeakPtrFactory<ModemQrtr> weak_factory_;
};

}  // namespace hermes

#endif  // HERMES_MODEM_QRTR_H_
