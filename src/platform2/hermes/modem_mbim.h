// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MODEM_MBIM_H_
#define HERMES_MODEM_MBIM_H_

#include <deque>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <base/strings/string_number_conversions.h>
#include <glib-bridge/glib_bridge.h>
#include <glib-bridge/glib_logger.h>
#include <glib-bridge/glib_scopers.h>
#include <google-lpa/lpa/card/euicc_card.h>
#include "hermes/euicc_interface.h"
#include "hermes/executor.h"
#include "hermes/libmbim_interface.h"
#include "hermes/logger.h"
#include "hermes/mbim_cmd.h"
#include "hermes/modem.h"
#include "hermes/modem_control_interface.h"
#include "hermes/modem_manager_proxy.h"
#include "hermes/socket_interface.h"

namespace hermes {
// Implementation of EuiccCard using MBIM
// messages.
class ModemMbim : public Modem<MbimCmd> {
 public:
  static constexpr int kMbimMessageSuccess = 144;
  static std::unique_ptr<ModemMbim> Create(
      Logger* logger,
      Executor* executor,
      std::unique_ptr<LibmbimInterface> libmbim,
      std::unique_ptr<ModemManagerProxyInterface> modem_manager_proxy);
  virtual ~ModemMbim();
  // EuiccInterface overrides
  void Initialize(EuiccManagerInterface* euicc_manager,
                  ResultCallback cb) override;
  void ProcessEuiccEvent(EuiccEvent event, ResultCallback cb) override;
  void RestoreActiveSlot(ResultCallback cb) override;
  bool IsSimValidAfterEnable() override;
  bool IsSimValidAfterDisable() override;
  void OpenConnection(
      const std::vector<uint8_t>& aid,
      base::OnceCallback<void(std::vector<uint8_t>)> cb) override;
  static bool ParseEidApduResponseForTesting(
      const MbimMessage* response,
      std::string* eid,
      std::unique_ptr<LibmbimInterface> libmbim);
  void SetIsReadyStateValidForTesting(bool is_ready_state_valid) {
    is_ready_state_valid_ = is_ready_state_valid;
  }

 private:
  struct SwitchSlotTxInfo : public TxInfo {
    explicit SwitchSlotTxInfo(const uint32_t physical_slot)
        : physical_slot_(physical_slot) {}
    const uint32_t physical_slot_;
  };
  ModemMbim(Logger* logger,
            Executor* executor,
            std::unique_ptr<LibmbimInterface> libmbim,
            std::unique_ptr<ModemManagerProxyInterface> modem_manager_proxy);
  void Shutdown() override;
  void TransmitFromQueue() override;
  std::unique_ptr<MbimCmd> GetTagForSendApdu() override;
  void ProcessMbimResult(int err);
  static void MbimCreateNewDeviceCb(GObject* source,
                                    GAsyncResult* res,
                                    ModemMbim* modem_mbim);
  static void MbimDeviceOpenReadyCb(MbimDevice* dev,
                                    GAsyncResult* res,
                                    ModemMbim* modem_mbim);
  void TransmitSubscriberStatusReady();
  void TransmitDeviceCaps();
  void TransmitCloseChannel();
  void TransmitDeviceSlotMapping();
  void TransmitSlotInfoStatus();
  void TransmitOpenChannel();
  void TransmitSendEidApdu();
  void TransmitSysCapsQuery();
  void TransmitSetDeviceSlotMapping();
  void TransmitMbimSendApdu(TxElement* tx_element);

  template <typename Func, typename... Args>
  void SendMessage(MbimCmd::MbimType type,
                   std::unique_ptr<TxInfo> tx_info,
                   ResultCallback cb,
                   Func&& next_step,
                   Args&&... args);

  static void SubscriberReadyStatusRspCb(MbimDevice* device,
                                         GAsyncResult* res,
                                         ModemMbim* modem_mbim);
  static void QuerySysCapsReady(MbimDevice* device,
                                GAsyncResult* res,
                                ModemMbim* modem_mbim);
  static void DeviceSlotStatusMappingRspCb(MbimDevice* device,
                                           GAsyncResult* res,
                                           ModemMbim* modem_mbim);

  static void DeviceCapsQueryReady(MbimDevice* device,
                                   GAsyncResult* res,
                                   ModemMbim* modem_mbim);

  static void DeviceSlotStatusInfoRspCb(MbimDevice* device,
                                        GAsyncResult* res,
                                        ModemMbim* modem_mbim);

  static void UiccLowLevelAccessCloseChannelSetCb(MbimDevice* device,
                                                  GAsyncResult* res,
                                                  ModemMbim* modem_mbim);

  static void UiccLowLevelAccessOpenChannelSetCb(MbimDevice* device,
                                                 GAsyncResult* res,
                                                 ModemMbim* modem_mbim);

  static void UiccLowLevelAccessApduEidParse(MbimDevice* device,
                                             GAsyncResult* res,
                                             ModemMbim* modem_mbim);
  static bool ParseEidApduResponse(const MbimMessage* response,
                                   std::string* eid,
                                   ModemMbim* modem_mbim,
                                   LibmbimInterface* libmbim);

  static void UiccLowLevelAccessApduResponseParse(MbimDevice* device,
                                                  GAsyncResult* res,
                                                  ModemMbim* modem_mbim);

  static void SetDeviceSlotMappingsRspCb(MbimDevice* device,
                                         GAsyncResult* res,
                                         ModemMbim* modem_mbim);

  static void ClientIndicationCb(MbimDevice* device,
                                 MbimMessage* notification,
                                 ModemMbim* modem_mbim);

  void CloseDevice();

  void CloseDeviceAndUninhibit(ResultCallback cb);

  enum class EuiccEventStep {
    GET_MBIM_DEVICE,
    GET_SLOT_MAPPING,
    GET_SLOT_INFO,
    CLOSE_CHANNEL,
    SET_SLOT_MAPPING,
    OPEN_CHANNEL,
    GET_EID,
    CHECK_EID,
    EUICC_EVENT_STEP_LAST,
  };
  enum class EidReadFailedStep {
    CLOSE_CHANNEL,
    RESTORE_SLOT_ATTEMPT1,
    RESTORE_SLOT_ATTEMPT2,
    STEP_LAST,
  };

  void ReacquireChannel(EuiccEventStep step,
                        std::vector<uint8_t> aid,
                        ResultCallback cb);
  void OnEuiccEventStart(uint32_t physical_slot,
                         bool switch_slot_only,
                         EuiccEventStep step,
                         ResultCallback cb);
  void OnEidReadFailed(const uint32_t physical_slot,
                       EidReadFailedStep step,
                       ResultCallback cb);
  void AcquireChannelAfterCardReady(EuiccEvent event, ResultCallback cb);

  class State {
   public:
    enum Value : uint8_t {
      kMbimUninitialized,
      kMbimInitializeStarted,
      kReadImei,
      kGetSubscriberReadyState,
      kCheckSingleSim,
      kSysQuery,  // for num slots
      kDeviceSlotMapping,
      kSlotInfo,
      kCloseChannel,
      kOpenChannel,
      kReadEid,
      kEidReadComplete,
      kMbimStarted,
    };

    State() : value_(kMbimUninitialized) {}
    // Transitions to the indicated state. Returns whether or not the
    // transition was successful.
    bool Transition(Value value);
    bool operator==(Value value) const { return value_ == value; }
    bool operator!=(Value value) const { return value_ != value; }
    friend std::ostream& operator<<(std::ostream& os, State state);

   private:
    explicit State(Value value) : value_(value) {}
    Value value_;
  };
  friend std::ostream& operator<<(std::ostream& os, State state);
  void InitializationStep(ModemMbim::State::Value next_state,
                          ResultCallback cb);
  void ReadSlotsInfo(uint32_t slot_num,
                     uint32_t retry_count,
                     ResultCallback cb);
  void OnEuiccUpdated();

  State current_state_;
  ResultCallback init_done_cb_;
  std::unique_ptr<LibmbimInterface> libmbim_;
  guint32 channel_;
  glib_bridge::ScopedGObject<MbimDevice> device_;
  uint8_t indication_id_;
  bool is_ready_state_valid_;
  MbimSubscriberReadyState ready_state_;
  GFile* file_ = NULL;
  struct SlotInfo {
    guint32 map_count_;  // number of executors/ radio. 1 for DSSA
    guint32 slot_count_;
    int cached_active_slot_;
    // cached_active_slot is updated when Hermes reads the slot mapping or when
    // Hermes switches slots. It may be outdated if another daemon switches
    // slots when Hermes is idle.
    std::optional<int> get_slot_mapping_result_;
    // get_slot_mapping_result_ may be used to  restore the active slot to that
    // before a Hermes operation
    std::vector<MbimUiccSlotState> slot_state_;
    std::vector<std::string> eid_;
    bool IsEuicc(int slot) const;
    bool IsEuiccPresentOnAnySlot() const;
    bool IsEsimActive() const { return IsEuicc(cached_active_slot_); }
    void Clear() { InitSlotInfo(0, 0); }
    void InitSlotInfo(guint32 slot_count, guint32 map_count);
    void SetEidActiveSlot(std::string eid);
    void SetSlotStateActiveSlot(MbimUiccSlotState state);
  };
  friend std::ostream& operator<<(std::ostream& os, const SlotInfo& info);
  SlotInfo slot_info_;
  base::WeakPtrFactory<ModemMbim> weak_factory_;
  bool eid_read_failed_ = false;
};

}  // namespace hermes

#endif  // HERMES_MODEM_MBIM_H_
