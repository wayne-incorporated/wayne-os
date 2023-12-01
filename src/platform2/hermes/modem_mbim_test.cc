// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/modem_mbim.h"

#include <memory>

#include <base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "hermes/fake_euicc_manager.h"
#include "hermes/mock_executor.h"
#include "hermes/sgp_22.h"

using ::testing::_;

namespace {
constexpr int kEuiccSlot = 0;
constexpr int kNonEuiccSlot = 1;
constexpr int kChannel = 10;
constexpr guint8 kEidApdu[9] = {0xBF, 0x3E, 0x12, 0x5A, 0x10,
                                0x11, 0x11, 0x11, 0x11};
constexpr int kEidApduLen = sizeof(kEidApdu) / sizeof(kEidApdu[0]);
}  // namespace

namespace hermes {

class MockModemManagerProxy : public ModemManagerProxyInterface {
 public:
  MOCK_METHOD(void,
              RegisterModemAppearedCallback,
              (base::OnceClosure cb),
              (override));
  MOCK_METHOD(void, WaitForModem, (base::OnceClosure cb), (override));

  MOCK_METHOD(std::string, GetMbimPort, (), (const, override));

  MOCK_METHOD(void, ScheduleUninhibit, (base::TimeDelta timeout), (override));
  MOCK_METHOD(void, WaitForModemAndInhibit, (ResultCallback cb), (override));
  MockModemManagerProxy() {
    ON_CALL(*this, WaitForModem).WillByDefault([](base::OnceClosure cb) {
      std::move(cb).Run();
    });
    ON_CALL(*this, WaitForModemAndInhibit).WillByDefault([](ResultCallback cb) {
      std::move(cb).Run(kModemSuccess);
    });
    ON_CALL(*this, GetMbimPort).WillByDefault([]() { return "wwan0"; });
  }
};

class FakeLibmbim : public LibmbimInterface {
 public:
  FakeLibmbim() {
    ON_CALL(*this, MbimMessageMsUiccLowLevelAccessOpenChannelResponseParse)
        .WillByDefault(testing::Invoke(
            this,
            &FakeLibmbim::
                FakeMbimMessageMsUiccLowLevelAccessOpenChannelResponseParse));
    ON_CALL(*this, MbimMessageMsUiccLowLevelAccessCloseChannelResponseParse)
        .WillByDefault(testing::Invoke(
            this,
            &FakeLibmbim::
                FakeMbimMessageMsUiccLowLevelAccessCloseChannelResponseParse));
  }
  void MbimDeviceNew(GFile* file,
                     GCancellable* cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data) override {
    LOG(INFO) << __func__;
    callback(nullptr, nullptr, user_data);
  };

  MbimDevice* MbimDeviceNewFinish(GAsyncResult* res, GError** error) override {
    return new MbimDevice();
  };

  void MbimDeviceOpenFull(MbimDevice* self,
                          MbimDeviceOpenFlags flags,
                          guint timeout,
                          GCancellable* cancellable,
                          GAsyncReadyCallback callback,
                          gpointer user_data) override {
    GTask* task;
    task = g_task_new(self, cancellable, nullptr, nullptr);
    g_task_return_boolean(task, TRUE);
    callback(reinterpret_cast<GObject*>(self),
             reinterpret_cast<GAsyncResult*>(task), user_data);
  }

  void MbimDeviceCommand(MbimDevice* self,
                         MbimMessage* message,
                         guint timeout,
                         GCancellable* cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data) override {
    callback(nullptr, nullptr, user_data);
  }

  MbimMessage* MbimDeviceCommandFinish(MbimDevice* self,
                                       GAsyncResult* res,
                                       GError** error) override {
    return mbim_message_new(nullptr, 0);
  }

  gboolean MbimMessageValidate(const MbimMessage* self,
                               GError** error) override {
    return TRUE;
  }

  MbimMessageType MbimMessageGetMessageType(const MbimMessage* self) override {
    return MBIM_MESSAGE_TYPE_COMMAND_DONE;
  };

  gboolean MbimMessageResponseGetResult(const MbimMessage* self,
                                        MbimMessageType expected,
                                        GError** error) override {
    return TRUE;
  }

  gboolean MbimMessageDeviceCapsResponseParse(
      const MbimMessage* message,
      MbimDeviceType* out_device_type,
      MbimCellularClass* out_cellular_class,
      MbimVoiceClass* out_voice_class,
      MbimSimClass* out_sim_class,
      MbimDataClass* out_data_class,
      MbimSmsCaps* out_sms_caps,
      MbimCtrlCaps* out_control_caps,
      guint32* out_max_sessions,
      gchar** out_custom_data_class,
      gchar** out_device_id,
      gchar** out_firmware_info,
      gchar** out_hardware_info,
      GError** error) override {
    *out_device_id = g_strdup_printf("123");
    return TRUE;
  }

  gboolean MbimDeviceCheckMsMbimexVersion(
      MbimDevice* self,
      guint8 ms_mbimex_version_major,
      guint8 ms_mbimex_version_minor) override {
    return TRUE;
  }

  bool GetReadyState(MbimDevice* device,
                     bool is_notification,
                     MbimMessage* notification,
                     MbimSubscriberReadyState* ready_state) override {
    *ready_state = MBIM_SUBSCRIBER_READY_STATE_INITIALIZED;
    return TRUE;
  }

  gboolean MbimMessageMsBasicConnectExtensionsSysCapsResponseParse(
      const MbimMessage* message,
      guint32* out_number_of_executors,
      guint32* out_number_of_slots,
      guint32* out_concurrency,
      guint64* out_modem_id,
      GError** error) override {
    *out_number_of_slots = 2;
    *out_number_of_executors = 1;
    return TRUE;
  }

  gboolean MbimMessageMsBasicConnectExtensionsDeviceSlotMappingsResponseParse(
      const MbimMessage* message,
      guint32* out_map_count,
      MbimSlotArray** out_slot_map,
      GError** error) override {
    *out_map_count = 1;
    MbimSlotArray* out;
    out = g_new0(MbimSlot*, 2);
    MbimSlot* mbim_slot = g_new0(MbimSlot, 1);
    mbim_slot->slot = active_slot_;
    out[0] = mbim_slot;
    *out_slot_map = out;
    return TRUE;
  }

  gboolean MbimMessageMsBasicConnectExtensionsSlotInfoStatusResponseParse(
      const MbimMessage* message,
      guint32* out_slot_index,
      MbimUiccSlotState* out_state,
      GError** error) override {
    static guint32 slot_index = 0;
    *out_slot_index = slot_index;
    *out_state = slot_index == kNonEuiccSlot ? MBIM_UICC_SLOT_STATE_EMPTY
                                             : MBIM_UICC_SLOT_STATE_ACTIVE_ESIM;
    slot_index++;
    slot_index %= 2;
    return TRUE;
  }

  MOCK_METHOD(gboolean,
              MbimMessageMsUiccLowLevelAccessOpenChannelResponseParse,
              (const MbimMessage* message,
               guint32* out_status,
               guint32* out_channel,
               guint32* out_response_size,
               const guint8** out_response,
               GError** error),
              (override));

  gboolean FakeMbimMessageMsUiccLowLevelAccessOpenChannelResponseParse(
      const MbimMessage* message,
      guint32* out_status,
      guint32* out_channel,
      guint32* out_response_size,
      const guint8** out_response,
      GError** error) {
    *out_status = ModemMbim::kMbimMessageSuccess;
    *out_channel = kChannel;
    *out_response_size = 0;
    return TRUE;
  }

  gboolean MbimMessageMsUiccLowLevelAccessApduResponseParse(
      const MbimMessage* message,
      guint32* out_status,
      guint32* out_response_size,
      const guint8** out_response,
      GError** error) override {
    *out_status = ModemMbim::kMbimMessageSuccess;
    *out_response = kEidApdu;
    *out_response_size = kEidApduLen;
    return TRUE;
  }
  MOCK_METHOD(gboolean,
              MbimMessageMsUiccLowLevelAccessCloseChannelResponseParse,
              (const MbimMessage* message, guint32* out_status, GError** error),
              (override));

  gboolean FakeMbimMessageMsUiccLowLevelAccessCloseChannelResponseParse(
      const MbimMessage* message, guint32* out_status, GError** error) {
    *out_status = ModemMbim::kMbimMessageSuccess;
    return TRUE;
  }

  guint32 active_slot_ = kEuiccSlot;
};

class ModemMbimTest : public testing::Test {
 protected:
  void SetUp() override {
    modem_manager_proxy_ = std::make_unique<MockModemManagerProxy>();
    libmbim_ = std::make_unique<FakeLibmbim>();
  }

  void TearDown() override { modem_.reset(); }

  void CreateModem() {
    modem_ = ModemMbim::Create(nullptr, &executor_, std::move(libmbim_),
                               std::move(modem_manager_proxy_));
    ASSERT_NE(modem_, nullptr);
  }

  base::OnceCallback<void(int)> GetResultCallback(int* test_result) {
    return base::BindOnce([](int* test_result, int err) { *test_result = err; },
                          test_result);
  }

  MockExecutor executor_;
  std::unique_ptr<ModemMbim> modem_;
  FakeEuiccManager euicc_manager_;
  std::unique_ptr<FakeLibmbim> libmbim_;
  std::unique_ptr<MockModemManagerProxy> modem_manager_proxy_;
};

// Initializes the modem on a non eSIM slot and expects the initialization to be
// successful.
TEST_F(ModemMbimTest, SmokeNonEuicc) {
  libmbim_->active_slot_ = kNonEuiccSlot;
  EXPECT_CALL(euicc_manager_, OnEuiccUpdated(_, _));
  EXPECT_CALL(*modem_manager_proxy_, WaitForModem(_));
  CreateModem();
  int init_result;
  modem_->Initialize(&euicc_manager_, GetResultCallback(&init_result));
  EXPECT_EQ(init_result, kModemSuccess);
}

// Initializes the modem on an eSIM slot and expects the initialization to be
// successful.
TEST_F(ModemMbimTest, SmokeEuicc) {
  EXPECT_CALL(euicc_manager_, OnEuiccUpdated(1, EuiccSlotInfo("11111111")));
  EXPECT_CALL(*modem_manager_proxy_, WaitForModem(_));
  CreateModem();
  int init_result;
  modem_->Initialize(&euicc_manager_, GetResultCallback(&init_result));
  EXPECT_EQ(init_result, kModemSuccess);
}

TEST_F(ModemMbimTest, UninhibitDuringDestruction) {
  EXPECT_CALL(*modem_manager_proxy_, ScheduleUninhibit(_));
  CreateModem();
}

TEST_F(ModemMbimTest, ProcessEuiccEvent) {
  EXPECT_CALL(*modem_manager_proxy_, WaitForModemAndInhibit(_));
  EXPECT_CALL(*libmbim_,
              MbimMessageMsUiccLowLevelAccessOpenChannelResponseParse)
      .Times(3);  // Once for reading eid during initialize, once for
                  // EuiccStep::START, and once for PENDING_NOTIFICATIONS.
  EXPECT_CALL(*libmbim_,
              MbimMessageMsUiccLowLevelAccessCloseChannelResponseParse)
      .Times(4);  // once before reading eid, once after eid, once before
                  // EuiccStep::START, once after EuiccStep::END.
  EXPECT_CALL(*modem_manager_proxy_, ScheduleUninhibit(_))
      .Times(2);  // Once during ProcessEuiccEvent(EuiccStep::END) and once
                  // during modem_ destruction.
  CreateModem();
  modem_->Initialize(&euicc_manager_, base::DoNothing());

  int start_result;
  modem_->ProcessEuiccEvent({kEuiccSlot + 1, EuiccStep::START},
                            GetResultCallback(&start_result));
  EXPECT_EQ(start_result, kModemSuccess);

  modem_->SetIsReadyStateValidForTesting(
      TRUE);  // The modem sends this as a notification before
              // PENDING_NOTIFICATIONS.
  int notifications_result;
  modem_->ProcessEuiccEvent({kEuiccSlot + 1, EuiccStep::PENDING_NOTIFICATIONS},
                            GetResultCallback(&notifications_result));
  EXPECT_EQ(notifications_result, kModemSuccess);

  int end_result;
  modem_->ProcessEuiccEvent({kEuiccSlot + 1, EuiccStep::END},
                            GetResultCallback(&end_result));
  EXPECT_EQ(end_result, kModemSuccess);
}

TEST_F(ModemMbimTest, TransmitApdu) {
  CreateModem();
  modem_->Initialize(&euicc_manager_, base::DoNothing());
  modem_->ProcessEuiccEvent({kEuiccSlot + 1, EuiccStep::START},
                            base::DoNothing());
  std::vector<uint8_t> raw_eid;
  auto cb = base::BindOnce([](std::vector<uint8_t>* raw_eid,
                              std::vector<uint8_t> resp) { *raw_eid = resp; },
                           &raw_eid);
  modem_->TransmitApdu(
      {0x80, 0xCA, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00},
      std::move(cb));  // The contents of this APDU don't matter, the libmbim_
                       // fake has been set up to send the eid as the response.
  ASSERT_EQ(raw_eid.size(), kEidApduLen + 2);  // the status word is 2 bytes

  for (int i = 0; i < kEidApduLen; ++i) {
    EXPECT_EQ(raw_eid[i], kEidApdu[i])
        << "Apdu response differs at index " << i;
  }
  EXPECT_EQ((raw_eid[raw_eid.size() - 1] << 8 | raw_eid[raw_eid.size() - 2]),
            ModemMbim::kMbimMessageSuccess);
}

}  // namespace hermes
