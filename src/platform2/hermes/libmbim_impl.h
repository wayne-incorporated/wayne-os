//  Copyright 2022 The ChromiumOS Authors
//  Use of this source code is governed by a BSD-style license that can be
//  found in the LICENSE file.

#ifndef HERMES_LIBMBIM_IMPL_H_
#define HERMES_LIBMBIM_IMPL_H_

#include "hermes/libmbim_interface.h"

namespace hermes {

class LibmbimImpl : public LibmbimInterface {
 public:
  void MbimDeviceNew(GFile* file,
                     GCancellable* cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data) override;
  MbimDevice* MbimDeviceNewFinish(GAsyncResult* res, GError** error) override {
    return ::mbim_device_new_finish(res, error);
  };
  virtual ~LibmbimImpl() = default;
  void MbimDeviceOpenFull(MbimDevice* self,
                          MbimDeviceOpenFlags flags,
                          guint timeout,
                          GCancellable* cancellable,
                          GAsyncReadyCallback callback,
                          gpointer user_data) override;
  void MbimDeviceCommand(MbimDevice* self,
                         MbimMessage* message,
                         guint timeout,
                         GCancellable* cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data) override;
  MbimMessage* MbimDeviceCommandFinish(MbimDevice* self,
                                       GAsyncResult* res,
                                       GError** error) override;
  gboolean MbimMessageValidate(const MbimMessage* self,
                               GError** error) override;
  MbimMessageType MbimMessageGetMessageType(const MbimMessage* self) override;
  gboolean MbimMessageResponseGetResult(const MbimMessage* self,
                                        MbimMessageType expected,
                                        GError** error) override;
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
      GError** error) override;

  gboolean MbimDeviceCheckMsMbimexVersion(
      MbimDevice* self,
      guint8 ms_mbimex_version_major,
      guint8 ms_mbimex_version_minor) override;
  bool GetReadyState(MbimDevice* device,
                     bool is_notification,
                     MbimMessage* notification,
                     MbimSubscriberReadyState* ready_state) override;
  gboolean MbimMessageMsBasicConnectExtensionsSysCapsResponseParse(
      const MbimMessage* message,
      guint32* out_number_of_executors,
      guint32* out_number_of_slots,
      guint32* out_concurrency,
      guint64* out_modem_id,
      GError** error) override;
  gboolean MbimMessageMsBasicConnectExtensionsDeviceSlotMappingsResponseParse(
      const MbimMessage* message,
      guint32* out_map_count,
      MbimSlotArray** out_slot_map,
      GError** error) override;
  gboolean MbimMessageMsBasicConnectExtensionsSlotInfoStatusResponseParse(
      const MbimMessage* message,
      guint32* out_slot_index,
      MbimUiccSlotState* out_state,
      GError** error) override;
  gboolean MbimMessageMsUiccLowLevelAccessOpenChannelResponseParse(
      const MbimMessage* message,
      guint32* out_status,
      guint32* out_channel,
      guint32* out_response_size,
      const guint8** out_response,
      GError** error) override;
  gboolean MbimMessageMsUiccLowLevelAccessApduResponseParse(
      const MbimMessage* message,
      guint32* out_status,
      guint32* out_response_size,
      const guint8** out_response,
      GError** error) override;
  gboolean MbimMessageMsUiccLowLevelAccessCloseChannelResponseParse(
      const MbimMessage* message, guint32* out_status, GError** error) override;
};
}  // namespace hermes

#endif  // HERMES_LIBMBIM_IMPL_H_
