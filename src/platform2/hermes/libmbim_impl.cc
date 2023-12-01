//  Copyright 2022 The ChromiumOS Authors
//  Use of this source code is governed by a BSD-style license that can be
//  found in the LICENSE file.

#include <base/logging.h>

#include "hermes/libmbim_impl.h"

namespace hermes {
void LibmbimImpl::MbimDeviceNew(GFile* file,
                                GCancellable* cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data) {
  mbim_device_new(file, cancellable, callback, user_data);
}
void LibmbimImpl::MbimDeviceOpenFull(MbimDevice* self,
                                     MbimDeviceOpenFlags flags,
                                     guint timeout,
                                     GCancellable* cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data) {
  return mbim_device_open_full(self, flags, timeout, cancellable, callback,
                               user_data);
}
void LibmbimImpl::MbimDeviceCommand(MbimDevice* self,
                                    MbimMessage* message,
                                    guint timeout,
                                    GCancellable* cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data) {
  mbim_device_command(self, message, timeout, cancellable, callback, user_data);
}
MbimMessage* LibmbimImpl::MbimDeviceCommandFinish(MbimDevice* self,
                                                  GAsyncResult* res,
                                                  GError** error) {
  return mbim_device_command_finish(self, res, error);
}
gboolean LibmbimImpl::MbimMessageValidate(const MbimMessage* self,
                                          GError** error) {
  return mbim_message_validate(self, error);
}
MbimMessageType LibmbimImpl::MbimMessageGetMessageType(
    const MbimMessage* self) {
  return mbim_message_get_message_type(self);
}
gboolean LibmbimImpl::MbimMessageResponseGetResult(const MbimMessage* self,
                                                   MbimMessageType expected,
                                                   GError** error) {
  return mbim_message_response_get_result(self, expected, error);
}
gboolean LibmbimImpl::MbimMessageDeviceCapsResponseParse(
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
    GError** error) {
  return mbim_message_device_caps_response_parse(
      message, out_device_type, out_cellular_class, out_voice_class,
      out_sim_class, out_data_class, out_sms_caps, out_control_caps,
      out_max_sessions, out_custom_data_class, out_device_id, out_firmware_info,
      out_hardware_info, error);
}

gboolean LibmbimImpl::MbimDeviceCheckMsMbimexVersion(
    MbimDevice* self,
    guint8 ms_mbimex_version_major,
    guint8 ms_mbimex_version_minor) {
  return mbim_device_check_ms_mbimex_version(self, ms_mbimex_version_major,
                                             ms_mbimex_version_minor);
}

bool LibmbimImpl::GetReadyState(MbimDevice* device,
                                bool is_notification,
                                MbimMessage* notification,
                                MbimSubscriberReadyState* ready_state) {
  g_autoptr(GError) error = NULL;

  if (mbim_device_check_ms_mbimex_version(device, 3, 0)) {
    MbimSubscriberReadyStatusFlag flags =
        MBIM_SUBSCRIBER_READY_STATUS_FLAG_NONE;
    auto parser_v3 =
        is_notification
            ? &mbim_message_ms_basic_connect_v3_subscriber_ready_status_notification_parse
            : &mbim_message_ms_basic_connect_v3_subscriber_ready_status_response_parse;
    if (!parser_v3(notification, ready_state, &flags, NULL, NULL,
                   NULL, /* ready_info */
                   NULL, /* telephone_numbers_count */
                   NULL, /* telephone_numbers */
                   &error)) {
      LOG(ERROR) << __func__ << ": Failed due to error: " << error->message;
      return false;
    }
  } else {
    auto parser = is_notification
                      ? &mbim_message_subscriber_ready_status_notification_parse
                      : &mbim_message_subscriber_ready_status_response_parse;
    if (!parser(notification, ready_state,
                /* subscriber_id */ NULL,
                /* sim_iccid */ NULL,
                /* ready_info */ NULL,
                /* telephone_numbers_count */ NULL,
                /* telephone_numbers */ NULL, &error)) {
      LOG(ERROR) << __func__ << ": Failed due to error: " << error->message;
      return false;
    }
  }
  return true;
}

gboolean LibmbimImpl::MbimMessageMsBasicConnectExtensionsSysCapsResponseParse(
    const MbimMessage* message,
    guint32* out_number_of_executors,
    guint32* out_number_of_slots,
    guint32* out_concurrency,
    guint64* out_modem_id,
    GError** error) {
  return mbim_message_ms_basic_connect_extensions_sys_caps_response_parse(
      message, out_number_of_executors, out_number_of_slots, out_concurrency,
      out_modem_id, error);
}

gboolean
LibmbimImpl::MbimMessageMsBasicConnectExtensionsDeviceSlotMappingsResponseParse(
    const MbimMessage* message,
    guint32* out_map_count,
    MbimSlotArray** out_slot_map,
    GError** error) {
  return ::
      mbim_message_ms_basic_connect_extensions_device_slot_mappings_response_parse(
          message, out_map_count, out_slot_map, error);
}

gboolean
LibmbimImpl::MbimMessageMsBasicConnectExtensionsSlotInfoStatusResponseParse(
    const MbimMessage* message,
    guint32* out_slot_index,
    MbimUiccSlotState* out_state,
    GError** error) {
  return ::
      mbim_message_ms_basic_connect_extensions_slot_info_status_response_parse(
          message, out_slot_index, out_state, error);
}

gboolean LibmbimImpl::MbimMessageMsUiccLowLevelAccessOpenChannelResponseParse(
    const MbimMessage* message,
    guint32* out_status,
    guint32* out_channel,
    guint32* out_response_size,
    const guint8** out_response,
    GError** error) {
  return ::mbim_message_ms_uicc_low_level_access_open_channel_response_parse(
      message, out_status, out_channel, out_response_size, out_response, error);
}

gboolean LibmbimImpl::MbimMessageMsUiccLowLevelAccessApduResponseParse(
    const MbimMessage* message,
    guint32* out_status,
    guint32* out_response_size,
    const guint8** out_response,
    GError** error) {
  return ::mbim_message_ms_uicc_low_level_access_apdu_response_parse(
      message, out_status, out_response_size, out_response, error);
}

gboolean LibmbimImpl::MbimMessageMsUiccLowLevelAccessCloseChannelResponseParse(
    const MbimMessage* message, guint32* out_status, GError** error) {
  return ::mbim_message_ms_uicc_low_level_access_close_channel_response_parse(
      message, out_status, error);
}

}  // namespace hermes
