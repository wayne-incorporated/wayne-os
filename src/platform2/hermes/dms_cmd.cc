// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/dms_cmd.h"

struct qmi_elem_info dms_qmi_result_ei[] = {
    {
        .data_type = QMI_UNSIGNED_2_BYTE,
        .elem_len = 1,
        .elem_size = sizeof(uint16_t),
        .offset = offsetof(struct dms_qmi_result, result),
    },
    {
        .data_type = QMI_UNSIGNED_2_BYTE,
        .elem_len = 1,
        .elem_size = sizeof(uint16_t),
        .offset = offsetof(struct dms_qmi_result, error),
    },
    {}};

struct qmi_elem_info dms_get_device_serial_numbers_req_ei[] = {{}};

struct qmi_elem_info dms_get_device_serial_numbers_resp_ei[] = {
    {
        .data_type = QMI_STRUCT,
        .elem_len = 1,
        .elem_size = sizeof(dms_qmi_result),
        .tlv_type = 0x2,
        .offset = offsetof(struct dms_get_device_serial_numbers_resp, result),
        .ei_array = dms_qmi_result_ei,
    },
    {
        .data_type = QMI_OPT_FLAG,
        .elem_len = 1,
        .elem_size = sizeof(bool),
        .tlv_type = 0x10,
        .offset =
            offsetof(struct dms_get_device_serial_numbers_resp, esn_valid),
    },
    {
        .data_type = QMI_STRING,
        .elem_len = kBufferDataSize,
        .elem_size = sizeof(uint8_t),
        .tlv_type = 0x10,
        .offset = offsetof(struct dms_get_device_serial_numbers_resp, esn),
    },
    {
        .data_type = QMI_OPT_FLAG,
        .elem_len = 1,
        .elem_size = sizeof(bool),
        .tlv_type = 0x11,
        .offset =
            offsetof(struct dms_get_device_serial_numbers_resp, imei_valid),
    },
    {
        .data_type = QMI_STRING,
        .elem_len = kBufferDataSize,
        .elem_size = sizeof(uint8_t),
        .tlv_type = 0x11,
        .offset = offsetof(struct dms_get_device_serial_numbers_resp, imei),
    },
    {}};
