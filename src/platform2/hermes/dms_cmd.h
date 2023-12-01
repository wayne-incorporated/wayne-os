// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_DMS_CMD_H_
#define HERMES_DMS_CMD_H_

#include <cstdint>

#include <base/check.h>
#include <base/logging.h>
#include <libqrtr.h>

#include "hermes/qmi_cmd_interface.h"

class DmsCmd : public QmiCmdInterface {
 public:
  enum QmiType : uint16_t {
    kGetDeviceSerialNumbers = 0x25,
  };

  explicit DmsCmd(QmiType qmi_type)
      : service_(Service::kDms), qmi_type_(qmi_type) {}

  uint16_t qmi_type() const override {
    return static_cast<uint16_t>(qmi_type_);
  }

  Service service() const override { return service_; }

  const char* ToString() {
    switch (qmi_type_) {
      case QmiType::kGetDeviceSerialNumbers:
        return "GetDeviceSerialNumbers";
      default:
        CHECK(false) << "Unrecognized value: "
                     << static_cast<uint16_t>(qmi_type_);
        return "";
    }
  }

 private:
  Service service_;
  QmiType qmi_type_;
};

struct dms_qmi_result {
  uint16_t result;
  uint16_t error;
};

struct dms_get_device_serial_numbers_req {};

struct dms_get_device_serial_numbers_resp {
  dms_qmi_result result;
  bool esn_valid;
  char esn[kBufferDataSize];
  bool imei_valid;
  char imei[kBufferDataSize];
};

extern struct qmi_elem_info dms_get_device_serial_numbers_req_ei[];
extern struct qmi_elem_info dms_get_device_serial_numbers_resp_ei[];

#endif  // HERMES_DMS_CMD_H_
