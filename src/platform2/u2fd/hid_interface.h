// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_HID_INTERFACE_H_
#define U2FD_HID_INTERFACE_H_

#include <string>

#include <base/functional/callback.h>

namespace u2f {

// Interface to create and manage a HID device.
// It passes output HID reports sent by the client connected to the HID device,
// and can send back input HID reports to the client.
class HidInterface {
 public:
  virtual ~HidInterface() = default;

  // Sets up the HID device. Must be called before any other method.
  // |hid_version| sets the HID interface version number as returned to clients.
  // |report_desc| contains the raw HID report descriptor.
  // Returns true on success.
  virtual bool Init(uint32_t hid_version, const std::string& report_desc) = 0;

  // Sends the HID report stored in |report| to the device client.
  // Returns true on success, false if it failed to send it.
  virtual bool SendReport(const std::string& report) = 0;

  // Callback invoked when the HID device client sends an output report.
  // The raw report prefixed by the report ID is passed in |report|.
  using OutputReportCallback =
      base::RepeatingCallback<void(const std::string& report)>;
  virtual void SetOutputReportHandler(
      const OutputReportCallback& on_output_report) = 0;
};

}  // namespace u2f

#endif  // U2FD_HID_INTERFACE_H_
