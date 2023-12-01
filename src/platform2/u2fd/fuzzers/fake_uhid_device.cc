// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/fuzzers/fake_uhid_device.h"

#include <base/check.h>

namespace u2f {

void FakeUHidDevice::SendOutputReport(const std::string& report) {
  CHECK(!on_output_report_.is_null());
  on_output_report_.Run(report);
}

bool FakeUHidDevice::Init(uint32_t hid_version,
                          const std::string& report_desc) {
  // Do nothing since this is a fake device.
  return true;
}

bool FakeUHidDevice::SendReport(const std::string& report) {
  // Do nothing since this is a fake device.
  return true;
}

void FakeUHidDevice::SetOutputReportHandler(
    const HidInterface::OutputReportCallback& on_output_report) {
  on_output_report_ = on_output_report;
}

}  // namespace u2f
