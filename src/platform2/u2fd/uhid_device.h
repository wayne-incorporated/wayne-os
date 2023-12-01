// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_UHID_DEVICE_H_
#define U2FD_UHID_DEVICE_H_

#include <memory>
#include <string>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>

#include "u2fd/hid_interface.h"

extern "C" {
#include <linux/uhid.h>
}

namespace u2f {

// Create a HID device using the /dev/uhid kernel interface.
class UHidDevice : public HidInterface {
 public:
  UHidDevice(uint32_t vendor_id,
             uint32_t product_id,
             const std::string& name,
             const std::string& phys);
  UHidDevice(const UHidDevice&) = delete;
  UHidDevice& operator=(const UHidDevice&) = delete;

  ~UHidDevice() override;

  // HidInterface implementation:
  bool Init(uint32_t hid_version, const std::string& report_desc) override;
  bool SendReport(const std::string& report) override;
  void SetOutputReportHandler(
      const HidInterface::OutputReportCallback& on_output_report) override;

 private:
  // Asks the kernel to create a new hid device node with interface |version|
  // presenting the blob |report_desc| as report descriptor.
  // Returns true on success.
  bool CreateDev(uint32_t version, const std::string& report_desc);
  // Asks the kernel to destroy the previously created hid device.
  void DestroyDev();
  // Sends to the kernel a new event |ev| on the hid device.
  // Returns true on success.
  bool WriteEvent(const struct uhid_event& ev);
  // Callback used when the kernel sends us an event on the hid device.
  void FdEvent();

  base::ScopedFD fd_;  // A file descriptor for /dev/uhid.
  bool created_;
  uint32_t vendor_id_;
  uint32_t product_id_;
  std::string name_;
  std::string phys_;

  HidInterface::OutputReportCallback on_output_report_;

  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
};

}  // namespace u2f

#endif  // U2FD_UHID_DEVICE_H_
