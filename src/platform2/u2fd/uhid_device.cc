// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <map>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "u2fd/uhid_device.h"

namespace u2f {

namespace {

const char kUHidNode[] = "/dev/uhid";

const char* GetUhidEventName(int event) {
  switch (event) {
    case UHID_START:
      return "START";
    case UHID_STOP:
      return "STOP";
    case UHID_OPEN:
      return "OPEN";
    case UHID_CLOSE:
      return "CLOSE";
    case UHID_OUTPUT:
      return "OUTPUT";
    default:
      NOTREACHED();
      return "UNKNOWN";
  }
}

}  // namespace

UHidDevice::UHidDevice(uint32_t vendor_id,
                       uint32_t product_id,
                       const std::string& name,
                       const std::string& phys)
    : created_(false),
      vendor_id_(vendor_id),
      product_id_(product_id),
      name_(name),
      phys_(phys) {}

UHidDevice::~UHidDevice() {
  if (created_)
    DestroyDev();
}

bool UHidDevice::Init(uint32_t hid_version, const std::string& report_desc) {
  DCHECK(!fd_.is_valid());
  fd_ = base::ScopedFD(HANDLE_EINTR(open(kUHidNode, O_RDWR)));
  if (!fd_.is_valid()) {
    PLOG(ERROR) << "Cannot open uhid node at " << kUHidNode;
    return false;
  }
  VLOG(1) << kUHidNode << " opened successfully.";

  if (!CreateDev(hid_version, report_desc)) {
    LOG(ERROR) << "Cannot create HID device.";
    return false;
  }
  created_ = true;

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd_.get(),
      base::BindRepeating(&UHidDevice::FdEvent, base::Unretained(this)));
  if (!watcher_) {
    LOG(ERROR) << "Unable to watch " << kUHidNode << " events";
    return false;
  }

  return true;
}

void UHidDevice::FdEvent() {
  struct uhid_event ev;

  ssize_t ret = read(fd_.get(), &ev, sizeof(ev));
  if (ret < 0) {
    PLOG(ERROR) << "Cannot read uhid";
    return;
  }
  if (ret != sizeof(ev)) {
    LOG(ERROR) << "Read " << ret << " byte(s) from " << kUHidNode
               << "; expected " << sizeof(ev);
    return;
  }

  switch (ev.type) {
    case UHID_START:
    case UHID_STOP:
    case UHID_OPEN:
    case UHID_CLOSE:
      VLOG(2) << "uhid event " << GetUhidEventName(ev.type);
      break;
    case UHID_OUTPUT:
      VLOG(1) << "uhid event " << GetUhidEventName(ev.type);
      if (ev.u.output.rtype != UHID_OUTPUT_REPORT)
        break;
      VLOG(2) << "HID Report: "
              << base::HexEncode(ev.u.output.data, ev.u.output.size);

      if (!on_output_report_.is_null()) {
        std::string report(reinterpret_cast<char*>(ev.u.output.data),
                           ev.u.output.size);
        on_output_report_.Run(report);
      }
      break;
    default:
      LOG(WARNING) << "Invalid event from uhid: " << ev.type;
  }
}

bool UHidDevice::WriteEvent(const struct uhid_event& ev) {
  return base::WriteFileDescriptor(fd_.get(),
                                   base::as_bytes(base::make_span(&ev, 1u)));
}

bool UHidDevice::SendReport(const std::string& report) {
  if (report.size() > UINT16_MAX)
    return false;

  struct uhid_event ev = {
      .type = UHID_INPUT2,
      .u.input2.size = static_cast<uint16_t>(report.size()),
  };

  if (report.size() > sizeof(ev.u.input2.data))
    return false;

  std::copy(report.begin(), report.end(), ev.u.input2.data);

  return WriteEvent(ev) == 0;
}

bool UHidDevice::CreateDev(uint32_t interface_version,
                           const std::string& report_desc) {
  if (report_desc.size() > UINT16_MAX)
    return false;

  struct uhid_event ev = {
      .type = UHID_CREATE2,
      .u.create2.rd_size = static_cast<uint16_t>(report_desc.size()),
      .u.create2.bus = BUS_VIRTUAL,
      .u.create2.vendor = vendor_id_,
      .u.create2.product = product_id_,
      .u.create2.version = interface_version,
  };
  if (report_desc.size() > sizeof(ev.u.create2.rd_data))
    return false;

  base::strlcpy(reinterpret_cast<char*>(ev.u.create2.name), name_.c_str(),
                sizeof(ev.u.create2.name));
  snprintf(reinterpret_cast<char*>(ev.u.create2.phys),
           sizeof(ev.u.create2.phys), "%s-%04X:%04X", phys_.c_str(),
           ev.u.create2.vendor, ev.u.create2.product);
  memcpy(ev.u.create2.rd_data, report_desc.data(),
         std::min(report_desc.size(), sizeof(ev.u.create2.rd_data)));

  return WriteEvent(ev);
}

void UHidDevice::DestroyDev() {
  const struct uhid_event ev = {.type = UHID_DESTROY};

  WriteEvent(ev);
}

void UHidDevice::SetOutputReportHandler(
    const HidInterface::OutputReportCallback& on_output_report) {
  on_output_report_ = on_output_report;
}

}  // namespace u2f
