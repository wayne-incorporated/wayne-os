// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hammerd/usb_utils.h"

#include <fcntl.h>
#include <linux/usbdevice_fs.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include <memory>
#include <string>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

namespace hammerd {
namespace {
constexpr int kError = -1;
constexpr unsigned int kTimeoutMs = 1000;  // Default timeout value.
}  // namespace

const base::FilePath GetUsbSysfsPath(const std::string& path) {
  return base::FilePath(
      base::StringPrintf("/sys/bus/usb/devices/%s", path.c_str()));
}

static bool GetUsbDevicePath(const std::string& path, base::FilePath* out) {
  // Find the line in the uevent that starts with "DEVNAME=", and replace it
  // with "/dev/".
  const std::string devname_prefix = "DEVNAME=";
  const base::FilePath uevent_path = GetUsbSysfsPath(path).Append("uevent");
  std::string content;
  if (!base::ReadFileToString(uevent_path, &content)) {
    LOG(ERROR) << "Failed to read uevent.";
    return false;
  }
  for (const auto& line : base::SplitStringPiece(
           content, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    if (base::StartsWith(line, devname_prefix, base::CompareCase::SENSITIVE)) {
      std::string path(line.data(), line.size());
      *out = base::FilePath("/dev").Append(path.substr(devname_prefix.size()));
      return true;
    }
  }
  LOG(ERROR) << "Failed to get usbfs path.";
  return false;
}

static bool ReadFileToInt(const base::FilePath& path, int* value) {
  std::string str;
  if (!base::ReadFileToString(path, &str)) {
    return false;
  }
  base::TrimWhitespaceASCII(str, base::TRIM_ALL, &str);
  return base::HexStringToInt(str, value);
}

static bool CheckFileIntValue(const base::FilePath& path, int value) {
  int file_value;
  return ReadFileToInt(path, &file_value) && (value == file_value);
}

UsbEndpoint::UsbEndpoint(uint16_t vendor_id,
                         uint16_t product_id,
                         std::string path)
    : vendor_id_(vendor_id), product_id_(product_id), path_(path) {}

UsbEndpoint::UsbEndpoint(std::string path) : path_(path) {}

UsbEndpoint::~UsbEndpoint() {
  Close();
}

bool UsbEndpoint::UsbSysfsExists() {
  const base::FilePath usb_path = GetUsbSysfsPath(path_);
  return base::DirectoryExists(usb_path);
}

UsbConnectStatus UsbEndpoint::Connect() {
  if (IsConnected()) {
    DLOG(INFO) << "Already initialized. Ignore.";
    return UsbConnectStatus::kSuccess;
  }

  // Confirm the device has valid vendor/product ID.
  // (b/70955082): Only return |kInvalidDevice| when the VID/PID files exist but
  // aren't the expected values.  This is to prevent mis-reporting an invalid
  // device on AP suspend/resume, when the files may not yet be ready.
  if (!UsbSysfsExists()) {
    LOG(ERROR) << "USB sysfs does not exist.";
    return UsbConnectStatus::kUsbPathEmpty;
  }
  const base::FilePath usb_path = GetUsbSysfsPath(path_);
  if (vendor_id_.has_value() && product_id_.has_value()) {
    int vendor_id, product_id;

    if (!ReadFileToInt(usb_path.Append("idVendor"), &vendor_id) ||
        !ReadFileToInt(usb_path.Append("idProduct"), &product_id)) {
      LOG(ERROR) << "Failed to read VID and PID.";
      return UsbConnectStatus::kUnknownError;
    }
    if (*vendor_id_ != vendor_id || *product_id_ != product_id) {
      LOG(ERROR) << "Invalid VID and PID.";
      return UsbConnectStatus::kInvalidDevice;
    }
  }
  if (!base::ReadFileToString(usb_path.Append("configuration"),
                              &configuration_string_)) {
    LOG(ERROR) << "Failed to read configuration file.";
    return UsbConnectStatus::kUnknownError;
  }
  base::TrimWhitespaceASCII(configuration_string_, base::TRIM_ALL,
                            &configuration_string_);
  // Find the interface matching class, subclass, and protocol and the endpoint
  // number. The interface should only contain one pair of endpoints with the
  // same endpoint number, one for IN and another for OUT.
  // The endpoint address is composed of:
  // - Bits 0..6: Endpoint Number
  // - Bits 7:    Direction 0 = Out, 1 = In
  bool is_found = false;
  base::FileEnumerator iface_paths(usb_path, false,
                                   base::FileEnumerator::FileType::DIRECTORIES,
                                   base::StringPrintf("%s:*", path_.c_str()));
  for (base::FilePath iface_path = iface_paths.Next(); !iface_path.empty();
       iface_path = iface_paths.Next()) {
    if (CheckFileIntValue(iface_path.Append("bInterfaceClass"),
                          kUsbClassGoogleUpdate) &&
        CheckFileIntValue(iface_path.Append("bInterfaceSubClass"),
                          kUsbSubclassGoogleUpdate) &&
        CheckFileIntValue(iface_path.Append("bInterfaceProtocol"),
                          kUsbProtocolGoogleUpdate)) {
      if (!ReadFileToInt(iface_path.Append("bInterfaceNumber"), &iface_num_)) {
        LOG(ERROR) << "Failed to read interface number.";
        return UsbConnectStatus::kUnknownError;
      }
      if (!CheckFileIntValue(iface_path.Append("bNumEndpoints"), 2)) {
        LOG(ERROR) << "Interface should only have 2 Endpoints.";
        return UsbConnectStatus::kUnknownError;
      }
      // Get endpoint number and chunk size. Two endpoints should have the same
      // endpoint number, so just calculate it by the first one.
      base::FilePath ep_path =
          base::FileEnumerator(iface_path, false,
                               base::FileEnumerator::FileType::DIRECTORIES,
                               "ep_*")
              .Next();
      if (!ReadFileToInt(ep_path.Append("bEndpointAddress"), &ep_num_) ||
          !ReadFileToInt(ep_path.Append("wMaxPacketSize"), &chunk_len_)) {
        LOG(ERROR) << "Failed to read endpoint address and chunk size.";
        return UsbConnectStatus::kUnknownError;
      }
      ep_num_ = ep_num_ & 0x7f;  // Bit mask of 0~6 bits.
      DLOG(INFO) << "found interface " << iface_num_ << ", endpoint "
                 << static_cast<int>(ep_num_) << ", chunk_len " << chunk_len_;
      is_found = true;
      break;
    }
  }
  if (!is_found) {
    LOG(ERROR) << "Failed to find a valid interface.";
    return UsbConnectStatus::kUnknownError;
  }

  // Open the usbfs file, and claim the interface.
  base::FilePath usbfs_path;
  if (!GetUsbDevicePath(path_, &usbfs_path)) {
    return UsbConnectStatus::kUnknownError;
  }
  fd_ = open(usbfs_path.value().c_str(), O_RDWR | O_CLOEXEC);
  if (fd_ < 0) {
    PLOG(ERROR) << "Failed to open usbfs file";
    Close();
    return UsbConnectStatus::kUnknownError;
  }
  if (ioctl(fd_, USBDEVFS_CLAIMINTERFACE, &iface_num_)) {
    PLOG(ERROR) << "Failed to claim interface";
    Close();
    return UsbConnectStatus::kUnknownError;
  }
  LOG(INFO) << "USB endpoint is initialized successfully.";
  return UsbConnectStatus::kSuccess;
}

// Release USB device.
void UsbEndpoint::Close() {
  if (iface_num_ >= 0) {
    ioctl(fd_, USBDEVFS_RELEASEINTERFACE, &iface_num_);
  }
  if (fd_ != -1) {
    close(fd_);
  }
  configuration_string_ = "";
  iface_num_ = -1;
  fd_ = -1;
  ep_num_ = -1;
  chunk_len_ = -1;
}

bool UsbEndpoint::IsConnected() const {
  return (fd_ != -1);
}

int UsbEndpoint::Transfer(const void* outbuf,
                          int outlen,
                          void* inbuf,
                          int inlen,
                          bool allow_less,
                          unsigned int timeout_ms) {
  if (Send(outbuf, outlen, allow_less, timeout_ms) != outlen) {
    return kError;
  }
  if (inlen == 0) {
    return 0;
  }
  return Receive(inbuf, inlen, allow_less, timeout_ms);
}

int UsbEndpoint::Send(const void* outbuf,
                      int outlen,
                      bool allow_less,
                      unsigned int timeout_ms) {
  // BulkTransfer() does not modify the buffer while using kUsbEndpointOut
  // direction mask.
  int actual = BulkTransfer(const_cast<void*>(outbuf), kUsbEndpointOut, outlen,
                            timeout_ms);
  if (!allow_less && actual != outlen) {
    LOG(ERROR) << "Failed to send the complete data.";
  }
  return actual;
}

int UsbEndpoint::Receive(void* inbuf,
                         int inlen,
                         bool allow_less,
                         unsigned int timeout_ms) {
  int actual = BulkTransfer(inbuf, kUsbEndpointIn, inlen, timeout_ms);
  if (!allow_less && actual != inlen) {
    LOG(ERROR) << "Failed to receive the complete data.";
    return kError;
  }
  return actual;
}

int UsbEndpoint::BulkTransfer(void* buf,
                              int direction_mask,
                              int len,
                              unsigned int timeout_ms) {
  if (timeout_ms == 0) {
    timeout_ms = kTimeoutMs;
  }

  struct usbdevfs_bulktransfer bulk = {
      .ep = static_cast<unsigned int>(ep_num_ | direction_mask),
      .len = static_cast<unsigned int>(len),
      .timeout = timeout_ms,
      .data = buf};
  return ioctl(fd_, USBDEVFS_BULK, &bulk);
}

}  // namespace hammerd
