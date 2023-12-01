/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/tests/usb_dfu_device.h"

#include <libusb-1.0/libusb.h>

#include <algorithm>
#include <optional>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/numerics/safe_conversions.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>

#define DFU_DETACH 0
#define DFU_DNLOAD 1
#define DFU_UPLOAD 2
#define DFU_GETSTATUS 3
#define DFU_CLRSTATUS 4
#define DFU_GETSTATE 5
#define DFU_ABORT 6

namespace cros {

namespace {

constexpr unsigned int kTransferTimeoutMs = 1000;

constexpr uint8_t kRequestTypeIn =
    LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE;
constexpr uint8_t kRequestTypeOut = LIBUSB_ENDPOINT_OUT |
                                    LIBUSB_REQUEST_TYPE_CLASS |
                                    LIBUSB_RECIPIENT_INTERFACE;

const libusb_interface_descriptor* FindDfuInterface(
    const libusb_config_descriptor* config_desc) {
  const libusb_interface_descriptor* dfu_intf_desc = nullptr;
  for (uint8_t i = 0; i < config_desc->bNumInterfaces; ++i) {
    // Assume the DFU interface has no alternate settings.
    const libusb_interface_descriptor& intf_desc =
        config_desc->interface[i].altsetting[0];
    if (intf_desc.bInterfaceClass == 0xFE /* Application */ &&
        intf_desc.bInterfaceSubClass == 0x01 /* Device Firmware Upgrade */) {
      constexpr int kDfuDescriptorLength = 9;
      if (intf_desc.extra_length != kDfuDescriptorLength) {
        LOG(ERROR) << "Incorrect DFU functional descriptor length: "
                   << intf_desc.extra_length;
        return nullptr;
      }
      if (dfu_intf_desc) {
        LOG(ERROR) << "Found multiple DFU interfaces";
        return nullptr;
      }
      if (config_desc->interface[i].num_altsetting > 1) {
        LOG(ERROR) << "Found alternate settings for the DFU interface";
        return nullptr;
      }
      dfu_intf_desc = &intf_desc;
    }
  }
  return dfu_intf_desc;
}

uint16_t ParseUint16(const unsigned char* data) {
  return (base::strict_cast<uint16_t>(data[1]) << 8) |
         base::strict_cast<uint16_t>(data[0]);
}

uint32_t ParseUint24(const unsigned char* data) {
  return (base::strict_cast<uint32_t>(data[2]) << 16) |
         (base::strict_cast<uint32_t>(data[1]) << 8) |
         base::strict_cast<uint32_t>(data[0]);
}

}  // namespace

std::unique_ptr<UsbContext> UsbContext::Create() {
  libusb_context* ctx;
  int ret = libusb_init(&ctx);
  if (ret != 0) {
    LOG(ERROR) << "Failed to initialize libusb context";
    return nullptr;
  }
  return std::make_unique<UsbContext>(ctx);
}

UsbContext::~UsbContext() {
  libusb_exit(ctx_);
}

std::unique_ptr<UsbDfuDevice> UsbContext::CreateUsbDfuDevice(uint16_t vid,
                                                             uint16_t pid,
                                                             uint32_t quirks) {
  libusb_device_handle* handle =
      libusb_open_device_with_vid_pid(ctx_, vid, pid);
  if (!handle) {
    return nullptr;
  }
  base::ScopedClosureRunner handle_deleter(
      base::BindOnce(libusb_close, handle));

  libusb_device* device = libusb_get_device(handle);
  libusb_device_descriptor dev_desc;
  int ret = libusb_get_device_descriptor(device, &dev_desc);
  if (ret != 0) {
    LOG(ERROR) << "Failed to get device descriptor: " << libusb_error_name(ret);
    return nullptr;
  }

  libusb_config_descriptor* config_desc;
  ret = libusb_get_active_config_descriptor(device, &config_desc);
  if (ret != 0) {
    LOG(ERROR) << "Failed to get active configuration descriptor: "
               << libusb_error_name(ret);
    return nullptr;
  }
  base::ScopedClosureRunner config_desc_deleter(
      base::BindOnce(libusb_free_config_descriptor, config_desc));

  const libusb_interface_descriptor* intf_desc = FindDfuInterface(config_desc);
  if (!intf_desc) {
    LOG(ERROR) << "DFU interface descriptor not found";
    return nullptr;
  }

  ret = libusb_claim_interface(handle, intf_desc->bInterfaceNumber);
  if (ret != 0) {
    LOG(ERROR) << "Failed to claim interface: " << libusb_error_name(ret);
    return nullptr;
  }

  handle_deleter.ReplaceClosure(base::DoNothing());
  return std::make_unique<UsbDfuDevice>(handle, dev_desc, *intf_desc, quirks);
}

UsbDfuDevice::UsbDfuDevice(libusb_device_handle* handle,
                           const libusb_device_descriptor& dev_desc,
                           const libusb_interface_descriptor& intf_desc,
                           uint32_t quirks)
    : handle_(handle),
      bcd_device_(dev_desc.bcdDevice),
      is_dfu_mode_(intf_desc.bInterfaceProtocol == 0x02),
      interface_number_(
          base::strict_cast<uint16_t>(intf_desc.bInterfaceNumber)),
      attributes_(base::strict_cast<uint8_t>(intf_desc.extra[2])),
      detach_timeout_(ParseUint16(intf_desc.extra + 3)),
      transfer_size_(ParseUint16(intf_desc.extra + 5)),
      quirks_(quirks) {
  if (quirks_ & kDfuQuirkIgnoreUpload) {
    attributes_ &= ~kCanUpload;
  }
}

UsbDfuDevice::~UsbDfuDevice() {
  int ret = libusb_release_interface(handle_,
                                     base::strict_cast<int>(interface_number_));
  // Suppress error logs when the underlying device has gone, which happens
  // after some DFU operations.
  if (ret != 0 && ret != LIBUSB_ERROR_NO_DEVICE) {
    LOG(ERROR) << "Failed to release interface: " << libusb_error_name(ret);
  }
  libusb_close(handle_);
}

bool UsbDfuDevice::Detach() const {
  int ret = libusb_control_transfer(handle_,
                                    /*bmRequestType=*/kRequestTypeOut,
                                    /*bRequest=*/DFU_DETACH,
                                    /*wValue=*/detach_timeout_,
                                    /*wIndex=*/interface_number_,
                                    /*data=*/nullptr,
                                    /*wLength=*/0, kTransferTimeoutMs);
  if (ret < 0) {
    LOG(ERROR) << "DFU_DETACH failed: " << libusb_error_name(ret);
    return false;
  }
  if (attributes_ & kWillDetach) {
    return true;
  }
  return Reset();
}

bool UsbDfuDevice::Download(base::span<const unsigned char> firmware) const {
  if (!(attributes_ & kCanDownload)) {
    LOG(ERROR) << "Device doesn't support download";
    return false;
  }
  auto state = GetState();
  if (!state) {
    return {};
  }
  if (*state != 0x02 /* dfuIDLE */) {
    LOG(ERROR) << "Expected device in dfuIDLE(2) state but in "
               << base::strict_cast<unsigned int>(*state);
    return {};
  }
  size_t transferred_size = 0;
  uint16_t block_num = 0;
  while (transferred_size < firmware.size()) {
    uint16_t block_size = base::checked_cast<uint16_t>(
        std::min(base::strict_cast<size_t>(transfer_size_),
                 firmware.size() - transferred_size));
    VLOG(1) << "Downloading block " << block_num << " of size " << block_size
            << " (" << transferred_size << "/" << firmware.size() << ")";
    int ret = libusb_control_transfer(
        handle_,
        /*bmRequestType=*/kRequestTypeOut,
        /*bRequest=*/DFU_DNLOAD,
        /*wValue=*/block_num,
        /*wIndex=*/interface_number_,
        /*data=*/const_cast<unsigned char*>(firmware.data()) + transferred_size,
        /*wLength=*/block_size, kTransferTimeoutMs);
    if (ret < 0) {
      LOG(ERROR) << "DFU_DNLOAD failed: " << libusb_error_name(ret);
      return false;
    }
    if (ret != base::strict_cast<int>(block_size)) {
      LOG(ERROR) << "DFU_DNLOAD transferred unexpected number of bytes: "
                 << ret;
      return false;
    }
    if (!SyncDownload()) {
      LOG(ERROR) << "Failed to sync DFU_DNLOAD request";
      return false;
    }
    ++block_num;
    transferred_size += base::strict_cast<size_t>(block_size);
  }
  DCHECK_EQ(transferred_size, firmware.size());

  int ret = libusb_control_transfer(handle_,
                                    /*bmRequestType=*/kRequestTypeOut,
                                    /*bRequest=*/DFU_DNLOAD,
                                    /*wValue=*/block_num,
                                    /*wIndex=*/interface_number_,
                                    /*data=*/nullptr,
                                    /*wLength=*/0, kTransferTimeoutMs);
  if (ret < 0) {
    LOG(ERROR) << "DFU_DNLOAD failed: " << libusb_error_name(ret);
    return false;
  }
  if (!SyncManifest()) {
    LOG(ERROR) << "Failed to sync manifestation";
    return false;
  }
  return true;
}

std::vector<unsigned char> UsbDfuDevice::Upload() const {
  if (!(attributes_ & kCanUpload)) {
    LOG(ERROR) << "Device doesn't support upload";
    return {};
  }
  auto state = GetState();
  if (!state) {
    return {};
  }
  if (*state != 0x02 /* dfuIDLE */) {
    LOG(ERROR) << "Expected device in dfuIDLE(2) state but in "
               << base::strict_cast<unsigned int>(*state);
    return {};
  }
  std::vector<unsigned char> firmware;
  size_t transferred_size = 0;
  uint16_t block_num = 0;
  while (true) {
    DCHECK_EQ(firmware.size(), transferred_size);
    firmware.resize(transferred_size + transfer_size_);
    int ret =
        libusb_control_transfer(handle_,
                                /*bmRequestType=*/kRequestTypeIn,
                                /*bRequest=*/DFU_UPLOAD,
                                /*wValue=*/block_num,
                                /*wIndex=*/interface_number_,
                                /*data=*/&firmware[transferred_size],
                                /*wLength=*/transfer_size_, kTransferTimeoutMs);
    if (ret < 0) {
      LOG(ERROR) << "DFU_UPLOAD failed: " << libusb_error_name(ret);
      return {};
    }
    size_t block_size = base::checked_cast<size_t>(ret);
    if (block_size > base::strict_cast<size_t>(transfer_size_)) {
      LOG(ERROR) << "DFU_UPLOAD transferred unexpected number of bytes: "
                 << block_size;
      return {};
    }
    ++block_num;
    transferred_size += block_size;
    VLOG(1) << "Uploaded block " << block_num << " of size " << block_size
            << " (" << transferred_size << ")";
    if (block_size < base::strict_cast<size_t>(transfer_size_)) {
      firmware.resize(transferred_size);
      break;
    }
  }
  DCHECK_EQ(firmware.size(), transferred_size);
  return firmware;
}

bool UsbDfuDevice::Attach() const {
  return (quirks_ & kDfuQuirkDetachForAttach) ? Detach() : Reset();
}

bool UsbDfuDevice::Reset() const {
  int ret = libusb_reset_device(handle_);
  if (ret < 0 && ret != LIBUSB_ERROR_NOT_FOUND) {
    LOG(ERROR) << "Failed to reset USB device: " << libusb_error_name(ret);
    return false;
  }
  return true;
}

std::optional<DfuStatus> UsbDfuDevice::GetStatus() const {
  unsigned char data[6];
  int ret =
      libusb_control_transfer(handle_,
                              /*bmRequestType=*/kRequestTypeIn,
                              /*bRequest=*/DFU_GETSTATUS,
                              /*wValue=*/0,
                              /*wIndex=*/interface_number_, data,
                              /*wLength=*/sizeof(data), kTransferTimeoutMs);
  if (ret < 0) {
    LOG(ERROR) << "DFU_GETSTATUS failed: " << libusb_error_name(ret);
    return std::nullopt;
  }
  if (ret != base::checked_cast<int>(sizeof(data))) {
    LOG(ERROR) << "DFU_GETSTATUS transferred unexpected number of bytes: "
               << ret;
    return std::nullopt;
  }
  return DfuStatus{
      .status = base::strict_cast<uint8_t>(data[0]),
      .state = base::strict_cast<uint8_t>(data[4]),
      .poll_timeout = ParseUint24(data + 1),
  };
}

std::optional<uint8_t> UsbDfuDevice::GetState() const {
  unsigned char data[1];
  int ret =
      libusb_control_transfer(handle_,
                              /*bmRequestType=*/kRequestTypeIn,
                              /*bRequest=*/DFU_GETSTATE,
                              /*wValue=*/0,
                              /*wIndex=*/interface_number_, data,
                              /*wLength=*/sizeof(data), kTransferTimeoutMs);
  if (ret < 0) {
    LOG(ERROR) << "DFU_GETSTATE failed: " << libusb_error_name(ret);
    return std::nullopt;
  }
  if (ret != base::checked_cast<int>(sizeof(data))) {
    LOG(ERROR) << "DFU_GETSTATE transferred unexpected number of bytes: "
               << ret;
    return std::nullopt;
  }
  return base::strict_cast<uint8_t>(data[0]);
}

bool UsbDfuDevice::SyncDownload() const {
  constexpr base::TimeDelta kTimeout = base::Seconds(1);

  base::ElapsedTimer timer;
  std::optional<DfuStatus> status;
  while (true) {
    status = GetStatus();
    if (!status) {
      return false;
    }
    if (status->status != 0x00 /* OK */) {
      LOG(ERROR) << "Got error status: "
                 << base::strict_cast<unsigned int>(status->status);
      return false;
    }
    if (status->state == 0x05 /* dfuDNLOAD-IDLE */) {
      break;
    } else if (status->state != 0x04 /* dfuDNBUSY */) {
      LOG(ERROR) << "Unexpected state: "
                 << base::strict_cast<unsigned int>(status->state);
      return false;
    }
    if (timer.Elapsed() > kTimeout) {
      LOG(ERROR) << "Timed out syncing download";
      // TODO(kamesan): Send DFU_ABORT to get back to dfuIDLE if needed.
      return false;
    }
    VLOG(1) << "Poll timeout = " << status->poll_timeout;
    base::PlatformThread::Sleep(
        base::Milliseconds(base::strict_cast<int64_t>(status->poll_timeout)));
  }
  return true;
}

bool UsbDfuDevice::SyncManifest() const {
  constexpr base::TimeDelta kTimeout = base::Seconds(15);

  // TODO(kamesan): Support non-bitManifestationTolerant devices when needed.
  // Some devices still work but not setting this flag.
  if (!(attributes_ & kManifestationTolerant)) {
    LOG(WARNING) << "Device doesn't have bitManifestationTolerant attribute";
  }
  base::ElapsedTimer timer;
  std::optional<DfuStatus> status;
  while (true) {
    status = GetStatus();
    if (!status) {
      return false;
    }
    if (status->status != 0x00 /* OK */) {
      LOG(ERROR) << "Got error status: "
                 << base::strict_cast<unsigned int>(status->status);
      return false;
    }
    if (status->state == 0x02 /* dfuIDLE */) {
      break;
    } else if (status->state != 0x07 /* dfuMANIFEST */) {
      LOG(ERROR) << "Unexpected state: "
                 << base::strict_cast<unsigned int>(status->state);
      return false;
    }
    if (timer.Elapsed() > kTimeout) {
      LOG(ERROR) << "Timed out syncing download";
      // TODO(kamesan): Send DFU_ABORT to get back to dfuIDLE if needed.
      return false;
    }
    VLOG(1) << "Poll timeout = " << status->poll_timeout;
    base::PlatformThread::Sleep(
        base::Milliseconds(base::strict_cast<int64_t>(status->poll_timeout)));
  }
  return true;
}

}  // namespace cros
