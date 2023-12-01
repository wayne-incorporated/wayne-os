// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/ec_usb_endpoint.h"

#include <absl/time/clock.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <libusb-1.0/libusb.h>
#include <string.h>

#include "libec/ec_command.h"

namespace ec {

int EcUsbEndpoint::FindInterfaceWithEndpoint(struct usb_endpoint* uep) {
  struct libusb_config_descriptor* conf;
  struct libusb_device* dev = uep->dev;
  int r = libusb_->get_active_config_descriptor(dev, &conf);
  if (r != LIBUSB_SUCCESS) {
    LOG(ERROR) << "get_active_config failed: " << libusb_error_name(r);
    return -1;
  }

  for (int i = 0; i < conf->bNumInterfaces; i++) {
    const struct libusb_interface* iface0 = &conf->interface[i];
    for (int j = 0; j < iface0->num_altsetting; j++) {
      const struct libusb_interface_descriptor* iface = &iface0->altsetting[j];
      for (int k = 0; k < iface->bNumEndpoints; k++) {
        const struct libusb_endpoint_descriptor* ep = &iface->endpoint[k];
        if (ep->bEndpointAddress == uep->address) {
          uep->chunk_len = ep->wMaxPacketSize;
          r = iface->bInterfaceNumber;
          libusb_->free_config_descriptor(conf);
          return r;
        }
      }
    }
  }

  libusb_->free_config_descriptor(conf);
  return -1;
}

bool EcUsbEndpoint::CheckDevice(libusb_device* dev,
                                uint16_t vid,
                                uint16_t pid) {
  struct libusb_device_descriptor desc;
  int r = libusb_->get_device_descriptor(dev, &desc);
  if (r != LIBUSB_SUCCESS) {
    LOG(ERROR) << "libusb_get_device_descriptor failed: "
               << libusb_error_name(r);
    return false;
  }

  if (vid != 0 && vid != desc.idVendor) {
    VLOG(1) << "idVendor doesn't match: " << std::hex << desc.idVendor;
    return false;
  }
  if (pid != 0 && pid != desc.idProduct) {
    VLOG(1) << "idProduct doesn't match: " << std::hex << desc.idProduct;
    return false;
  }

  return true;
}

const struct usb_endpoint& EcUsbEndpoint::GetEndpointPtr() {
  return endpoint_;
}

bool EcUsbEndpoint::AttemptInit(uint16_t vid, uint16_t pid) {
  int r = libusb_->init(nullptr);
  if (r != LIBUSB_SUCCESS) {
    LOG(ERROR) << "libusb_init failed: " << libusb_error_name(r);
    return false;
  }
  libusb_is_init_ = true;

  libusb_device** devs;
  r = libusb_->get_device_list(nullptr, &devs);
  if (r < LIBUSB_SUCCESS) {
    VLOG(1) << "No device is found: " << libusb_error_name(r);
    return false;
  }

  bool dev_found = false;
  for (int i = 0; devs[i]; i++) {
    dev_found = CheckDevice(devs[i], vid, pid);
    if (dev_found) {
      VLOG(1) << "Found device " << std::hex << vid << ":" << std::hex << pid;
      endpoint_.dev = devs[i];
      break;
    }
  }

  libusb_->free_device_list(devs, 1);

  if (!dev_found) {
    VLOG(1) << "Can't find device " << std::hex << vid << ":" << std::hex
            << pid;
    return false;
  }

  endpoint_.address = 2; /* USB_EP_HOSTCMD */

  int iface_num = FindInterfaceWithEndpoint(&endpoint_);
  if (iface_num < 0) {
    LOG(WARNING) << "USB HOSTCMD not supported by the device";
    return false;
  }

  if (!endpoint_.chunk_len) {
    LOG(ERROR) << "wMaxPacketSize isn't valid";
    return false;
  }

  endpoint_.interface_number = iface_num;

  VLOG(1) << "Found interface=" << endpoint_.interface_number
          << base::StringPrintf(" endpoint=0x%02x", endpoint_.address)
          << " chunk_len=" << endpoint_.chunk_len;

  return true;
}

bool EcUsbEndpoint::Init(uint16_t vid, uint16_t pid) {
  // Save vid and pid in case we need to use them to reinitialize the endpoint
  vid_ = vid;
  pid_ = pid;

  int retries = kDefaultInitRetries;
  bool success = AttemptInit(vid, pid);
  while (!success && retries--) {
    CleanUp();
    absl::SleepFor(absl::Milliseconds(timeout_ms_));
    success = AttemptInit(vid, pid);
  }

  if (success) {
    LOG(INFO) << "Successfully initialized USB Endpoint after retry #"
              << (max_retries_ - retries);
  } else {
    LOG(WARNING) << "Failed to initialize USB Endpoint after retry #"
                 << (max_retries_ - retries);
  }

  return success;
}

bool EcUsbEndpoint::ResetEndpoint() {
  CleanUp();

  if (!Init(vid_, pid_)) {
    LOG(ERROR) << "Failed to reset usb endpoint.";
    return false;
  }

  return true;
}

bool EcUsbEndpoint::ClaimInterface() {
  if (!OpenDeviceHandle()) {
    LOG(ERROR) << "Failed to open USB device handle";
    return false;
  }

  if (endpoint_.dev_handle == nullptr || endpoint_.interface_number == 0) {
    LOG(ERROR) << "Device handle or interface number are not set.";
    CloseDeviceHandle();
    return false;
  }

  int r = libusb_->claim_interface(endpoint_.dev_handle,
                                   endpoint_.interface_number);

  int retries = max_retries_;
  while ((r == LIBUSB_ERROR_NO_DEVICE || r == LIBUSB_ERROR_BUSY) && retries--) {
    if (r == LIBUSB_ERROR_NO_DEVICE) {
      LOG(WARNING) << "Lost USB Device. Attempting to reset the endpoint.";
      if (!ResetEndpoint()) {
        break;
      }
    }

    absl::SleepFor(absl::Milliseconds(timeout_ms_));
    r = libusb_->claim_interface(endpoint_.dev_handle,
                                 endpoint_.interface_number);
  }

  if (r != LIBUSB_SUCCESS) {
    LOG(ERROR) << "Failed to claim interface with error "
               << libusb_error_name(r) << " after retry #"
               << (max_retries_ - retries);
    CloseDeviceHandle();
    return false;
  }

  VLOG(1) << "Successfully claimed interface after retry #"
          << (max_retries_ - retries);
  return true;
}

bool EcUsbEndpoint::ReleaseInterface() {
  if (endpoint_.dev_handle == nullptr || endpoint_.interface_number == 0) {
    // We haven't claimed the interface.
    LOG(INFO) << "No need to release interface which is not claimed.";
    return true;
  }

  int r = libusb_->release_interface(endpoint_.dev_handle,
                                     endpoint_.interface_number);
  if (r != LIBUSB_SUCCESS && r != LIBUSB_ERROR_NOT_FOUND) {
    LOG(ERROR) << "libusb_release_interface failed: " << libusb_error_name(r);
    return false;
  }

  CloseDeviceHandle();
  return true;
}

bool EcUsbEndpoint::OpenDeviceHandle() {
  libusb_device_handle* handle = nullptr;
  int r = libusb_->open(endpoint_.dev, &handle);
  if (r != LIBUSB_SUCCESS) {
    LOG(ERROR) << "libusb_open failed: " << libusb_error_name(r);
    return false;
  }

  endpoint_.dev_handle = handle;
  return true;
}

void EcUsbEndpoint::CloseDeviceHandle() {
  if (endpoint_.dev_handle != nullptr) {
    libusb_->close(endpoint_.dev_handle);
  }
  endpoint_.dev_handle = nullptr;
}

void EcUsbEndpoint::CleanUp() {
  if (!libusb_is_init_)
    return;

  if (endpoint_.dev_handle) {
    if (endpoint_.interface_number)
      ReleaseInterface();
  }

  libusb_->exit(nullptr);

  libusb_is_init_ = false;
}

EcUsbEndpoint::~EcUsbEndpoint() {
  CleanUp();
}

}  // namespace ec
