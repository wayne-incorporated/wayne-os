// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_EC_USB_ENDPOINT_H_
#define LIBEC_EC_USB_ENDPOINT_H_

#include <brillo/brillo_export.h>
#include <libusb-1.0/libusb.h>
#include <memory>
#include <utility>

#include "libec/libusb_wrapper.h"

namespace ec {

inline constexpr uint16_t kUsbVidGoogle = 0x18d1;
inline constexpr uint16_t kUsbPidCrosEc = 0x5022;

inline constexpr uint32_t kDefaultMaxRetries = 1;
inline constexpr uint32_t kDefaultTimeoutMs = 100;

inline constexpr uint32_t kDefaultInitRetries = 0;

struct usb_endpoint {
  struct libusb_device* dev = nullptr;
  struct libusb_device_handle* dev_handle = nullptr;
  int interface_number = 0;
  uint8_t address = 0;
  int chunk_len = 0;
};

class EcUsbEndpointInterface {
 public:
  virtual ~EcUsbEndpointInterface() {}

  virtual bool Init(uint16_t vid, uint16_t pid) = 0;
  virtual const struct usb_endpoint& GetEndpointPtr() = 0;
  virtual bool ClaimInterface() = 0;
  virtual bool ReleaseInterface() = 0;

 private:
  std::unique_ptr<LibusbWrapper> libusb_;
  struct usb_endpoint endpoint_;
  virtual bool CheckDevice(libusb_device* dev, uint16_t vid, uint16_t pid) = 0;
  virtual int FindInterfaceWithEndpoint(struct usb_endpoint* uep) = 0;
  virtual bool OpenDeviceHandle() = 0;
  virtual void CloseDeviceHandle() = 0;
};

class BRILLO_EXPORT EcUsbEndpoint : public EcUsbEndpointInterface {
 public:
  EcUsbEndpoint() : EcUsbEndpoint(std::make_unique<LibusbWrapper>()) {}
  explicit EcUsbEndpoint(std::unique_ptr<LibusbWrapper> libusb,
                         uint32_t max_retries = kDefaultMaxRetries,
                         uint32_t timeout_ms = kDefaultTimeoutMs)
      : libusb_(std::move(libusb)),
        max_retries_(max_retries),
        timeout_ms_(timeout_ms) {}
  ~EcUsbEndpoint();

  bool Init(uint16_t vid, uint16_t pid);
  const struct usb_endpoint& GetEndpointPtr();
  bool ClaimInterface();
  bool ReleaseInterface();

 private:
  bool CheckDevice(libusb_device* dev, uint16_t vid, uint16_t pid);
  int FindInterfaceWithEndpoint(struct usb_endpoint* uep);
  bool OpenDeviceHandle();
  void CloseDeviceHandle();
  bool AttemptInit(uint16_t vid, uint16_t pid);
  bool ResetEndpoint();
  void CleanUp();

  std::unique_ptr<LibusbWrapper> libusb_;
  struct usb_endpoint endpoint_;
  bool libusb_is_init_ = false;
  const uint32_t max_retries_;
  const uint32_t timeout_ms_;
  uint16_t vid_ = 0;
  uint16_t pid_ = 0;
};

class BRILLO_EXPORT EcUsbEndpointStub : public EcUsbEndpointInterface {
 public:
  ~EcUsbEndpointStub() {}

  bool Init(uint16_t vid, uint16_t pid) { return true; }
  const struct usb_endpoint& GetEndpointPtr() { return endpoint_; }
  bool ClaimInterface() { return true; }
  bool ReleaseInterface() { return true; }

 private:
  std::unique_ptr<LibusbWrapper> libusb_;
  struct usb_endpoint endpoint_;
  bool CheckDevice(libusb_device* dev, uint16_t vid, uint16_t pid) {
    return true;
  }
  int FindInterfaceWithEndpoint(struct usb_endpoint* uep) { return 0; }
  bool OpenDeviceHandle() { return true; }
  void CloseDeviceHandle() {}
};

}  // namespace ec

#endif  // LIBEC_EC_USB_ENDPOINT_H_
