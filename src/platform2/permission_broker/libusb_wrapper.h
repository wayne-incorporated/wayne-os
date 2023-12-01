// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_LIBUSB_WRAPPER_H_
#define PERMISSION_BROKER_LIBUSB_WRAPPER_H_

#include <iostream>
#include <memory>
#include <vector>

#include <libusb-1.0/libusb.h>
#include <linux/usb/ch11.h>

#include <base/strings/stringprintf.h>

namespace permission_broker {

// Container of USB device information. The class encapsulates device
// information like Vendor ID and Product ID and abstracts the way these
// information are extracted from libusb.
struct UsbDeviceInfo {
  uint16_t vid;
  uint16_t pid;
  uint8_t device_class;

  UsbDeviceInfo() : vid(0), pid(0), device_class(LIBUSB_CLASS_VENDOR_SPEC) {}
  // Convenience overloaded constructor used when VID and PID are known at
  // instantiation time.
  UsbDeviceInfo(uint16_t vid, uint16_t pid)
      : vid(vid), pid(pid), device_class(LIBUSB_CLASS_VENDOR_SPEC) {}
  // Convenience overloaded constructor used when VID, PID, and device class are
  // known at instantiation time.
  UsbDeviceInfo(uint16_t vid, uint16_t pid, uint8_t device_class)
      : vid(vid), pid(pid), device_class(device_class) {}

  // We ignore the device class for comparison; the comparison is only based on
  // VID and PID.
  bool operator==(const UsbDeviceInfo& object) const {
    return object.vid == vid && object.pid == pid;
  }

  friend std::ostream& operator<<(std::ostream& os,
                                  const UsbDeviceInfo& object) {
    auto description =
        base::StringPrintf("vid: 0x%04x, pid: 0x%04x, class: 0x%02x",
                           object.vid, object.pid, object.device_class);
    os << description;
    return os;
  }
};

// Convenience deleter object used to manage the libusb context object. Such
// contexts require to be initialized via libusb_init() and destroyed via
// libusb_exit(). To make the lifetime more apparent we use the deleter to
// combine the raw pointer with smart pointers.
struct LibusbContextDeleter {
  void operator()(libusb_context* ctx) { libusb_exit(ctx); }
};

// Interface used to abstract the interaction with the libusb provided API. This
// API defines the required functions needed by UsbControl to be able to
// interact with the USB subsystem.
// Such abstraction is also meant to simplify testing.
class UsbDeviceInterface {
 public:
  virtual ~UsbDeviceInterface() = default;

  virtual UsbDeviceInfo GetInfo() const = 0;
  virtual uint8_t GetPort() const = 0;
  // This function implementation can return nullptr to indicate that it was not
  // possible to obtain a parent device for the represented USB device. This can
  // also be the case when, for example, the parent device is **not** a hub.
  virtual std::unique_ptr<UsbDeviceInterface> GetParent() const = 0;

  // Sets the power state to on/off depending on |enabled| of a specified port.
  // This API can only be used on HUB devices.
  virtual bool SetPowerState(bool enabled, uint16_t port) const = 0;
};

// Specialization of the UsbDeviceInterface that uses the libusb API to
// communicate with the USB peripherals.
class UsbDevice : public UsbDeviceInterface {
 public:
  // When passing a libusb_device pointer to this constructor, the ownership of
  // pointer is assigned to the new instance of UsbDevice.
  // In other words, UsbDevice will take care of ref up and ref down the object
  // respectively at construction and at destructiopn.
  explicit UsbDevice(libusb_device* device);
  UsbDevice(const UsbDevice&) = delete;
  UsbDevice& operator=(const UsbDevice&) = delete;

  ~UsbDevice() override;

  UsbDeviceInfo GetInfo() const override;
  std::unique_ptr<UsbDeviceInterface> GetParent() const override;
  uint8_t GetPort() const override;

  bool SetPowerState(bool enabled, uint16_t port) const override;

 private:
  std::unique_ptr<libusb_device, void (*)(libusb_device*)> device_;
  UsbDeviceInfo info_;
};

// Manager intended to provide an API to interact with multiple USB devices. The
// main purpose of the class is to provide search mechanisms over the list of
// connected devices.
// This interface is intended as a generalization of that for testing purposes.
class UsbDeviceManagerInterface {
 public:
  virtual ~UsbDeviceManagerInterface() = default;

  virtual std::vector<std::unique_ptr<UsbDeviceInterface>> GetDevicesByVidPid(
      uint16_t vid, uint16_t pid) = 0;
};

// Specialized implementation of UsbDeviceManagerInterface that uses libusb
// to retrieve and filter USB devices connected to CrOS.
class UsbDeviceManager : public UsbDeviceManagerInterface {
 public:
  UsbDeviceManager();
  UsbDeviceManager(const UsbDeviceManager&) = delete;
  UsbDeviceManager& operator=(const UsbDeviceManager&) = delete;

  ~UsbDeviceManager() override;

  std::vector<std::unique_ptr<UsbDeviceInterface>> GetDevicesByVidPid(
      uint16_t vid, uint16_t pid) override;

 private:
  std::unique_ptr<libusb_context, LibusbContextDeleter> context_;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_LIBUSB_WRAPPER_H_
