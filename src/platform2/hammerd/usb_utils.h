// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Implement the USB-related functions using sysfs and usbfs.
// The structure of sysfs:
// /sys/bus/usb/devices/
// |-- <bus>-<port>/
//     |-- idVendor
//     |-- idProduct
//     |-- configuration
//     |-- uevent
//     |-- <bus>-<port>:<config>.<interface>/
//         |-- bInterfaceNumber
//         |-- bInterfaceClass
//         |-- bInterfaceSubClass
//         |-- bInterfaceProtocol
//         |-- ep_<ep_num>/
//             |-- wMaxPacketSize

#ifndef HAMMERD_USB_UTILS_H_
#define HAMMERD_USB_UTILS_H_

#include <stdint.h>

#include <optional>
#include <string>

#include <base/files/file_path.h>

namespace hammerd {

constexpr int kUsbEndpointIn = 0x80;
constexpr int kUsbEndpointOut = 0x00;

constexpr uint8_t kUsbClassGoogleUpdate = 0xff;
constexpr uint8_t kUsbSubclassGoogleUpdate = 0x53;
constexpr uint8_t kUsbProtocolGoogleUpdate = 0xff;

// Get the path of the USB device root sysfs.
const base::FilePath GetUsbSysfsPath(const std::string& path);

enum class UsbConnectStatus {
  kSuccess,        // USB device is connected successfully.
  kUsbPathEmpty,   // Sysfs path of USB device is not found.
  kInvalidDevice,  // USB device has wrong VID/PID.
  kUnknownError,   // Other failure.
};

class UsbEndpointInterface {
 public:
  virtual ~UsbEndpointInterface() = default;

  // Check whether the USB sysfs file exist or not.
  virtual bool UsbSysfsExists() = 0;
  // Initializes the USB endpoint.
  virtual UsbConnectStatus Connect() = 0;
  // Releases USB endpoint.
  virtual void Close() = 0;
  // Returns whether the USB endpoint is initialized.
  virtual bool IsConnected() const = 0;

  // Sends the data to USB endpoint and then reads the result back.
  // Returns the byte number of the received data. -1 if the process fails, or
  // if `allow_less` is false and the received data does not match outlen.
  virtual int Transfer(const void* outbuf,
                       int outlen,
                       void* inbuf,
                       int inlen,
                       bool allow_less = false,
                       unsigned int timeout_ms = 0) = 0;
  // Sends the data to USB endpoint.
  // Returns the byte number of the received data. -1 if the process fails, or
  // if `allow_less` is false and the received data does not match outlen.
  virtual int Send(const void* outbuf,
                   int outlen,
                   bool allow_less = false,
                   unsigned int timeout_ms = 0) = 0;
  // Receives the data from USB endpoint.
  // Returns the byte number of the received data. -1 if the process fails, or
  // if `allow_less` is false and the received data does not match outlen.
  virtual int Receive(void* inbuf,
                      int inlen,
                      bool allow_less = false,
                      unsigned int timeout_ms = 0) = 0;

  // Gets the chunk length of the USB endpoint.
  virtual int GetChunkLength() const = 0;

  // Gets the configuration string of the USB endpoint.
  virtual std::string GetConfigurationString() const = 0;
};

class UsbEndpoint : public UsbEndpointInterface {
 public:
  UsbEndpoint(uint16_t vendor_id, uint16_t product_id, std::string path);
  explicit UsbEndpoint(std::string path);
  UsbEndpoint(const UsbEndpoint&) = delete;
  UsbEndpoint& operator=(const UsbEndpoint&) = delete;

  // UsbEndpointInterface:
  ~UsbEndpoint() override;
  bool UsbSysfsExists() override;
  UsbConnectStatus Connect() override;
  void Close() override;
  bool IsConnected() const override;
  int Transfer(const void* outbuf,
               int outlen,
               void* inbuf,
               int inlen,
               bool allow_less = false,
               unsigned int timeout_ms = 0) override;
  int Send(const void* outbuf,
           int outlen,
           bool allow_less = false,
           unsigned int timeout_ms = 0) override;
  int Receive(void* inbuf,
              int inlen,
              bool allow_less = false,
              unsigned int timeout_ms = 0) override;
  int GetChunkLength() const override { return chunk_len_; }
  std::string GetConfigurationString() const override {
    return configuration_string_;
  }

 private:
  // Returns the actual transfered data size.
  // If the timeout is not assigned, then use default timeout value.
  // |direction_mask| should be one of kUsbEndpointIn or kUsbEndpointOut.
  int BulkTransfer(void* buf,
                   int direction_mask,
                   int len,
                   unsigned int timeout_ms = 0);

  std::optional<uint16_t> vendor_id_;
  std::optional<uint16_t> product_id_;
  std::string path_;
  int fd_ = -1;
  std::string configuration_string_;
  int iface_num_ = -1;
  int ep_num_ = -1;
  int chunk_len_ = -1;
};

}  // namespace hammerd
#endif  // HAMMERD_USB_UTILS_H_
