// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_LIBUSB_WRAPPER_H_
#define LIBEC_LIBUSB_WRAPPER_H_

#include <libusb-1.0/libusb.h>

namespace ec {

class LibusbWrapper {
 public:
  virtual ~LibusbWrapper() = default;

  virtual int init(libusb_context** ctx) { return ::libusb_init(ctx); }
  virtual void exit(libusb_context* ctx) { ::libusb_exit(ctx); }
  virtual ssize_t get_device_list(libusb_context* ctx, libusb_device*** list) {
    return ::libusb_get_device_list(ctx, list);
  }
  virtual int get_device_descriptor(libusb_device* dev,
                                    struct libusb_device_descriptor* desc) {
    return ::libusb_get_device_descriptor(dev, desc);
  }
  virtual void free_device_list(libusb_device** list, int unref_devices) {
    ::libusb_free_device_list(list, unref_devices);
  }
  virtual int open(libusb_device* dev, libusb_device_handle** dev_handle) {
    return ::libusb_open(dev, dev_handle);
  }
  virtual void close(libusb_device_handle* dev_handle) {
    ::libusb_close(dev_handle);
  }
  virtual libusb_device* get_device(libusb_device_handle* dev_handle) {
    return ::libusb_get_device(dev_handle);
  }
  virtual int get_active_config_descriptor(
      libusb_device* dev, struct libusb_config_descriptor** config) {
    return ::libusb_get_active_config_descriptor(dev, config);
  }
  virtual void free_config_descriptor(struct libusb_config_descriptor* config) {
    ::libusb_free_config_descriptor(config);
  }
  virtual int claim_interface(libusb_device_handle* dev_handle,
                              int interface_number) {
    return ::libusb_claim_interface(dev_handle, interface_number);
  }
  virtual int release_interface(libusb_device_handle* dev_handle,
                                int interface_number) {
    return ::libusb_release_interface(dev_handle, interface_number);
  }
};

}  // namespace ec

#endif  // LIBEC_LIBUSB_WRAPPER_H_
