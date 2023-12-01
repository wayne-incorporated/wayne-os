// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_MANAGER_H_
#define LIBBRILLO_BRILLO_USB_USB_MANAGER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>
#include <brillo/streams/stream.h>
#include <brillo/usb/usb_error.h>

struct libusb_context;

namespace brillo {

class UsbDevice;

// A USB manager for managing a USB session created by libusb 1.0.
class BRILLO_EXPORT UsbManager {
 public:
  // UsbManager watches file descriptors using
  // FileDescriptorWatcher::WatchReadable/WatchWritable, so the caller must have
  // already created a FileDescriptorWatcher for the current thread. See the
  // comments on FileDescriptorWatcher::WatchReadable for details.
  static std::unique_ptr<UsbManager> Create();

  UsbManager(const UsbManager&) = delete;
  UsbManager& operator=(const UsbManager&) = delete;

  ~UsbManager();

  // Sets the debug level of libusb to |level|.
  void SetDebugLevel(int level);

  // Gets the USB device that is currently connected to the bus numbered
  // |bus_number|, at the address |device_address| on the bus, with its vendor
  // ID equal to |vendor_id|, and its product ID equal to |product_id|. Returns
  // NULL if no such device is found. The returned UsbDevice object becomes
  // invalid, and thus should not be held, beyond the lifetime of this object.
  std::unique_ptr<UsbDevice> GetDevice(uint8_t bus_number,
                                       uint8_t device_address,
                                       uint16_t vendor_id,
                                       uint16_t product_id);

  // Gets the list of USB devices currently attached to the system. Returns true
  // on success. |devices| is always cleared before being updated. The returned
  // UsbDevice objects become invalid, and thus should not be held, beyond the
  // lifetime of this object.
  bool GetDevices(std::vector<std::unique_ptr<UsbDevice>>* devices);

  const UsbError& error() const { return error_; }

 protected:
  UsbManager();

  // Initializes a USB session via libusb. Returns true on success.
  bool Initialize();

  // Starts watching |file_descriptor| for its readiness for I/O based on |mode|
  // |callback| is invoked when |file_descriptor| is ready for I/O. Returns true
  // on success.
  bool StartWatchingFileDescriptor(int file_descriptor,
                                   brillo::Stream::AccessMode mode,
                                   const base::RepeatingClosure& callback);

  // Stops watching |file_descriptor| for its readiness for I/O. Returns true on
  // success.
  bool StopWatchingFileDescriptor(int file_descriptor);

  // Stops watching all file descriptors that have been watched via
  // StartWatchingFileDescriptor(). Returns true on success.
  void StopWatchingAllFileDescriptors();

 private:
  struct Watcher {
    std::unique_ptr<base::FileDescriptorWatcher::Controller> read_watcher;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> write_watcher;
  };

  static void OnPollFileDescriptorAdded(int file_descriptor,
                                        short events,  // NOLINT
                                        void* user_data);
  static void OnPollFileDescriptorRemoved(int file_descriptor, void* user_data);

  // Starts watching the file descriptors for libusb events. Returns true on
  // success.
  bool StartWatchingPollFileDescriptors();

  // Handles libusb events in non-blocking mode.
  void HandleEventsNonBlocking();

  libusb_context* context_;
  std::map<int, Watcher> file_descriptor_watchers_;
  UsbError error_;

  base::WeakPtrFactory<UsbManager> weak_factory_{this};
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_USB_USB_MANAGER_H_
