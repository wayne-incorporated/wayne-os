// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_CROSVM_CONTROL_H_
#define VM_TOOLS_CONCIERGE_CROSVM_CONTROL_H_

#include <crosvm/crosvm_control.h>

#include <memory>

namespace vm_tools::concierge {

// Wrapper class for the crosvm_control library.
// Provides a simple pass through to the library, but also allows for a
// mock to be injected for testing.

class CrosvmControl {
 public:
  // Returns the global instance.
  static CrosvmControl* Get();

  // Resets the global instance.
  static void Reset();

  // Stops the crosvm instance whose control socket is listening on
  // `socket_path`.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool StopVm(const char* socket_path) = 0;

  // Suspends the crosvm instance whose control socket is listening on
  // `socket_path`.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool SuspendVm(const char* socket_path) = 0;

  // Resumes the crosvm instance whose control socket is listening on
  // `socket_path`.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool ResumeVm(const char* socket_path) = 0;

  // Creates an RT vCPU for the crosvm instance whose control socket is
  // listening on `socket_path`.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool MakeRtVm(const char* socket_path) = 0;

  // Adjusts the balloon size of the crosvm instance whose control socket is
  // listening on `socket_path`.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool SetBalloonSize(const char* socket_path, size_t num_bytes) = 0;

  // Returns the maximum possible number of USB devices.
  virtual size_t MaxUsbDevices() = 0;

  // Returns all USB devices passed through the crosvm instance whose control
  // socket is listening on `socket_path`.
  //
  // The function returns the number of entries written.
  // Arguments
  //
  // `socket_path` - Path to the crosvm control socket.
  // `entries` - Pointer to an array of `UsbDeviceEntry` where the details
  //  about the attached devices will be written to.
  // `entries_length` - Number of entries in the array specified by `entries`
  //
  // Use the value returned by [`crosvm_client_max_usb_devices()`] to determine
  // the size of the input array to this function.
  virtual ssize_t UsbList(const char* socket_path,
                          struct UsbDeviceEntry* entries,
                          ssize_t entries_length) = 0;

  // Attaches an USB device to crosvm instance whose control socket is listening
  // on `socket_path`.
  //
  // The function returns the number of entries written.
  // Arguments
  //
  // `socket_path` - Path to the crosvm control socket
  // `bus` - USB device bus ID (unused)
  // `addr` - USB device address (unused)
  // `vid` - USB device vendor ID (unused)
  // `pid` - USB device product ID (unused)
  // `dev_path` - Path to the USB device (Most likely
  // `/dev/bus/usb/<bus>/<addr>`).
  // `out_port` - (optional) internal port will be written here if provided.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool UsbAttach(const char* socket_path,
                         uint8_t bus,
                         uint8_t addr,
                         uint16_t vid,
                         uint16_t pid,
                         const char* dev_path,
                         uint8_t* out_port) = 0;

  // Detaches an USB device from crosvm instance whose control socket is
  // listening on `socket_path`. `port` determines device to be detached.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool UsbDetach(const char* socket_path, uint8_t port) = 0;

  // Modifies the battery status of crosvm instance whose control socket is
  // listening on `socket_path`.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool ModifyBattery(const char* socket_path,
                             const char* battery_type,
                             const char* property,
                             const char* target) = 0;

  // Resizes the disk of the crosvm instance whose control socket is listening
  // on `socket_path`.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool ResizeDisk(const char* socket_path,
                          size_t disk_index,
                          uint64_t new_size) = 0;

  // Returns balloon stats of the crosvm instance whose control socket is
  // listening on `socket_path`.
  //
  // The parameters `stats` and `actual` are optional and will only be written
  // to if they are non-null.
  //
  // The function returns true on success or false if an error occurred.
  //
  // Note
  //
  // Entries in `BalloonStatsFfi` that are not available will be set to `-1`.
  virtual bool BalloonStats(const char* socket_path,
                            struct BalloonStatsFfi* stats,
                            uint64_t* actual) = 0;

  // Enable vmm-swap of crosvm and move all the guest memory to the staging
  // memory.
  //
  // This affects the crosvm instance whose control socket is listening on
  // `socket_path`.
  virtual bool EnableVmmSwap(const char* socket_path) = 0;

  // Swap out the staging memory to the swap file.
  //
  // This affects the crosvm instance whose control socket is listening on
  // `socket_path`.
  virtual bool VmmSwapOut(const char* socket_path) = 0;

  // Trim static pages and zero pages in the staging memory.
  //
  // This affects the crosvm instance whose control socket is listening on
  // `socket_path`.
  virtual bool VmmSwapTrim(const char* socket_path) = 0;

  // Disable vmm-swap of crosvm.
  //
  // This affects the crosvm instance whose control socket is listening on
  // `socket_path`.
  virtual bool DisableVmmSwap(const char* socket_path) = 0;

  // Returns vmm-swap status of the crosvm instance whose control socket is
  // listening on `socket_path`.
  //
  // The parameters `status`is optional and will only be written to if they are
  // non-null.
  //
  // The function returns true on success or false if an error occurred.
  virtual bool VmmSwapStatus(const char* socket_path,
                             struct SwapStatus* status) = 0;

  virtual ~CrosvmControl() = default;

 protected:
  static void SetInstance(std::unique_ptr<CrosvmControl> instance);
};

}  // namespace vm_tools::concierge

#endif  // VM_TOOLS_CONCIERGE_CROSVM_CONTROL_H_
