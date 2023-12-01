// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_CROSVM_CONTROL_IMPL_H_
#define VM_TOOLS_CONCIERGE_CROSVM_CONTROL_IMPL_H_

#include "vm_tools/concierge/crosvm_control.h"

namespace vm_tools::concierge {

class CrosvmControlImpl : public CrosvmControl {
 public:
  static void Init();

  explicit CrosvmControlImpl(const CrosvmControl&) = delete;
  CrosvmControlImpl& operator=(const CrosvmControl&) = delete;

  bool StopVm(const char* socket_path) override;
  bool SuspendVm(const char* socket_path) override;
  bool ResumeVm(const char* socket_path) override;
  bool MakeRtVm(const char* socket_path) override;
  bool SetBalloonSize(const char* socket_path, size_t num_bytes) override;
  uintptr_t MaxUsbDevices() override;
  ssize_t UsbList(const char* socket_path,
                  struct UsbDeviceEntry* entries,
                  ssize_t entries_length) override;
  bool UsbAttach(const char* socket_path,
                 uint8_t bus,
                 uint8_t addr,
                 uint16_t vid,
                 uint16_t pid,
                 const char* dev_path,
                 uint8_t* out_port) override;
  bool UsbDetach(const char* socket_path, uint8_t port) override;
  bool ModifyBattery(const char* socket_path,
                     const char* battery_type,
                     const char* property,
                     const char* target) override;
  bool ResizeDisk(const char* socket_path,
                  size_t disk_index,
                  uint64_t new_size) override;
  bool BalloonStats(const char* socket_path,
                    struct BalloonStatsFfi* stats,
                    uint64_t* actual) override;
  bool EnableVmmSwap(const char* socket_path) override;
  bool VmmSwapOut(const char* socket_path) override;
  bool VmmSwapTrim(const char* socket_path) override;
  bool DisableVmmSwap(const char* socket_path) override;
  bool VmmSwapStatus(const char* socket_path,
                     struct SwapStatus* status) override;

 private:
  CrosvmControlImpl() = default;
};

}  // namespace vm_tools::concierge

#endif  // VM_TOOLS_CONCIERGE_CROSVM_CONTROL_IMPL_H_
