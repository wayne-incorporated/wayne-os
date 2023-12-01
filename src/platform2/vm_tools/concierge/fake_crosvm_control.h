// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_FAKE_CROSVM_CONTROL_H_
#define VM_TOOLS_CONCIERGE_FAKE_CROSVM_CONTROL_H_

#include <memory>
#include <string>
#include "vm_tools/concierge/crosvm_control.h"

namespace vm_tools::concierge {

class FakeCrosvmControl : public CrosvmControl {
 public:
  static void Init();

  static FakeCrosvmControl* Get();

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

  std::string target_socket_path_ = "";

  int count_set_balloon_size_ = 0;
  int count_enable_vmm_swap_ = 0;
  int count_vmm_swap_out_ = 0;
  int count_vmm_swap_trim_ = 0;
  int count_disable_vmm_swap_ = 0;

  bool result_set_balloon_size_ = true;
  bool result_balloon_stats_ = true;
  bool result_enable_vmm_swap_ = true;
  bool result_vmm_swap_out_ = true;
  bool result_vmm_swap_trim_ = true;
  bool result_disable_vmm_swap_ = true;
  bool result_vmm_swap_status_ = true;

  uint64_t target_balloon_size_ = 0;
  uint64_t actual_balloon_size_ = 0;
  struct BalloonStatsFfi balloon_stats_;
  struct SwapStatus vmm_swap_status_;
};

}  // namespace vm_tools::concierge

#endif  // VM_TOOLS_CONCIERGE_FAKE_CROSVM_CONTROL_H_
