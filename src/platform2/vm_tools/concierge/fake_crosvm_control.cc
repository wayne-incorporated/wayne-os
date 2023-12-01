// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/fake_crosvm_control.h"

#include <base/memory/ptr_util.h>

namespace vm_tools::concierge {

void FakeCrosvmControl::Init() {
  CrosvmControl::SetInstance(base::WrapUnique(new FakeCrosvmControl()));
}

FakeCrosvmControl* FakeCrosvmControl::Get() {
  return reinterpret_cast<FakeCrosvmControl*>(CrosvmControl::Get());
}

bool FakeCrosvmControl::StopVm(const char* socket_path) {
  target_socket_path_ = socket_path;
  return true;
}

bool FakeCrosvmControl::SuspendVm(const char* socket_path) {
  target_socket_path_ = socket_path;
  return true;
}

bool FakeCrosvmControl::ResumeVm(const char* socket_path) {
  target_socket_path_ = socket_path;
  return true;
}

bool FakeCrosvmControl::MakeRtVm(const char* socket_path) {
  target_socket_path_ = socket_path;
  return true;
}

bool FakeCrosvmControl::SetBalloonSize(const char* socket_path,
                                       size_t num_bytes) {
  target_socket_path_ = socket_path;
  target_balloon_size_ = num_bytes;
  count_set_balloon_size_ += 1;
  return result_set_balloon_size_;
}

uintptr_t FakeCrosvmControl::MaxUsbDevices() {
  return 0;
}

ssize_t FakeCrosvmControl::UsbList(const char* socket_path,
                                   struct UsbDeviceEntry* entries,
                                   ssize_t entries_length) {
  target_socket_path_ = socket_path;
  return 0;
}

bool FakeCrosvmControl::UsbAttach(const char* socket_path,
                                  uint8_t bus,
                                  uint8_t addr,
                                  uint16_t vid,
                                  uint16_t pid,
                                  const char* dev_path,
                                  uint8_t* out_port) {
  target_socket_path_ = socket_path;
  return true;
}

bool FakeCrosvmControl::UsbDetach(const char* socket_path, uint8_t port) {
  target_socket_path_ = socket_path;
  return true;
}

bool FakeCrosvmControl::ModifyBattery(const char* socket_path,
                                      const char* battery_type,
                                      const char* property,
                                      const char* target) {
  target_socket_path_ = socket_path;
  return true;
}

bool FakeCrosvmControl::ResizeDisk(const char* socket_path,
                                   size_t disk_index,
                                   uint64_t new_size) {
  target_socket_path_ = socket_path;
  return true;
}

bool FakeCrosvmControl::BalloonStats(const char* socket_path,
                                     struct BalloonStatsFfi* stats,
                                     uint64_t* actual) {
  target_socket_path_ = socket_path;
  *actual = actual_balloon_size_;
  *stats = balloon_stats_;
  return result_balloon_stats_;
}

bool FakeCrosvmControl::EnableVmmSwap(const char* socket_path) {
  target_socket_path_ = socket_path;
  count_enable_vmm_swap_ += 1;
  return result_enable_vmm_swap_;
}

bool FakeCrosvmControl::VmmSwapOut(const char* socket_path) {
  target_socket_path_ = socket_path;
  count_vmm_swap_out_ += 1;
  return result_vmm_swap_out_;
}

bool FakeCrosvmControl::VmmSwapTrim(const char* socket_path) {
  target_socket_path_ = socket_path;
  count_vmm_swap_trim_ += 1;
  return result_vmm_swap_trim_;
}

bool FakeCrosvmControl::DisableVmmSwap(const char* socket_path) {
  target_socket_path_ = socket_path;
  count_disable_vmm_swap_ += 1;
  return result_disable_vmm_swap_;
}

bool FakeCrosvmControl::VmmSwapStatus(const char* socket_path,
                                      struct SwapStatus* status) {
  target_socket_path_ = socket_path;
  *status = vmm_swap_status_;
  return result_vmm_swap_status_;
}

}  // namespace vm_tools::concierge
