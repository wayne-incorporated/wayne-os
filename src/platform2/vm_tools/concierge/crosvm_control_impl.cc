// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/crosvm_control_impl.h"

#include <base/memory/ptr_util.h>

#include <memory>

namespace vm_tools::concierge {

void CrosvmControlImpl::Init() {
  SetInstance(base::WrapUnique(new CrosvmControlImpl()));
}

bool CrosvmControlImpl::StopVm(const char* socket_path) {
  return crosvm_client_stop_vm(socket_path);
}

bool CrosvmControlImpl::SuspendVm(const char* socket_path) {
  return crosvm_client_suspend_vm(socket_path);
}

bool CrosvmControlImpl::ResumeVm(const char* socket_path) {
  return crosvm_client_resume_vm(socket_path);
}

bool CrosvmControlImpl::MakeRtVm(const char* socket_path) {
  return crosvm_client_make_rt_vm(socket_path);
}

bool CrosvmControlImpl::SetBalloonSize(const char* socket_path,
                                       size_t num_bytes) {
  return crosvm_client_balloon_vms(socket_path, num_bytes);
}

uintptr_t CrosvmControlImpl::MaxUsbDevices() {
  return crosvm_client_max_usb_devices();
}

ssize_t CrosvmControlImpl::UsbList(const char* socket_path,
                                   struct UsbDeviceEntry* entries,
                                   ssize_t entries_length) {
  return crosvm_client_usb_list(socket_path, entries, entries_length);
}

bool CrosvmControlImpl::UsbAttach(const char* socket_path,
                                  uint8_t bus,
                                  uint8_t addr,
                                  uint16_t vid,
                                  uint16_t pid,
                                  const char* dev_path,
                                  uint8_t* out_port) {
  return crosvm_client_usb_attach(socket_path, bus, addr, vid, pid, dev_path,
                                  out_port);
}

bool CrosvmControlImpl::UsbDetach(const char* socket_path, uint8_t port) {
  return crosvm_client_usb_detach(socket_path, port);
}

bool CrosvmControlImpl::ModifyBattery(const char* socket_path,
                                      const char* battery_type,
                                      const char* property,
                                      const char* target) {
  return crosvm_client_modify_battery(socket_path, battery_type, property,
                                      target);
}

bool CrosvmControlImpl::ResizeDisk(const char* socket_path,
                                   size_t disk_index,
                                   uint64_t new_size) {
  return crosvm_client_resize_disk(socket_path, disk_index, new_size);
}

bool CrosvmControlImpl::BalloonStats(const char* socket_path,
                                     struct BalloonStatsFfi* stats,
                                     uint64_t* actual) {
  return crosvm_client_balloon_stats(socket_path, stats, actual);
}

bool CrosvmControlImpl::EnableVmmSwap(const char* socket_path) {
  return crosvm_client_swap_enable_vm(socket_path);
}

bool CrosvmControlImpl::VmmSwapOut(const char* socket_path) {
  return crosvm_client_swap_swapout_vm(socket_path);
}

bool CrosvmControlImpl::VmmSwapTrim(const char* socket_path) {
  return crosvm_client_swap_trim(socket_path);
}

bool CrosvmControlImpl::DisableVmmSwap(const char* socket_path) {
  return crosvm_client_swap_disable_vm(socket_path);
}

bool CrosvmControlImpl::VmmSwapStatus(const char* socket_path,
                                      struct SwapStatus* status) {
  return crosvm_client_swap_status(socket_path, status);
}

}  // namespace vm_tools::concierge
