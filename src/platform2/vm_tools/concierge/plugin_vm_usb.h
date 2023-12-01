// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_PLUGIN_VM_USB_H_
#define VM_TOOLS_CONCIERGE_PLUGIN_VM_USB_H_

#include <stdint.h>

namespace vm_tools {
namespace concierge {

enum UsbRequestType : uint32_t {
  ATTACH_DEVICE,
  DETACH_DEVICE,
};

struct UsbCtrlRequest {
  UsbRequestType type;
  uint32_t handle;
  union {
    struct {
      uint8_t bus;
      uint8_t addr;
      uint16_t vid;
      uint16_t pid;
    } DevInfo;
    uint8_t _padding[32 - 4 - 4];
  };
};

struct UsbCtrlResponse {
  enum Status : uint32_t {
    OK,
    FAIL,
  };
  UsbRequestType type;
  uint32_t handle;
  Status status;
  uint8_t _padding[32 - 4 - 4 - 4];
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_PLUGIN_VM_USB_H_
