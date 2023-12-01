// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Access via MCP2221A device.
 */
#ifndef HPS_HAL_MCP_H_
#define HPS_HAL_MCP_H_

#include <memory>

#include <libusb-1.0/libusb.h>

#include "hps/dev.h"

namespace hps {

inline static constexpr int kMcpTransferSize = 64;  // Transfer buffer size

class Mcp : public DevInterface {
 public:
  ~Mcp() override;
  void Close();
  bool ReadDevice(uint8_t cmd, uint8_t* data, size_t len) override;
  bool WriteDevice(uint8_t cmd, const uint8_t* data, size_t len) override;
  size_t BlockSizeBytes() override;
  static std::unique_ptr<DevInterface> Create(uint8_t address,
                                              uint32_t speedKHz);

 private:
  explicit Mcp(uint8_t addr)
      : address_(static_cast<uint8_t>(addr << 1)),
        div_(0),
        context_(nullptr),
        handle_(nullptr) {}
  bool Init(uint32_t speedKHz);
  bool PrepareBus();
  bool Cmd();
  void Clear();

  uint8_t address_;
  uint8_t div_;
  libusb_context* context_;
  libusb_device_handle* handle_;
  uint8_t in_[kMcpTransferSize];
  uint8_t out_[kMcpTransferSize];
};

}  // namespace hps

#endif  // HPS_HAL_MCP_H_
