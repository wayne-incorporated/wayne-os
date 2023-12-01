// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_SWAP_TOOL_H_
#define DEBUGD_SRC_SWAP_TOOL_H_

#include <string>

#include <brillo/errors/error.h>
#include <base/files/file_path.h>

namespace debugd {

class SwapTool {
 public:
  SwapTool() = default;
  SwapTool(const SwapTool&) = delete;
  SwapTool& operator=(const SwapTool&) = delete;

  ~SwapTool() = default;

  std::string SwapEnable(int32_t size, bool change_now) const;
  std::string SwapDisable(bool change_now) const;
  std::string SwapStartStop(bool on) const;
  std::string SwapStatus() const;
  std::string SwapSetParameter(const std::string& parameter_name,
                               int32_t parameter_value) const;

  // Zram writeback configuration.
  std::string SwapZramEnableWriteback(uint32_t size_mb) const;
  std::string SwapZramSetWritebackLimit(uint32_t num_pages) const;
  std::string SwapZramMarkIdle(uint32_t age_seconds) const;
  std::string InitiateSwapZramWriteback(uint32_t mode) const;

  // Swappiness (/proc/sys/vm/swappiness) configuration.
  std::string SwapSetSwappiness(uint32_t swappiness_value) const;

  // Kstaled swap configuration.
  bool KstaledSetRatio(brillo::ErrorPtr* error, uint8_t kstaled_ratio) const;

 private:
  static bool WriteValueToFile(const base::FilePath& file,
                               const std::string& val,
                               std::string* msg);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_SWAP_TOOL_H_
