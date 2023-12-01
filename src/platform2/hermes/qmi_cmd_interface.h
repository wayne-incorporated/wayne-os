// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_QMI_CMD_INTERFACE_H_
#define HERMES_QMI_CMD_INTERFACE_H_

#include <cstdint>

// size of buffer into which qmi arrays are read.
constexpr int kBufferDataSize = 260;

class QmiCmdInterface {
 public:
  enum Service : uint32_t { kDms = 0x2, kUim = 0xB };
  virtual uint16_t qmi_type() const = 0;
  virtual Service service() const = 0;
  virtual ~QmiCmdInterface() = default;
};

#endif  // HERMES_QMI_CMD_INTERFACE_H_
