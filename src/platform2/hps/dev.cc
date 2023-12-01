// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Device access interface common functions.
 */

#include "hps/dev.h"

#include <optional>

#include "base/logging.h"
#include <base/strings/stringprintf.h>
#include "hps/hps_reg.h"
#include "hps/utils.h"

namespace hps {
namespace {

class WakeLockNoOpImpl : public WakeLock {
 public:
  WakeLockNoOpImpl() = default;
  ~WakeLockNoOpImpl() override = default;
  bool supports_power_management() override { return false; }
};

}  // namespace

bool DevInterface::Read(uint8_t cmd, uint8_t* data, size_t len) {
  if (this->ReadDevice(cmd, data, len)) {
    VLOG(2) << base::StringPrintf("Read: cmd: 0x%x len: %zd OK", cmd, len);
    return true;
  }
  VLOG(2) << base::StringPrintf("Read: cmd: 0x%x len: %zd FAILED", cmd, len);
  return false;
}

bool DevInterface::Write(uint8_t cmd, const uint8_t* data, size_t len) {
  if (this->WriteDevice(cmd, data, len)) {
    VLOG(2) << base::StringPrintf("Write: cmd: 0x%x len: %zd OK", cmd, len);
    return true;
  }
  VLOG(2) << base::StringPrintf("Write: cmd: 0x%x len: %zd FAILED", cmd, len);
  return false;
}

/*
 * Read 1 register.
 * Returns value read, or -1 for error.
 */
std::optional<uint16_t> DevInterface::ReadReg(HpsReg r) {
  auto reg = HpsRegInfo(r);
  uint8_t res[2];

  if (this->ReadDevice(I2cReg(r), res, sizeof(res))) {
    uint16_t ret = static_cast<uint16_t>(res[0] << 8) | res[1];
    VLOG(2) << base::StringPrintf("ReadReg: %s : 0x%.4x OK", reg->name, ret);
    return ret;
  } else {
    VLOG(2) << "ReadReg: " << reg->name << " FAILED";
    return std::nullopt;
  }
}

std::optional<std::string> DevInterface::ReadStringReg(HpsReg r, size_t len) {
  auto reg = HpsRegInfo(r);
  std::string ret(len, '\0');

  if (this->ReadDevice(I2cReg(r), reinterpret_cast<uint8_t*>(ret.data()),
                       static_cast<unsigned int>(ret.size()))) {
    auto terminator = ret.find('\0');
    if (terminator != std::string::npos) {
      ret.resize(terminator);
    }
    VLOG(2) << base::StringPrintf("ReadReg: %s (%zu bytes) OK", reg->name,
                                  ret.size());
    return ret;
  } else {
    VLOG(2) << "ReadStringReg: " << reg->name << " FAILED";
    return std::nullopt;
  }
}

/*
 * Write 1 register.
 * Returns false on failure.
 */
bool DevInterface::WriteReg(HpsReg r, uint16_t data) {
  auto reg = HpsRegInfo(r);
  uint8_t buf[2];

  buf[0] = data >> 8;
  buf[1] = data & 0xFF;

  if (this->WriteDevice(I2cReg(r), buf, sizeof(buf))) {
    VLOG(2) << base::StringPrintf("WriteReg: %s : 0x%.4x OK", reg->name, data);
    return true;
  } else {
    VLOG(2) << base::StringPrintf("WriteReg: %s : 0x%.4x FAILED", reg->name,
                                  data);
    return false;
  }
}

/*
 * Return the maximum download block size (in bytes).
 * Default is 256 bytes.
 */
size_t DevInterface::BlockSizeBytes() {
  return 256;
}

std::unique_ptr<WakeLock> DevInterface::CreateWakeLock() {
  return std::make_unique<WakeLockNoOpImpl>();
}

}  // namespace hps
