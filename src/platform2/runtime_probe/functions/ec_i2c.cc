// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/ec_i2c.h"

#include <fcntl.h>

#include <utility>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/strings/stringprintf.h>
#include <base/values.h>
#include <libec/i2c_read_command.h>

namespace runtime_probe {

namespace {
constexpr int kEcCmdNumAttempts = 10;
}  // namespace

std::unique_ptr<ec::I2cReadCommand> EcI2cFunction::GetI2cReadCommand() const {
  return ec::I2cReadCommand::Create(
      static_cast<uint8_t>(i2c_bus_), static_cast<uint8_t>(chip_addr_),
      static_cast<uint8_t>(data_addr_), static_cast<uint8_t>(size_ / 8));
}

base::ScopedFD EcI2cFunction::GetEcDevice() const {
  return base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));
}

bool EcI2cFunction::PostParseArguments() {
  if (size_ != 8 && size_ != 16) {
    LOG(ERROR) << "function " << GetFunctionName()
               << " argument \"size\" should be 8 or 16.";
    return false;
  }
  return true;
}

EcI2cFunction::DataType EcI2cFunction::EvalImpl() const {
  base::ScopedFD ec_dev = GetEcDevice();
  auto cmd = GetI2cReadCommand();
  if (!cmd) {
    LOG(ERROR) << "Failed to create ec::I2cReadCommand";
    return {};
  }
  if (!cmd->RunWithMultipleAttempts(ec_dev.get(), kEcCmdNumAttempts)) {
    LOG(ERROR) << "Failed to read I2C data from EC";
    return {};
  }
  if (cmd->I2cStatus()) {
    LOG(ERROR) << "Unexpected I2C status: "
               << static_cast<int>(cmd->I2cStatus());
    return {};
  }

  DataType result{};
  base::Value::Dict dv{};
  if (size_ == 8) {
    dv.Set("data", cmd->Data());
  } else if (size_ == 16) {
    dv.Set("data", cmd->Data());
  }
  result.Append(std::move(dv));
  return result;
}

}  // namespace runtime_probe
