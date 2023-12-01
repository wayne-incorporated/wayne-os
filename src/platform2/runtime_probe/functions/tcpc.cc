// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/tcpc.h"

#include <fcntl.h>

#include <memory>
#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/values.h>
#include <libec/pd_chip_info_command.h>

namespace runtime_probe {
namespace {

// Times to retry the ec command if timeout.
const int kEcCmdNumAttempts = 10;
// The maximum port number of TCPC.
const uint8_t kMaxPortCount = 255;

uint32_t RunCommandRetry(const base::ScopedFD& ec_dev,
                         ec::PdChipInfoCommandV0* cmd) {
  for (int i = 0; i < kEcCmdNumAttempts; ++i) {
    // We expected the command runs successfully or returns invalid param error.
    if (cmd->Run(ec_dev.get()) || cmd->Result() == EC_RES_INVALID_PARAM)
      return cmd->Result();
  }
  LOG(ERROR) << "Failed to run ec command, error code: " << cmd->Result();
  return cmd->Result();
}

}  // namespace

std::unique_ptr<ec::PdChipInfoCommandV0> TcpcFunction::GetPdChipInfoCommandV0(
    uint8_t port) const {
  // Set |live| to 1 to read live chip values instead of hard-coded values.
  return std::make_unique<ec::PdChipInfoCommandV0>(port, /*live=*/1);
}

base::ScopedFD TcpcFunction::GetEcDevice() const {
  return base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));
}

TcpcFunction::DataType TcpcFunction::EvalImpl() const {
  DataType result{};
  base::ScopedFD ec_dev = GetEcDevice();

  for (uint8_t port = 0; port < kMaxPortCount; ++port) {
    auto cmd = GetPdChipInfoCommandV0(port);
    if (RunCommandRetry(ec_dev, cmd.get()) != EC_RES_SUCCESS)
      break;

    base::Value::Dict val;
    val.Set("port", base::NumberToString(port));
    val.Set("vendor_id", base::StringPrintf("0x%x", cmd->VendorId()));
    val.Set("product_id", base::StringPrintf("0x%x", cmd->ProductId()));
    val.Set("device_id", base::StringPrintf("0x%x", cmd->DeviceId()));
    result.Append(std::move(val));
  }

  return result;
}

}  // namespace runtime_probe
