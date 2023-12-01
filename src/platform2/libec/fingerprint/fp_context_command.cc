// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <utility>
#include <vector>

#include <base/base64.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/ec/ec_commands.h>

#include "libec/ec_command.h"
#include "libec/ec_command_async.h"
#include "libec/fingerprint/fp_context_command.h"

namespace ec {

namespace {

std::unique_ptr<std::vector<uint8_t>> HexStringToBytes(const std::string& hex,
                                                       size_t max_size) {
  auto ret = std::make_unique<std::vector<uint8_t>>();
  if (hex.empty()) {
    return ret;
  }

  if (!base::HexStringToBytes(hex, ret.get())) {
    return nullptr;
  }
  if (ret->size() > max_size) {
    ret->resize(max_size);
  }
  return ret;
}

}  // namespace

FpContextCommand_v0::FpContextCommand_v0() : EcCommand(EC_CMD_FP_CONTEXT, 0) {}

std::unique_ptr<FpContextCommand_v0> FpContextCommand_v0::Create(
    const std::string& user_hex) {
  struct ec_params_fp_context ctxt = {};
  auto user_id = HexStringToBytes(user_hex, sizeof(ctxt.userid));
  if (!user_id) {
    return nullptr;
  }
  memcpy(ctxt.userid, user_id->data(), user_id->size());
  // Using new to access non-public constructor. See https://abseil.io/tips/134.
  auto cmd = base::WrapUnique(new FpContextCommand_v0());
  cmd->SetReq(ctxt);
  return cmd;
}

FpContextCommand_v1::FpContextCommand_v1()
    : EcCommandAsync(EC_CMD_FP_CONTEXT,
                     FP_CONTEXT_GET_RESULT,
                     {.poll_for_result_num_attempts = 70},
                     1) {}

std::unique_ptr<FpContextCommand_v1> FpContextCommand_v1::Create(
    const std::string& user_hex) {
  struct ec_params_fp_context_v1 ctxt = {.action = FP_CONTEXT_ASYNC};
  auto user_id = HexStringToBytes(user_hex, sizeof(ctxt.userid));
  if (!user_id) {
    return nullptr;
  }
  memcpy(ctxt.userid, user_id->data(), user_id->size());
  // Using new to access non-public constructor. See https://abseil.io/tips/134.
  auto cmd = base::WrapUnique(new FpContextCommand_v1());
  cmd->SetReq(ctxt);
  return cmd;
}

}  // namespace ec
