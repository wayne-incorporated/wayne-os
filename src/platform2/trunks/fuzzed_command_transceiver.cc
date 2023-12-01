// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// FuzzedCommanTransceiver is a test transceiver for fuzzing TPM commands and
// responses.

#include <arpa/inet.h>
#include <cstring>
#include <utility>

#include <base/check.h>
#include <base/functional/callback.h>

#include "trunks/command_parser.h"
#include "trunks/fuzzed_command_transceiver.h"
#include "trunks/real_command_parser.h"
#include "trunks/tpm_generated.h"

namespace {

// Probability in % of generating a pure random value or byte stream.
constexpr uint32_t kPureRandomProb = 5;
// Probability in % of generating an error response.
constexpr uint32_t kErrorResponseProb = 20;
// Probability in % of generating a response of minimal size.
constexpr uint32_t kMinimalResponseProb = 80;

std::string BuildHeader(uint16_t tag, uint32_t size, uint32_t code) {
  std::string header;
  trunks::Serialize_uint16_t(tag, &header);
  trunks::Serialize_uint32_t(size, &header);
  trunks::Serialize_uint32_t(code, &header);
  return header;
}

}  // namespace

namespace trunks {

FuzzedCommandTransceiver::FuzzedCommandTransceiver(
    FuzzedDataProvider* const data_provider, size_t max_message_size)
    : data_provider_(data_provider), max_message_size_(max_message_size) {
  CHECK(data_provider);
}

void FuzzedCommandTransceiver::SendCommand(const std::string& command,
                                           ResponseCallback callback) {
  std::move(callback).Run(SendCommandAndWait(command));
}

std::string FuzzedCommandTransceiver::SendCommandAndWait(
    const std::string& command) {
  return ConsumeResponseForCommand(command);
}

std::string FuzzedCommandTransceiver::ConsumeCommand() {
  // With low probability return a completely random message.
  if (ConsumeBoolWithProbability(kPureRandomProb)) {
    return ConsumeRandomMessage();
  }

  // Build a valid message.
  uint16_t tag = ConsumeCommandTag();
  uint32_t code = ConsumeCommandCode();
  std::string handles = ConsumeHandles(GetNumberOfRequestHandles(code));
  std::string payload = ConsumePayload(kHeaderSize + handles.size());

  return BuildHeader(tag, kHeaderSize + handles.size() + payload.size(), code) +
         handles + payload;
}

std::string FuzzedCommandTransceiver::ConsumeResponseForCommand(
    const std::string& command) {
  // With low probability return a completely random message.
  if (ConsumeBoolWithProbability(kPureRandomProb)) {
    return ConsumeRandomMessage();
  }

  // Parse command, use defaults in case of parsing errors.
  uint16_t cmd_tag = TPM_ST_NO_SESSIONS;
  uint32_t cmd_code = TPM_CC_FIRST;
  uint32_t cmd_size = 0;
  RealCommandParser parser;
  std::string buffer = command;
  parser.ParseHeader(&buffer, &cmd_tag, &cmd_size, &cmd_code);

  // Decide if we want to return an error or success.
  uint32_t resp_code;
  std::string handles;
  if (ConsumeBoolWithProbability(kErrorResponseProb)) {
    resp_code = ConsumeResponseCode();
  } else {
    resp_code = TPM_RC_SUCCESS;
    handles = ConsumeHandles(GetNumberOfResponseHandles(cmd_code));
  }

  // Error or success, with high probability return response of minimal size.
  std::string payload;
  if (!ConsumeBoolWithProbability(kMinimalResponseProb)) {
    payload = ConsumePayload(kHeaderSize + handles.size());
  }

  return BuildHeader(cmd_tag, kHeaderSize + handles.size() + payload.size(),
                     resp_code) +
         handles + payload;
}

uint32_t FuzzedCommandTransceiver::ConsumeCommandCode() {
  // Decide between realistic and purely random value.
  if (ConsumeBoolWithProbability(kPureRandomProb)) {
    return ConsumeUint32();
  }
  return data_provider_->ConsumeIntegralInRange<uint32_t>(TPM_CC_FIRST,
                                                          TPM_CC_LAST);
}

uint32_t FuzzedCommandTransceiver::ConsumeResponseCode() {
  // Decide between realistic and purely random value.
  if (ConsumeBoolWithProbability(kPureRandomProb)) {
    return ConsumeUint32();
  }
  uint32_t rc = data_provider_->ConsumeIntegralInRange<uint32_t>(0, 0xFFF);
  if (data_provider_->ConsumeBool()) {
    // Generate WARN or FMT0 error RC.
    rc &= 0x97F;
  } else {
    // Generate FMT1 error RC.
    rc |= RC_FMT1;
  }
  return rc;
}

uint16_t FuzzedCommandTransceiver::ConsumeCommandTag() {
  // Decide between realistic and purely random value.
  if (ConsumeBoolWithProbability(kPureRandomProb)) {
    return data_provider_->ConsumeIntegral<uint16_t>();
  }
  if (data_provider_->ConsumeBool()) {
    return TPM_ST_SESSIONS;
  }
  return TPM_ST_NO_SESSIONS;
}

std::string FuzzedCommandTransceiver::ConsumeHandles(size_t qnt_handles) {
  std::string handles;
  for (; qnt_handles > 0; --qnt_handles) {
    Serialize_uint32_t(ConsumeHandle(), &handles);
  }
  return handles;
}

uint32_t FuzzedCommandTransceiver::ConsumeHandle() {
  uint32_t handle = ConsumeUint32();
  // Decide between realistic and purely random value.
  if (!ConsumeBoolWithProbability(kPureRandomProb)) {
    handle &= 0xC3000003u;
  }
  return handle;
}

std::string FuzzedCommandTransceiver::ConsumePayload(size_t pre_payload_size) {
  if (max_message_size_ <= pre_payload_size) {
    return std::string();
  }
  return data_provider_->ConsumeRandomLengthString(max_message_size_ -
                                                   pre_payload_size);
}

bool FuzzedCommandTransceiver::ConsumeBoolWithProbability(
    uint32_t probability) {
  return data_provider_->ConsumeIntegralInRange<uint32_t>(0, 99) < probability;
}

std::string FuzzedCommandTransceiver::ConsumeRandomMessage() {
  return data_provider_->ConsumeRandomLengthString(max_message_size_);
}

uint32_t FuzzedCommandTransceiver::ConsumeUint32() {
  return data_provider_->ConsumeIntegralInRange<uint32_t>(0, 0xFFFFFFFFu);
}

}  // namespace trunks
