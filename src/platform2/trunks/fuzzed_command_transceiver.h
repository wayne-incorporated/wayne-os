// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// FuzzedCommanTransceiver is a test transceiver for fuzzing TPM commands and
// responses.

#ifndef TRUNKS_FUZZED_COMMAND_TRANSCEIVER_H_
#define TRUNKS_FUZZED_COMMAND_TRANSCEIVER_H_

#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "trunks/command_transceiver.h"

namespace trunks {

// Provides responses based on random data consumed from FuzzedDataProvider.
class FuzzedCommandTransceiver : public CommandTransceiver {
 public:
  FuzzedCommandTransceiver(FuzzedDataProvider* const data_provider,
                           size_t max_message_size);
  FuzzedCommandTransceiver(const FuzzedCommandTransceiver&) = delete;
  FuzzedCommandTransceiver& operator=(const FuzzedCommandTransceiver&) = delete;

  // CommandTransceiver methods.
  void SendCommand(const std::string& command,
                   ResponseCallback callback) override;
  std::string SendCommandAndWait(const std::string& command) override;

  // Builds a fuzzed TPM command.
  std::string ConsumeCommand();

  // Builds a fuzzed response to the provided command.
  std::string ConsumeResponseForCommand(const std::string& command);

  // Returns a realistic fuzzed command code.
  uint32_t ConsumeCommandCode();

  // Returns a realistic fuzzed response code.
  uint32_t ConsumeResponseCode();

  // Returns a realistic fuzzed command tag.
  uint16_t ConsumeCommandTag();

  // Returns fuzzed area with |qnt_handles| handles.
  std::string ConsumeHandles(size_t qnt_handles);

  // Returns fuzzed TPM handle.
  uint32_t ConsumeHandle();

  // Returns fuzzed payload for the message with header and handles area
  // taking |pre_payload_size| bytes.
  std::string ConsumePayload(size_t pre_payload_size);

 private:
  // Returns fuzzed bool, which is true with probability |probability| %.
  bool ConsumeBoolWithProbability(uint32_t probability);

  // Returns a random fuzzed message.
  std::string ConsumeRandomMessage();

  // Returns a random uint32_t.
  uint32_t ConsumeUint32();

  FuzzedDataProvider* const data_provider_;
  const size_t max_message_size_;
};

}  // namespace trunks

#endif  // TRUNKS_FUZZED_COMMAND_TRANSCEIVER_H_
