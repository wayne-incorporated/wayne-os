// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_FUZZERS_FUZZED_USER_STATE_H_
#define U2FD_FUZZERS_FUZZED_USER_STATE_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "u2fd/client/user_state.h"

namespace u2f {

class FuzzedUserState : public UserState {
 public:
  explicit FuzzedUserState(FuzzedDataProvider* data_provider);

  // Generates the next state with the fuzzed data
  void NextState();

  // UserState methods
  std::optional<brillo::SecureBlob> GetUserSecret() override;
  std::optional<std::vector<uint8_t>> GetCounter() override;
  bool IncrementCounter() override;
  void SetSessionStartedCallback(
      base::RepeatingCallback<void(const std::string&)> callback) override;
  void SetSessionStoppedCallback(
      base::RepeatingCallback<void()> callback) override;
  bool HasUser() override;
  std::optional<std::string> GetUser() override;
  std::optional<std::string> GetSanitizedUser() override;

 private:
  FuzzedDataProvider* const data_provider_;

  std::optional<brillo::SecureBlob> user_secret_;
  std::optional<uint32_t> counter_;
};

}  // namespace u2f

#endif  // U2FD_FUZZERS_FUZZED_USER_STATE_H_
