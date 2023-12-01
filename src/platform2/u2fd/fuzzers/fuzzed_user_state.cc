// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/fuzzers/fuzzed_user_state.h"

#include <optional>

#include <base/sys_byteorder.h>

#include "u2fd/client/util.h"

namespace u2f {

namespace {
constexpr char kUser[] = "user";
constexpr char kSanitizedUser[] =
    "12dea96fec20593566ab75692c9949596833adc9";  // SHA1("user")
}  // namespace

FuzzedUserState::FuzzedUserState(FuzzedDataProvider* data_provider)
    : data_provider_(data_provider) {
  NextState();
}

void FuzzedUserState::NextState() {
  // This function consumes the same amount of data regardless of whether or not
  // the state is nullopt.

  std::string user_secret =
      data_provider_->ConsumeBytesAsString(kUserSecretSizeBytes);
  if (data_provider_->ConsumeBool()) {
    user_secret_ = brillo::SecureBlob(user_secret);
  } else {
    user_secret_ = std::nullopt;
  }

  uint32_t counter = data_provider_->ConsumeIntegral<uint32_t>();
  if (data_provider_->ConsumeBool()) {
    counter_ = counter;
  } else {
    counter_ = std::nullopt;
  }
}

std::optional<brillo::SecureBlob> FuzzedUserState::GetUserSecret() {
  return user_secret_;
}

std::optional<std::vector<uint8_t>> FuzzedUserState::GetCounter() {
  if (!counter_.has_value()) {
    return std::nullopt;
  }

  std::vector<uint8_t> counter_bytes;
  util::AppendToVector(base::HostToNet32(*counter_), &counter_bytes);
  return counter_bytes;
}

bool FuzzedUserState::IncrementCounter() {
  (*counter_)++;

  return data_provider_->ConsumeBool();
}

void FuzzedUserState::SetSessionStartedCallback(
    base::RepeatingCallback<void(const std::string&)>) {
  // Do nothing since FuzzedUserState does not call this callback function for
  // now
}
void FuzzedUserState::SetSessionStoppedCallback(
    base::RepeatingCallback<void()>) {
  // Do nothing since FuzzedUserState does not call this callback function for
  // now
}

bool FuzzedUserState::HasUser() {
  // TODO(domen): Support the state that there is no user.
  // We will need to call the callback functions in order to support changing
  // the user.
  return true;
}
std::optional<std::string> FuzzedUserState::GetUser() {
  return kUser;
}
std::optional<std::string> FuzzedUserState::GetSanitizedUser() {
  return kSanitizedUser;
}

}  // namespace u2f
