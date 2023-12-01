// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/client/user_state.h"

#include <algorithm>
#include <optional>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/sys_byteorder.h>
#include <brillo/file_utils.h>
#include <dbus/login_manager/dbus-constants.h>
#include <openssl/rand.h>

#include "u2fd/client/user_state.pb.h"
#include "u2fd/client/util.h"

namespace u2f {

namespace {

constexpr const char kSessionStateStarted[] = "started";
constexpr const char kUserSecretPath[] = "/run/daemon-store/u2f/%s/secret_db";
constexpr const char kCounterPath[] = "/run/daemon-store/u2f/%s/counter_db";

// Due to b/186431345, U2F credentials were asserted by the WebAuthn platform
// authenticator with a timestamp-based signature counter. After this was
// rectified, the UserState signature counter needed to be bumped up to be
// larger than the most recent timestamp counter that the WebAuthn platform
// authenticator reported.
constexpr uint32_t kCounterMinB186431345 =
    1640995200;  // 2022-01-01 00:00:00 UTC

void OnSignalConnected(const std::string& interface,
                       const std::string& signal,
                       bool success) {
  if (!success) {
    LOG(ERROR) << "Could not connect to signal " << signal << " on interface "
               << interface;
  }
}

}  // namespace

UserState::UserState(org::chromium::SessionManagerInterfaceProxy* sm_proxy,
                     uint32_t counter_min)
    : sm_proxy_(sm_proxy),
      weak_ptr_factory_(this),
      counter_min_(std::max(kCounterMinB186431345, counter_min)) {
  sm_proxy_->RegisterSessionStateChangedSignalHandler(
      base::BindRepeating(&UserState::OnSessionStateChanged,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));

  LoadState();
}

UserState::UserState() : weak_ptr_factory_(this), counter_min_(0) {}

bool UserState::HasUser() {
  return user_.has_value() && sanitized_user_.has_value();
}

std::optional<std::string> UserState::GetUser() {
  if (user_.has_value()) {
    return *user_;
  } else {
    LOG(ERROR) << "User requested but not available.";
    return std::nullopt;
  }
}

std::optional<std::string> UserState::GetSanitizedUser() {
  if (sanitized_user_.has_value()) {
    return *sanitized_user_;
  } else {
    LOG(ERROR) << "Sanitized user requested but not available.";
    return std::nullopt;
  }
}

std::optional<brillo::SecureBlob> UserState::GetUserSecret() {
  if (user_secret_.has_value()) {
    return *user_secret_;
  } else {
    LOG(ERROR) << "User secret requested but not available.";
    return std::nullopt;
  }
}

std::optional<std::vector<uint8_t>> UserState::GetCounter() {
  if (!counter_.has_value()) {
    LOG(ERROR) << "Counter requested but not available.";
    return std::nullopt;
  }

  std::vector<uint8_t> counter_bytes;
  util::AppendToVector(base::HostToNet32(*counter_), &counter_bytes);

  return counter_bytes;
}

bool UserState::IncrementCounter() {
  (*counter_)++;

  if (!PersistCounter()) {
    LOG(ERROR) << "Failed to persist updated counter. Attempting to re-load.";
    LoadCounter();
    return false;
  }

  return true;
}

void UserState::LoadState() {
  UpdatePrimarySessionSanitizedUser();
  if (sanitized_user_.has_value()) {
    LoadOrCreateUserSecret();
    LoadCounter();
    if (session_started_callback_ && user_.has_value()) {
      session_started_callback_.Run(*user_);
    }
  }
}

void UserState::OnSessionStateChanged(const std::string& state) {
  if (state == kSessionStateStarted) {
    LoadState();
  } else {
    user_.reset();
    sanitized_user_.reset();
    user_secret_.reset();
    counter_.reset();
    if (session_stopped_callback_) {
      session_stopped_callback_.Run();
    }
  }
}

void UserState::UpdatePrimarySessionSanitizedUser() {
  dbus::MethodCall method_call(
      login_manager::kSessionManagerInterface,
      login_manager::kSessionManagerRetrievePrimarySession);
  std::string user;
  std::string sanitized_user;
  brillo::ErrorPtr error;

  if (!sm_proxy_->RetrievePrimarySession(&user, &sanitized_user, &error) ||
      sanitized_user.empty()) {
    VLOG(1) << "Failed to retreive current user. This is expected on "
               "startup if no user is logged in.";
    user_.reset();
    sanitized_user_.reset();
  } else {
    user_ = user;
    sanitized_user_ = sanitized_user;
  }
}

void UserState::LoadOrCreateUserSecret() {
  base::FilePath path(
      base::StringPrintf(kUserSecretPath, sanitized_user_->c_str()));

  if (base::PathExists(path)) {
    LoadUserSecret(path);
  } else {
    CreateUserSecret(path);
  }
}

namespace {

// Wraps the specified proto in a message that includes a hash for integrity
// checking.
template <typename Proto, typename Blob>
bool WrapUserData(const Proto& user_data, Blob* out) {
  brillo::SecureBlob user_data_bytes(user_data.ByteSizeLong());
  if (!user_data.SerializeToArray(user_data_bytes.data(),
                                  user_data_bytes.size())) {
    return false;
  }

  std::vector<uint8_t> hash = util::Sha256(user_data_bytes);

  // TODO(louiscollard): Securely delete proto.
  UserDataContainer container;
  container.set_data(user_data_bytes.data(), user_data_bytes.size());
  container.set_sha256(hash.data(), hash.size());

  out->resize(container.ByteSizeLong());
  return container.SerializeToArray(out->data(), out->size());
}

template <typename Proto>
bool UnwrapUserData(const std::string& container, Proto* out) {
  UserDataContainer container_pb;
  if (!container_pb.ParseFromString(container)) {
    LOG(ERROR) << "Failed to parse user data container";
    return false;
  }

  std::vector<uint8_t> hash;
  util::AppendToVector(container_pb.sha256(), &hash);

  std::vector<uint8_t> hash_verify = util::Sha256(container_pb.data());

  return hash == hash_verify && out->ParseFromString(container_pb.data());
}

}  // namespace

void UserState::LoadUserSecret(const base::FilePath& path) {
  // TODO(louiscollard): Securely delete these.
  std::string secret_str;
  UserSecret secret_pb;

  if (base::ReadFileToString(path, &secret_str) &&
      UnwrapUserData<UserSecret>(secret_str, &secret_pb)) {
    user_secret_ = brillo::SecureBlob(secret_pb.secret());
  } else {
    LOG(ERROR) << "Failed to load user secret from: " << path.value();
    user_secret_.reset();
  }
}

void UserState::CreateUserSecret(const base::FilePath& path) {
  user_secret_ = brillo::SecureBlob(kUserSecretSizeBytes);

  if (RAND_bytes(&user_secret_->front(), user_secret_->size()) != 1) {
    LOG(ERROR) << "Failed to create new user secret";
    user_secret_.reset();
    return;
  }

  // TODO(louiscollard): Securely delete proto.
  UserSecret secret_proto;
  secret_proto.set_secret(user_secret_->data(), user_secret_->size());

  brillo::SecureBlob secret_proto_wrapped;
  if (!WrapUserData(secret_proto, &secret_proto_wrapped) ||
      !brillo::WriteBlobToFileAtomic(path, secret_proto_wrapped, 0600)) {
    LOG(ERROR) << "Failed to persist new user secret to disk.";
    user_secret_.reset();
  }
}

void UserState::LoadCounter() {
  base::FilePath path(
      base::StringPrintf(kCounterPath, sanitized_user_->c_str()));

  if (!base::PathExists(path)) {
    counter_ = counter_min_;
    VLOG(1) << "U2F counter missing, initializing counter with value of "
            << *counter_;
    return;
  }

  std::string counter;
  U2fCounter counter_pb;
  if (base::ReadFileToString(path, &counter) &&
      UnwrapUserData<U2fCounter>(counter, &counter_pb)) {
    uint32_t persistent_counter = counter_pb.counter();
    if (persistent_counter < counter_min_) {
      VLOG(1) << "Overriding persisted counter value of "
              << counter_pb.counter() << " with minimum value " << counter_min_;
      counter_ = counter_min_;
    } else {
      counter_ = persistent_counter;
    }
  } else {
    LOG(ERROR) << "Failed to load counter from: " << path.value();
    counter_.reset();
  }
}

bool UserState::PersistCounter() {
  base::FilePath path(
      base::StringPrintf(kCounterPath, sanitized_user_->c_str()));

  U2fCounter counter_pb;
  counter_pb.set_counter(*counter_);

  std::vector<uint8_t> counter_wrapped;

  return WrapUserData(counter_pb, &counter_wrapped) &&
         brillo::WriteBlobToFileAtomic(path, counter_wrapped, 0600);
}

void UserState::SetSessionStartedCallback(
    base::RepeatingCallback<void(const std::string&)> callback) {
  session_started_callback_ = std::move(callback);
}

void UserState::SetSessionStoppedCallback(
    base::RepeatingCallback<void()> callback) {
  session_stopped_callback_ = std::move(callback);
}

}  // namespace u2f
