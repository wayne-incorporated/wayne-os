// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fingerprint_manager.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/dbus/dbus_object.h>
#include <chromeos/dbus/service_constants.h>

namespace cryptohome {

namespace {

struct AuthScanDBusResult {
  biod::FingerprintMessage auth_result;
  std::vector<std::string> user_ids;
};

// Parses OnAuthScanDone signal from biod. Returns true if parsing succeeds.
bool ParseDBusSignal(dbus::Signal* signal, AuthScanDBusResult* result) {
  dbus::MessageReader signal_reader(signal);

  if (!signal_reader.PopArrayOfBytesAsProto(&result->auth_result))
    return false;

  switch (result->auth_result.msg_case()) {
    case biod::FingerprintMessage::MsgCase::kError:
    case biod::FingerprintMessage::MsgCase::kScanResult:
      break;
    case biod::FingerprintMessage::MsgCase::MSG_NOT_SET:
      VLOG(1) << "Fingerprint response doesn't contain any data";
      return false;
    default:
      VLOG(1) << "Unsupported message received";
      return false;
  }

  // Parsing is completed if the scan result isn't success.
  if (result->auth_result.msg_case() !=
          biod::FingerprintMessage::MsgCase::kScanResult ||
      result->auth_result.scan_result() !=
          biod::ScanResult::SCAN_RESULT_SUCCESS) {
    return true;
  }

  dbus::MessageReader matches_reader(nullptr);
  if (!signal_reader.PopArray(&matches_reader))
    return false;

  while (matches_reader.HasMoreData()) {
    dbus::MessageReader entry_reader(nullptr);
    if (!matches_reader.PopDictEntry(&entry_reader))
      return false;

    std::string user_id;
    if (!entry_reader.PopString(&user_id))
      return false;

    result->user_ids.emplace_back(user_id);
  }

  return true;
}

}  // namespace

std::unique_ptr<FingerprintManager> FingerprintManager::Create(
    const scoped_refptr<dbus::Bus>& bus, const dbus::ObjectPath& path) {
  auto fingerprint_manager = std::make_unique<FingerprintManager>();
  if (!fingerprint_manager->Initialize(bus, path))
    return nullptr;
  return fingerprint_manager;
}

FingerprintManager::FingerprintManager()
    : proxy_(nullptr),
      connected_to_auth_scan_done_signal_(false),
      weak_factory_(this),
      mount_thread_id_(base::PlatformThread::CurrentId()) {}

FingerprintManager::~FingerprintManager() = default;

bool FingerprintManager::Initialize(const scoped_refptr<dbus::Bus>& bus,
                                    const dbus::ObjectPath& path) {
  default_proxy_ = biod::BiometricsManagerProxyBase::Create(bus, path);
  if (!default_proxy_)
    return false;
  default_proxy_->ConnectToAuthScanDoneSignal(
      base::BindRepeating(&FingerprintManager::OnAuthScanDone,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&FingerprintManager::OnAuthScanDoneSignalConnected,
                     weak_factory_.GetWeakPtr()));
  if (!proxy_)
    proxy_ = default_proxy_.get();
  return true;
}

void FingerprintManager::OnAuthScanDoneSignalConnected(
    const std::string& interface, const std::string& signal, bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to connect to signal " << signal << " on interface "
               << interface;
  }
  // If we fail to connect to the AuthScanDone signal, it makes no sense to do
  // subsequent operations.
  connected_to_auth_scan_done_signal_ = success;
}

void FingerprintManager::Reset() {
  state_ = State::NO_AUTH_SESSION;
  current_user_->clear();
  auth_scan_done_callback_.Reset();
  signal_callback_.Reset();
}

const ObfuscatedUsername& FingerprintManager::GetCurrentUser() {
  return current_user_;
}

base::WeakPtr<FingerprintManager> FingerprintManager::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

void FingerprintManager::OnAuthScanDone(dbus::Signal* signal) {
  VLOG(1) << "Received AuthScanDone signal.";

  // This method is called if any auth scan operation completes, so we validate
  // that this signal is expected.
  if (state_ != State::AUTH_SESSION_OPEN)
    return;

  AuthScanDoneResourceManager resource_manager(this);

  AuthScanDBusResult result;
  if (!ParseDBusSignal(signal, &result)) {
    ProcessFailed();
    return;
  }

  if (result.auth_result.msg_case() ==
      biod::FingerprintMessage::MsgCase::kError) {
    VLOG(1) << "Authentication failed: error: "
            << biod::FingerprintErrorToString(result.auth_result.error());
    ProcessFailed();
    return;
  }

  // Now we know that result.auth_result contains ScanResult.
  CHECK(result.auth_result.msg_case() ==
        biod::FingerprintMessage::MsgCase::kScanResult);

  if (result.auth_result.scan_result() !=
      biod::ScanResult::SCAN_RESULT_SUCCESS) {
    VLOG(1) << "Authentication failed: scan result: "
            << biod::ScanResultToString(result.auth_result.scan_result());
    ProcessRetry();
    return;
  }

  if (std::find(result.user_ids.begin(), result.user_ids.end(),
                *current_user_) == result.user_ids.end()) {
    VLOG(1) << "Authentication failed: not matched.";
    ProcessRetry();
    return;
  }

  VLOG(1) << "Authentication succeeded.";
  if (auth_scan_done_callback_)
    std::move(auth_scan_done_callback_).Run(FingerprintScanStatus::SUCCESS);
  if (signal_callback_)
    signal_callback_.Run(FingerprintScanStatus::SUCCESS);

  state_ = State::AUTH_SESSION_LOCKED;
}

void FingerprintManager::ProcessRetry() {
  retry_left_--;

  FingerprintScanStatus error;
  if (retry_left_ <= 0) {
    state_ = State::AUTH_SESSION_LOCKED;
    error = FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED;
  } else {
    error = FingerprintScanStatus::FAILED_RETRY_ALLOWED;
  }
  if (auth_scan_done_callback_)
    std::move(auth_scan_done_callback_).Run(error);
  if (signal_callback_)
    signal_callback_.Run(error);
}

void FingerprintManager::ProcessFailed() {
  if (auth_scan_done_callback_) {
    std::move(auth_scan_done_callback_)
        .Run(FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  }
  if (signal_callback_) {
    signal_callback_.Run(FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  }
  state_ = State::AUTH_SESSION_LOCKED;
}

void FingerprintManager::SetAuthScanDoneCallback(
    ResultCallback auth_scan_done_callback) {
  DCHECK(base::PlatformThread::CurrentId() == mount_thread_id_);

  if (!connected_to_auth_scan_done_signal_)
    return;

  // Don't allow any operation if we are not in an auth session.
  if (state_ != State::AUTH_SESSION_OPEN) {
    std::move(auth_scan_done_callback)
        .Run(FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
    return;
  }

  auth_scan_done_callback_ = std::move(auth_scan_done_callback);
}

void FingerprintManager::SetUserAndRunClientCallback(
    StartSessionCallback auth_session_start_client_callback,
    const ObfuscatedUsername& user,
    bool success) {
  // Set |current_user_| to |user| if auth session started successfully.
  if (success) {
    current_user_ = user;
    retry_left_ = kMaxFingerprintRetries;
    state_ = State::AUTH_SESSION_OPEN;
  } else {
    Reset();
  }
  std::move(auth_session_start_client_callback).Run(success);
}

void FingerprintManager::SetSignalCallback(SignalCallback callback) {
  DCHECK(base::PlatformThread::CurrentId() == mount_thread_id_);
  signal_callback_ = std::move(callback);
}

void FingerprintManager::StartAuthSessionAsyncForUser(
    const ObfuscatedUsername& user,
    StartSessionCallback auth_session_start_client_callback) {
  DCHECK(base::PlatformThread::CurrentId() == mount_thread_id_);

  if (!connected_to_auth_scan_done_signal_)
    return;

  // Disallow starting auth session if another session might be pending.
  if (state_ != State::NO_AUTH_SESSION) {
    std::move(auth_session_start_client_callback).Run(false);
    return;
  }

  // Wrapper callback around the client's callback for starting auth session,
  // so that we can set |current_user_| in addition to running the client's
  // callback.
  auto auth_session_start_callback = base::BindOnce(
      &FingerprintManager::SetUserAndRunClientCallback, base::Unretained(this),
      std::move(auth_session_start_client_callback), user);

  proxy_->StartAuthSessionAsync(std::move(auth_session_start_callback));
}

void FingerprintManager::EndAuthSession() {
  // Return an error to any pending call. This is for the case where the client
  // decides to cancel fingerprint auth before receiving a response from us.
  if (auth_scan_done_callback_) {
    std::move(auth_scan_done_callback_)
        .Run(FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  }
  proxy_->EndAuthSession();
  Reset();
}

bool FingerprintManager::HasAuthSessionForUser(const ObfuscatedUsername& user) {
  DCHECK(base::PlatformThread::CurrentId() == mount_thread_id_);

  if (!proxy_ || !connected_to_auth_scan_done_signal_)
    return false;

  if (state_ != State::AUTH_SESSION_OPEN || current_user_ != user)
    return false;

  return true;
}

void FingerprintManager::SetProxy(biod::BiometricsManagerProxyBase* proxy) {
  proxy_ = proxy;
}

}  // namespace cryptohome
