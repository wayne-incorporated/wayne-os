// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/trunks_factory_impl.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/logging.h>

#include "trunks/blob_parser.h"
#include "trunks/error_codes.h"
#include "trunks/hmac_session_impl.h"
#include "trunks/password_authorization_delegate.h"
#include "trunks/policy_session_impl.h"
#include "trunks/session_manager_impl.h"
#include "trunks/tpm_cache.h"
#include "trunks/tpm_cache_impl.h"
#include "trunks/tpm_generated.h"
#include "trunks/tpm_state_impl.h"
#include "trunks/tpm_utility_impl.h"
#include "trunks/trunks_dbus_proxy.h"

namespace {

constexpr int kDefaultRetryDelayInMS = 250;
constexpr int kDefaultRetryTimeoutInMS = 10 * 1000;
constexpr int kDefaultRetries =
    kDefaultRetryTimeoutInMS / kDefaultRetryDelayInMS;
constexpr base::TimeDelta kDefaultRetryDelay =
    base::Milliseconds(kDefaultRetryDelayInMS);

}  // namespace

namespace trunks {

// A post-processing transceiver that attaches on top of the transceiver passed
// to TrunksFactoryImpl. Peforms the following functions:
// - Checks the response in SendCommandAndWait and retries the command
//   in case the response code requests a retry. See RetryNeededFor() for
//   details.
class TrunksFactoryImpl::PostProcessingTransceiver : public CommandTransceiver {
 public:
  explicit PostProcessingTransceiver(CommandTransceiver* transceiver)
      : command_retry_delay_(kDefaultRetryDelay),
        max_command_retries_(kDefaultRetries),
        transceiver_(transceiver) {
    CHECK(transceiver_);
  }
  PostProcessingTransceiver(const PostProcessingTransceiver&) = delete;
  PostProcessingTransceiver& operator=(const PostProcessingTransceiver&) =
      delete;

  void set_max_command_retries(int max_command_retries) {
    max_command_retries_ = max_command_retries;
  }

  void set_command_retry_delay(base::TimeDelta command_retry_delay) {
    command_retry_delay_ = command_retry_delay;
  }

  bool Init() override { return transceiver_->Init(); }

  void SendCommand(const std::string& command,
                   ResponseCallback callback) override {
    transceiver_->SendCommand(command, std::move(callback));
  }

  std::string SendCommandAndWait(const std::string& command) override {
    int attempt_num = 0;
    std::string response;
    do {
      if (attempt_num > 0) {
        base::PlatformThread::Sleep(command_retry_delay_);
      }
      response = transceiver_->SendCommandAndWait(command);
    } while (RetryNeededFor(response, ++attempt_num));
    VLOG_IF(2, attempt_num > 1) << "Command sent " << attempt_num << " times.";
    return response;
  }

 private:
  bool RetryNeededFor(const std::string& response, int attempt_num) {
    if (attempt_num > max_command_retries_) {
      LOG(WARNING) << "Gave up retrying command after " << attempt_num
                   << " attempts.";
      return false;
    }
    TPM_RC rc;
    TPM_RC parse_rc = GetResponseCode(response, rc);
    if (parse_rc != TPM_RC_SUCCESS) {
      return false;
    }
    switch (rc) {
      case TPM_RC_RETRY:
      case TPM_RC_NV_RATE:
        if (attempt_num == 1) {
          LOG(WARNING) << "Retrying command after " << GetErrorString(rc);
        } else {
          VLOG(2) << "Retrying command after " << GetErrorString(rc);
        }
        return true;
      default:
        return false;
    }
  }

  base::TimeDelta command_retry_delay_;
  int max_command_retries_;
  CommandTransceiver* transceiver_;
};

TrunksFactoryImpl::TrunksFactoryImpl() {
  default_transceiver_.reset(new TrunksDBusProxy());
  transceiver_.reset(new PostProcessingTransceiver(default_transceiver_.get()));
}

TrunksFactoryImpl::TrunksFactoryImpl(CommandTransceiver* transceiver) {
  transceiver_.reset(new PostProcessingTransceiver(transceiver));
}

TrunksFactoryImpl::~TrunksFactoryImpl() {}

bool TrunksFactoryImpl::Initialize() {
  if (initialized_) {
    return true;
  }
  tpm_.reset(new Tpm(transceiver_.get()));
  tpm_cache_ = std::make_unique<TpmCacheImpl>(*this);
  if (!IsDefaultTransceiverUsed()) {
    initialized_ = true;
  } else {
    initialized_ = transceiver_->Init();
    if (!initialized_) {
      LOG(WARNING) << "Failed to initialize the trunks IPC proxy; "
                   << "trunksd is not ready.";
    }
  }
  return initialized_;
}

Tpm* TrunksFactoryImpl::GetTpm() const {
  return tpm_.get();
}

TpmCache* TrunksFactoryImpl::GetTpmCache() const {
  return tpm_cache_.get();
}

std::unique_ptr<TpmState> TrunksFactoryImpl::GetTpmState() const {
  return std::make_unique<TpmStateImpl>(*this);
}

std::unique_ptr<TpmUtility> TrunksFactoryImpl::GetTpmUtility() const {
  return std::make_unique<TpmUtilityImpl>(*this);
}

std::unique_ptr<AuthorizationDelegate>
TrunksFactoryImpl::GetPasswordAuthorization(const std::string& password) const {
  return std::make_unique<PasswordAuthorizationDelegate>(password);
}

std::unique_ptr<SessionManager> TrunksFactoryImpl::GetSessionManager() const {
  return std::make_unique<SessionManagerImpl>(*this);
}

std::unique_ptr<HmacSession> TrunksFactoryImpl::GetHmacSession() const {
  return std::make_unique<HmacSessionImpl>(*this);
}

std::unique_ptr<PolicySession> TrunksFactoryImpl::GetPolicySession() const {
  return std::make_unique<PolicySessionImpl>(*this, TPM_SE_POLICY);
}

std::unique_ptr<PolicySession> TrunksFactoryImpl::GetTrialSession() const {
  return std::make_unique<PolicySessionImpl>(*this, TPM_SE_TRIAL);
}

std::unique_ptr<BlobParser> TrunksFactoryImpl::GetBlobParser() const {
  return std::make_unique<BlobParser>();
}

void TrunksFactoryImpl::set_max_command_retries(int max_command_retries) {
  transceiver_->set_max_command_retries(max_command_retries);
}

void TrunksFactoryImpl::set_command_retry_delay(
    base::TimeDelta command_retry_delay) {
  transceiver_->set_command_retry_delay(command_retry_delay);
}

}  // namespace trunks
