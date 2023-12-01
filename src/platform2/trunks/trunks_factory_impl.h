// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TRUNKS_FACTORY_IMPL_H_
#define TRUNKS_TRUNKS_FACTORY_IMPL_H_

#include "trunks/trunks_factory.h"

#include <memory>
#include <string>

#include <base/time/time.h>

#include "trunks/command_transceiver.h"
#include "trunks/tpm_cache.h"
#include "trunks/trunks_export.h"

namespace trunks {

// TrunksFactoryImpl is the default TrunksFactory implementation. This class is
// thread-safe with the exception of Initialize() but created objects are not
// necessarily thread-safe. Example usage:
//
// TrunksFactoryImpl factory;
// factory.Initialize(true /*failure_is_fatal*/);
// Tpm* tpm = factory.GetTpm();
class TRUNKS_EXPORT TrunksFactoryImpl : public TrunksFactory {
 public:
  // Uses an IPC proxy as the default CommandTransceiver.
  TrunksFactoryImpl();
  // TrunksFactoryImpl does not take ownership of |transceiver|. This
  // transceiver is forwarded down to the Tpm instance maintained by
  // this factory. It is assumed that the |transceiver| is already initialized.
  explicit TrunksFactoryImpl(CommandTransceiver* transceiver);
  TrunksFactoryImpl(const TrunksFactoryImpl&) = delete;
  TrunksFactoryImpl& operator=(const TrunksFactoryImpl&) = delete;

  ~TrunksFactoryImpl() override;

  // Initialize the factory. This must be called before any other methods.
  // Returns true on success.
  bool Initialize();

  // TrunksFactory methods.
  Tpm* GetTpm() const override;
  TpmCache* GetTpmCache() const override;

  std::unique_ptr<TpmState> GetTpmState() const override;
  std::unique_ptr<TpmUtility> GetTpmUtility() const override;
  std::unique_ptr<AuthorizationDelegate> GetPasswordAuthorization(
      const std::string& password) const override;
  std::unique_ptr<SessionManager> GetSessionManager() const override;
  std::unique_ptr<HmacSession> GetHmacSession() const override;
  std::unique_ptr<PolicySession> GetPolicySession() const override;
  std::unique_ptr<PolicySession> GetTrialSession() const override;
  std::unique_ptr<BlobParser> GetBlobParser() const override;

  // In case of getting a response code requesting a retry, set the maximum
  // number or retries and delay between each retry when sending a command
  // to the underlying transceiver using CommandTransceiver::SendCommandAndWait.
  void set_max_command_retries(int max_command_retries);
  void set_command_retry_delay(base::TimeDelta command_retry_delay);

 private:
  class PostProcessingTransceiver;

  bool IsDefaultTransceiverUsed() const {
    return default_transceiver_ != nullptr;
  }

  std::unique_ptr<CommandTransceiver> default_transceiver_;
  std::unique_ptr<PostProcessingTransceiver> transceiver_;
  std::unique_ptr<TpmCache> tpm_cache_;
  std::unique_ptr<Tpm> tpm_;
  bool initialized_ = false;
};

}  // namespace trunks

#endif  // TRUNKS_TRUNKS_FACTORY_IMPL_H_
