// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_KEY_CHALLENGE_SERVICE_IMPL_H_
#define CRYPTOHOME_KEY_CHALLENGE_SERVICE_IMPL_H_

#include <memory>
#include <string>

#include <base/memory/ref_counted.h>
#include <cryptohome/proto_bindings/rpc.pb.h>

#include "cryptohome/key_challenge_service.h"
#include "cryptohome_key_delegate/dbus-proxies.h"

namespace dbus {
class Bus;
}  // namespace dbus

namespace cryptohome {

// Real implementation of the KeyChallengeService interface that uses D-Bus for
// making key challenge requests to the specified service.
class KeyChallengeServiceImpl final : public KeyChallengeService {
 public:
  // |key_delegate_dbus_service_name| is the D-Bus service name that implements
  // the org.chromium.CryptohomeKeyDelegateInterface interface.
  KeyChallengeServiceImpl(scoped_refptr<dbus::Bus> dbus_bus,
                          const std::string& key_delegate_dbus_service_name);
  KeyChallengeServiceImpl(const KeyChallengeServiceImpl&) = delete;
  KeyChallengeServiceImpl& operator=(const KeyChallengeServiceImpl&) = delete;

  ~KeyChallengeServiceImpl() override;

  // KeyChallengeService overrides:
  void ChallengeKey(const AccountIdentifier& account_id,
                    const KeyChallengeRequest& key_challenge_request,
                    ResponseCallback response_callback) override;

  void FidoMakeCredential(
      const std::string& client_data_json,
      const cryptohome::fido::PublicKeyCredentialCreationOptions& options,
      MakeCredentialCallback response_callback) override;

  void FidoGetAssertion(
      const std::string& client_data_json,
      const cryptohome::fido::PublicKeyCredentialRequestOptions& request,
      GetAssertionCallback response_callback) override;

 private:
  const std::string key_delegate_dbus_service_name_;
  org::chromium::CryptohomeKeyDelegateInterfaceProxy dbus_proxy_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_KEY_CHALLENGE_SERVICE_IMPL_H_
