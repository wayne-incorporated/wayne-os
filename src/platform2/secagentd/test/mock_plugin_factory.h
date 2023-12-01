// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_TEST_MOCK_PLUGIN_FACTORY_H_
#define SECAGENTD_TEST_MOCK_PLUGIN_FACTORY_H_

#include <memory>
#include <string>

#include "gmock/gmock.h"  // IWYU pragma: keep
#include "secagentd/common.h"
#include "secagentd/device_user.h"
#include "secagentd/plugins.h"

namespace secagentd::testing {

class MockPluginFactory : public PluginFactoryInterface {
 public:
  MOCK_METHOD(
      std::unique_ptr<PluginInterface>,
      Create,
      (Types::Plugin type,
       scoped_refptr<MessageSenderInterface> message_sender,
       scoped_refptr<ProcessCacheInterface> process_cache,
       scoped_refptr<PoliciesFeaturesBrokerInterface> policies_features_broker,
       scoped_refptr<DeviceUserInterface> device_user,
       uint32_t batch_interval_s),
      (override));

  MOCK_METHOD(std::unique_ptr<PluginInterface>,
              CreateAgentPlugin,
              (scoped_refptr<MessageSenderInterface> message_sender,
               scoped_refptr<DeviceUserInterface> device_user,
               std::unique_ptr<org::chromium::AttestationProxyInterface>
                   attestation_proxy,
               std::unique_ptr<org::chromium::TpmManagerProxyInterface>
                   tpm_manager_proxy,
               base::OnceCallback<void()> cb,
               uint32_t heartbeat_timer),
              (override));
};

class MockPlugin : public PluginInterface {
 public:
  absl::Status Activate() override {
    auto rv = MockActivate();
    is_active_ = rv.ok() ? true : is_active_;
    return rv;
  }

  absl::Status Deactivate() override {
    auto rv = MockDeactivate();
    is_active_ = rv.ok() ? false : is_active_;
    return rv;
  }

  bool GetIsActive() { return is_active_; }

  MOCK_METHOD(absl::Status, MockActivate, ());
  MOCK_METHOD(std::string, GetName, (), (const override));
  MOCK_METHOD(absl::Status, MockDeactivate, ());
  MOCK_METHOD(bool, IsActive, (), (const override));
  bool is_active_{false};
};

}  // namespace secagentd::testing
#endif  // SECAGENTD_TEST_MOCK_PLUGIN_FACTORY_H_
