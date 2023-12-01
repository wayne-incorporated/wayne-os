// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_TEST_UTILS_FAKE_PCA_AGENT_SERVICE_H_
#define HWSEC_TEST_UTILS_FAKE_PCA_AGENT_SERVICE_H_

#include <memory>
#include <utility>

#include <attestation/proto_bindings/pca_agent.pb.h>
#include <base/memory/ref_counted.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/attestation/dbus-constants.h>

// This generated file has to go after the protobuf definition.
#include <attestation/pca-agent/dbus_adaptors/org.chromium.PcaAgent.h>

namespace hwsec_test_utils {
namespace fake_pca_agent {

class FakePcaAgentService : public org::chromium::PcaAgentInterface {
 public:
  FakePcaAgentService();
  ~FakePcaAgentService() override = default;

  // Not copyable or movable.
  FakePcaAgentService(const FakePcaAgentService&) = delete;
  FakePcaAgentService& operator=(const FakePcaAgentService&) = delete;
  FakePcaAgentService(FakePcaAgentService&&) = delete;
  FakePcaAgentService& operator=(FakePcaAgentService&&) = delete;

  void Enroll(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                  attestation::pca_agent::EnrollReply>> response,
              const attestation::pca_agent::EnrollRequest& in_request) override;
  void GetCertificate(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          attestation::pca_agent::GetCertificateReply>> response,
      const attestation::pca_agent::GetCertificateRequest& in_request) override;
};

class FakePcaAgentServiceAdaptor : public org::chromium::PcaAgentAdaptor {
 public:
  explicit FakePcaAgentServiceAdaptor(
      org::chromium::PcaAgentInterface* pca_agent_interface,
      scoped_refptr<dbus::Bus> bus)
      : org::chromium::PcaAgentAdaptor(pca_agent_interface),
        dbus_object_(
            nullptr,
            bus,
            dbus::ObjectPath(attestation::pca_agent::kPcaAgentServicePath)) {}

  // Not copyable or movable.
  FakePcaAgentServiceAdaptor(const FakePcaAgentServiceAdaptor&) = delete;
  FakePcaAgentServiceAdaptor& operator=(const FakePcaAgentServiceAdaptor&) =
      delete;
  FakePcaAgentServiceAdaptor(FakePcaAgentServiceAdaptor&&) = delete;
  FakePcaAgentServiceAdaptor& operator=(FakePcaAgentServiceAdaptor&&) = delete;

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
    RegisterWithDBusObject(&dbus_object_);
    dbus_object_.RegisterAsync(std::move(cb));
  }

 private:
  brillo::dbus_utils::DBusObject dbus_object_;
};

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

#endif  // HWSEC_TEST_UTILS_FAKE_PCA_AGENT_SERVICE_H_
