// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_PCA_AGENT_SERVER_PCA_AGENT_SERVICE_H_
#define ATTESTATION_PCA_AGENT_SERVER_PCA_AGENT_SERVICE_H_

#include <memory>
#include <utility>

#include <attestation/proto_bindings/pca_agent.pb.h>
#include <base/memory/ref_counted.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/attestation/dbus-constants.h>

#include "attestation/pca-agent/dbus_adaptors/org.chromium.PcaAgent.h"

namespace attestation {
namespace pca_agent {

class PcaAgentService : public org::chromium::PcaAgentInterface {
 public:
  PcaAgentService() = default;
  PcaAgentService(const PcaAgentService&) = delete;
  PcaAgentService& operator=(const PcaAgentService&) = delete;

  ~PcaAgentService() override = default;

  // org::chromium::PcaAgentInterface overrides.
  void Enroll(std::unique_ptr<
                  brillo::dbus_utils::DBusMethodResponse<EnrollReply>> response,
              const EnrollRequest& in_request) override;
  void GetCertificate(
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<GetCertificateReply>> response,
      const GetCertificateRequest& in_request) override;
};

class PcaAgentServiceAdaptor : public org::chromium::PcaAgentAdaptor {
 public:
  explicit PcaAgentServiceAdaptor(
      org::chromium::PcaAgentInterface* pca_agent_interface,
      scoped_refptr<dbus::Bus> bus)
      : org::chromium::PcaAgentAdaptor(pca_agent_interface),
        dbus_object_(nullptr, bus, dbus::ObjectPath(kPcaAgentServicePath)) {}
  PcaAgentServiceAdaptor(const PcaAgentServiceAdaptor&) = delete;
  PcaAgentServiceAdaptor& operator=(const PcaAgentServiceAdaptor&) = delete;

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
    RegisterWithDBusObject(&dbus_object_);
    dbus_object_.RegisterAsync(std::move(cb));
  }

 private:
  brillo::dbus_utils::DBusObject dbus_object_;
};

}  // namespace pca_agent
}  // namespace attestation

#endif  // ATTESTATION_PCA_AGENT_SERVER_PCA_AGENT_SERVICE_H_
