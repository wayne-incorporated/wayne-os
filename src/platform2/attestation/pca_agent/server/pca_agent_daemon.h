// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_PCA_AGENT_SERVER_PCA_AGENT_DAEMON_H_
#define ATTESTATION_PCA_AGENT_SERVER_PCA_AGENT_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>
#include <dbus/attestation/dbus-constants.h>

#include "attestation/pca_agent/server/pca_agent_service.h"

namespace attestation {
namespace pca_agent {

class PcaAgentDaemon : public brillo::DBusServiceDaemon {
 public:
  PcaAgentDaemon() : DBusServiceDaemon(kPcaAgentServiceName) {}
  PcaAgentDaemon(const PcaAgentDaemon&) = delete;
  PcaAgentDaemon& operator=(const PcaAgentDaemon&) = delete;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    service_.reset(new PcaAgentService());
    adaptor_.reset(new PcaAgentServiceAdaptor(service_.get(), bus_));
    adaptor_->RegisterAsync(
        sequencer->GetHandler("RegisterAsync() failed", true));
  }

 private:
  std::unique_ptr<PcaAgentService> service_;
  std::unique_ptr<PcaAgentServiceAdaptor> adaptor_;
};

}  // namespace pca_agent
}  // namespace attestation

#endif  // ATTESTATION_PCA_AGENT_SERVER_PCA_AGENT_DAEMON_H_
