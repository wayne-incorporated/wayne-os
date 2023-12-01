// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/service.h"

#include <base/command_line.h>
#include <brillo/syslog_logging.h>
#include <dbus/attestation/dbus-constants.h>

namespace hwsec_test_utils {
namespace fake_pca_agent {

class FakePcaAgentDaemon : public brillo::DBusServiceDaemon {
 public:
  FakePcaAgentDaemon()
      : DBusServiceDaemon(attestation::pca_agent::kPcaAgentServiceName) {}

  // Not copyable or movable.
  FakePcaAgentDaemon(const FakePcaAgentDaemon&) = delete;
  FakePcaAgentDaemon& operator=(const FakePcaAgentDaemon&) = delete;
  FakePcaAgentDaemon(FakePcaAgentDaemon&&) = delete;
  FakePcaAgentDaemon& operator=(FakePcaAgentDaemon&&) = delete;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    service_.reset(new FakePcaAgentService());
    adaptor_.reset(new FakePcaAgentServiceAdaptor(service_.get(), bus_));
    adaptor_->RegisterAsync(
        sequencer->GetHandler("RegisterAsync() failed", true));
  }

 private:
  std::unique_ptr<FakePcaAgentService> service_;
  std::unique_ptr<FakePcaAgentServiceAdaptor> adaptor_;
};

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int flags = brillo::kLogToSyslog;
  if (cl->HasSwitch("log_to_stderr")) {
    flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(flags);

  return hwsec_test_utils::fake_pca_agent::FakePcaAgentDaemon().Run();
}
