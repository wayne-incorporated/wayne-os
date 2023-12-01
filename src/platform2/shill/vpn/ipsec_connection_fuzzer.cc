// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>

#include <base/logging.h>

#include "shill/event_dispatcher.h"
#include "shill/net/process_manager.h"
#include "shill/vpn/ipsec_connection.h"

namespace shill {

class IPsecConnectionUnderTest : public IPsecConnection {
 public:
  explicit IPsecConnectionUnderTest(
      std::unique_ptr<IPsecConnection::Config> config,
      std::unique_ptr<VPNConnection> l2tp_connection,
      EventDispatcher* dispatcher,
      ProcessManager* process_manager)
      : IPsecConnection(
            std::move(config),
            std::make_unique<VPNConnection::Callbacks>(
                base::DoNothing(), base::DoNothing(), base::DoNothing()),
            std::move(l2tp_connection),
            nullptr,
            dispatcher,
            process_manager) {
    state_ = VPNConnection::State::kConnecting;
  }

  IPsecConnectionUnderTest(const IPsecConnectionUnderTest&) = delete;
  IPsecConnectionUnderTest& operator=(const IPsecConnectionUnderTest&) = delete;

  void TriggerReadIPsecStatus() {
    IPsecConnection::ScheduleConnectTask(ConnectStep::kIPsecConnected);
  }

  // Do nothing since we only want to test the `swanctl --list-sas` step.
  void ScheduleConnectTask(ConnectStep) override {}
};

// Does nothing in PostTask().
class EventDispatcherForFuzzer : public EventDispatcher {
 public:
  EventDispatcherForFuzzer() = default;
  EventDispatcherForFuzzer(const EventDispatcherForFuzzer&) = delete;
  EventDispatcherForFuzzer& operator=(const EventDispatcherForFuzzer&) = delete;
  ~EventDispatcherForFuzzer() override = default;

  void PostDelayedTask(const base::Location& location,
                       base::OnceClosure task,
                       base::TimeDelta delay) override {}
};

class FakeProcessManager : public ProcessManager {
 public:
  explicit FakeProcessManager(const std::string& data) : data_(data) {}
  FakeProcessManager(const FakeProcessManager&) = delete;
  FakeProcessManager& operator=(const FakeProcessManager&) = delete;

  pid_t StartProcessInMinijailWithStdout(
      const base::Location&,
      const base::FilePath&,
      const std::vector<std::string>&,
      const std::map<std::string, std::string>&,
      const MinijailOptions&,
      ExitWithStdoutCallback callback) {
    std::move(callback).Run(/*exit_status=*/0, data_);
    return 123;
  }

 private:
  std::string data_;
};

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  // Initialized the IPsecConnection class with an IKEv2 setting, and thus the
  // code path for parsing both virtual IP and cipher suites can be covered.
  auto config = std::make_unique<IPsecConnection::Config>();
  config->ike_version = IPsecConnection::Config::IKEVersion::kV2;
  EventDispatcherForFuzzer dispatcher;
  FakeProcessManager process_manager(
      std::string{reinterpret_cast<const char*>(data), size});
  IPsecConnectionUnderTest connection(std::move(config),
                                      /*l2tp_connection=*/nullptr, &dispatcher,
                                      &process_manager);

  connection.TriggerReadIPsecStatus();

  return 0;
}

}  // namespace shill
