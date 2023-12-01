// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <net/if.h>

#include <fuzzer/FuzzedDataProvider.h>
#include <set>
#include <string>
#include <vector>

#include "base/logging.h"

#include "patchpanel/firewall.h"
#include "patchpanel/minijailed_process_runner.h"

using patchpanel::ModifyPortRuleRequest;
using Protocol = patchpanel::ModifyPortRuleRequest::Protocol;

namespace patchpanel {
namespace {

class FakeProcessRunner : public MinijailedProcessRunner {
 public:
  FakeProcessRunner() : MinijailedProcessRunner(nullptr, nullptr) {}
  FakeProcessRunner(const FakeProcessRunner&) = delete;
  FakeProcessRunner& operator=(const FakeProcessRunner&) = delete;
  ~FakeProcessRunner() = default;

  int Run(const std::vector<std::string>& argv, bool log_failures) override {
    return 0;
  }

  int RunSync(const std::vector<std::string>& argv,
              bool log_failures,
              std::string* output) override {
    return 0;
  }
};
}  // namespace

}  // namespace patchpanel

struct Environment {
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

void FuzzAcceptRules(patchpanel::Firewall* firewall,
                     const uint8_t* data,
                     size_t size) {
  FuzzedDataProvider data_provider(data, size);
  while (data_provider.remaining_bytes() > 0) {
    ModifyPortRuleRequest::Protocol proto = data_provider.ConsumeBool()
                                                ? ModifyPortRuleRequest::TCP
                                                : ModifyPortRuleRequest::UDP;
    uint16_t port = data_provider.ConsumeIntegral<uint16_t>();
    std::string iface = data_provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
    if (data_provider.ConsumeBool()) {
      firewall->AddAcceptRules(proto, port, iface);
    } else {
      firewall->DeleteAcceptRules(proto, port, iface);
    }
  }
}

void FuzzForwardRules(patchpanel::Firewall* firewall,
                      const uint8_t* data,
                      size_t size) {
  FuzzedDataProvider data_provider(data, size);
  while (data_provider.remaining_bytes() > 0) {
    ModifyPortRuleRequest::Protocol proto = data_provider.ConsumeBool()
                                                ? ModifyPortRuleRequest::TCP
                                                : ModifyPortRuleRequest::UDP;
    uint16_t forwarded_port = data_provider.ConsumeIntegral<uint16_t>();
    uint16_t dst_port = data_provider.ConsumeIntegral<uint16_t>();
    struct in_addr input_ip_addr = {
        .s_addr = data_provider.ConsumeIntegral<uint32_t>()};
    struct in_addr dst_ip_addr = {
        .s_addr = data_provider.ConsumeIntegral<uint32_t>()};
    char input_buffer[INET_ADDRSTRLEN];
    char dst_buffer[INET_ADDRSTRLEN];
    memset(input_buffer, 0, INET_ADDRSTRLEN);
    memset(dst_buffer, 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &input_ip_addr, input_buffer, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_ip_addr, dst_buffer, INET_ADDRSTRLEN);
    std::string input_ip = input_buffer;
    std::string dst_ip = dst_buffer;
    std::string iface = data_provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
    if (data_provider.ConsumeBool()) {
      firewall->AddIpv4ForwardRule(proto, input_ip, forwarded_port, iface,
                                   dst_ip, dst_port);
    } else {
      firewall->DeleteIpv4ForwardRule(proto, input_ip, forwarded_port, iface,
                                      dst_ip, dst_port);
    }
  }
}

void FuzzLoopbackLockdownRules(patchpanel::Firewall* firewall,
                               const uint8_t* data,
                               size_t size) {
  FuzzedDataProvider data_provider(data, size);
  while (data_provider.remaining_bytes() > 0) {
    ModifyPortRuleRequest::Protocol proto = data_provider.ConsumeBool()
                                                ? ModifyPortRuleRequest::TCP
                                                : ModifyPortRuleRequest::UDP;
    uint16_t port = data_provider.ConsumeIntegral<uint16_t>();
    if (data_provider.ConsumeBool()) {
      firewall->AddLoopbackLockdownRules(proto, port);
    } else {
      firewall->DeleteLoopbackLockdownRules(proto, port);
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  auto process_runner = new patchpanel::FakeProcessRunner();
  patchpanel::Firewall firewall(process_runner);

  FuzzAcceptRules(&firewall, data, size);
  FuzzForwardRules(&firewall, data, size);
  FuzzLoopbackLockdownRules(&firewall, data, size);

  return 0;
}
