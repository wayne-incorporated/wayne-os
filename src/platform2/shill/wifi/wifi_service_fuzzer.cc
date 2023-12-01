// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <string>

#include <chromeos/dbus/shill/dbus-constants.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "base/at_exit.h"
#include "base/logging.h"
#include "shill/error.h"
#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/wifi/mock_wifi_provider.h"
#include "shill/wifi/wifi_service.h"

namespace shill {

class Environment {
 public:
  Environment() {
    // Disable logging.
    logging::SetMinLogLevel(logging::LOG_FATAL);
  }
};

class WiFiServiceFuzzer {
 public:
  static void Run(const uint8_t* data, size_t size) {
    FuzzedDataProvider data_provider(data, size);
    bool security_option = data_provider.ConsumeBool();
    std::string security_class =
        security_option ? kSecurityClassWep : kSecurityClassPsk;
    uint8_t ssid_size = data_provider.ConsumeIntegral<uint8_t>();
    std::vector<uint8_t> ssid = data_provider.ConsumeBytes<uint8_t>(ssid_size);
    std::string passphrase = data_provider.ConsumeRemainingBytesAsString();

    MockControl control;
    MockEventDispatcher dispatcher;
    MockMetrics metrics;
    MockManager manager(&control, &dispatcher, &metrics);
    MockWiFiProvider provider(&manager);
    WiFiServiceRefPtr service =
        new WiFiService(&manager, &provider, ssid, kModeManaged, security_class,
                        WiFiSecurity(), false);
    Error error;
    service->SetPassphrase(passphrase, &error);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  base::AtExitManager at_exit;
  WiFiServiceFuzzer::Run(data, size);
  return 0;
}

}  // namespace shill
