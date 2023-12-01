// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/port_manager.h"

#include <string>

#include <base/logging.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "typecd/mock_ec_util.h"
#include "typecd/mock_port.h"

using testing::_;
using ::testing::Return;

namespace typecd {

// Add a wrapper around PortManager, since some functions aren't accessible from
// the fuzzer functions' namespace.
class PortManagerFuzzer {
 public:
  void SetModeEntrySupported() { manager_.SetModeEntrySupported(true); }

  void SetECUtil(ECUtil* ec_util) { manager_.SetECUtil(ec_util); }

  void AddPort(std::unique_ptr<MockPort> port) {
    manager_.ports_.insert(
        std::pair<int, std::unique_ptr<Port>>(0, std::move(port)));
  }

  void SetUserActive(bool active) { manager_.SetUserActive(active); }

  void RunModeEntry(int port) { manager_.RunModeEntry(port); }

 private:
  typecd::PortManager manager_;
};

}  // namespace typecd

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_ERROR); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);
  typecd::PortManagerFuzzer fuzzer;

  // Since we only have a MockECUtil, just force the |mode_entry_supported_|
  // flag.
  fuzzer.SetModeEntrySupported();

  // Create the MockECUtil and don't set any expectations, since we don't
  // care what is called.
  auto ec_util = std::make_unique<typecd::MockECUtil>();
  fuzzer.SetECUtil(ec_util.get());

  // Add a fake port that and fill its return values randomly.
  auto port = std::make_unique<typecd::MockPort>(base::FilePath("fakepath"), 0);
  EXPECT_CALL(*port, GetDataRole())
      .WillRepeatedly(
          testing::Return(data_provider.ConsumeEnum<typecd::DataRole>()));
  EXPECT_CALL(*port, IsPartnerDiscoveryComplete())
      .WillRepeatedly(testing::Return(data_provider.ConsumeBool()));
  EXPECT_CALL(*port, IsCableDiscoveryComplete())
      .WillRepeatedly(testing::Return(data_provider.ConsumeBool()));
  EXPECT_CALL(*port, CanEnterUSB4())
      .WillRepeatedly(testing::Return(
          data_provider.ConsumeEnum<typecd::ModeEntryResult>()));
  EXPECT_CALL(*port, CanEnterTBTCompatibilityMode())
      .WillRepeatedly(testing::Return(
          data_provider.ConsumeEnum<typecd::ModeEntryResult>()));
  EXPECT_CALL(*port, CanEnterDPAltMode(nullptr))
      .WillRepeatedly(testing::Return(data_provider.ConsumeBool()));
  fuzzer.AddPort(std::move(port));

  fuzzer.SetUserActive(data_provider.ConsumeBool());

  // Simulate a hotplug.
  fuzzer.RunModeEntry(0);

  return 0;
}
