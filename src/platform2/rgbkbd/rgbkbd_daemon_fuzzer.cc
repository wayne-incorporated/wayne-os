// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <memory>

#include <base/logging.h>
#include <base/notreached.h>
#include <dbus/message.h>
#include <dbus/rgbkbd/dbus-constants.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <rgbkbd/rgbkbd_daemon.h>

namespace rgbkbd {

namespace {

const int kEnumSizeInBytes = 1;

// Check that capability enum size < 255.
static_assert(static_cast<uint8_t>(RgbKeyboardCapabilities::kMaxValue) <=
              std::numeric_limits<uint8_t>::max());

// 1 byte for random (0-4) range for branch switch, 1 byte for random uint8_t
// enum for capabilities, 3 bytes min for {r,g,b} (uint8_t), 4 bytes for branch
// value (int).
const int kMinBytes = 8 + kEnumSizeInBytes;
}  // namespace

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  dbus::Bus::Options options;
  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);
  auto adaptor_ = std::make_unique<DBusAdaptor>(bus, /*cros_config=*/nullptr,
                                                /*crossystem=*/nullptr,
                                                /*daemon=*/nullptr);
  FuzzedDataProvider provider(data, size);

  // Must have at least kEnumSizeInBytes available to set initial testing
  // capability.
  if (size < kEnumSizeInBytes) {
    return 0;
  }

  // Start with testing mode enabled.
  const uint8_t initial_capability = provider.ConsumeIntegralInRange<uint8_t>(
      0, static_cast<uint8_t>(RgbKeyboardCapabilities::kMaxValue));
  adaptor_->SetTestingMode(/*enable_testing=*/true,
                           static_cast<uint32_t>(initial_capability));

  while (provider.remaining_bytes() >= kMinBytes) {
    const int branch = provider.ConsumeIntegralInRange<int8_t>(0, 4);
    switch (branch) {
      case 0: {
        adaptor_->SetCapsLockState(provider.ConsumeBool());
        break;
      }
      case 1: {
        const uint8_t r = provider.ConsumeIntegral<uint8_t>();
        const uint8_t g = provider.ConsumeIntegral<uint8_t>();
        const uint8_t b = provider.ConsumeIntegral<uint8_t>();
        adaptor_->SetStaticBackgroundColor(r, g, b);
        break;
      }
      case 2: {
        adaptor_->SetRainbowMode();
        break;
      }
      case 3: {
        const uint32_t capability = provider.ConsumeIntegralInRange<uint8_t>(
            0, static_cast<uint8_t>(RgbKeyboardCapabilities::kMaxValue));
        adaptor_->SetTestingMode(/*enable_testing=*/true,
                                 static_cast<uint32_t>(capability));
        break;
      }
      case 4: {
        const int zone = provider.ConsumeIntegral<int>();
        const uint8_t r = provider.ConsumeIntegral<uint8_t>();
        const uint8_t g = provider.ConsumeIntegral<uint8_t>();
        const uint8_t b = provider.ConsumeIntegral<uint8_t>();
        adaptor_->SetZoneColor(zone, r, g, b);
        break;
      }
      default: {
        NOTREACHED();
        break;
      }
    }
  }
  return 0;
}

}  // namespace rgbkbd
