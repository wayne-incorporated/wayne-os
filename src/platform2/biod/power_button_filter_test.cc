// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/power_button_filter.h"

#include <base/memory/ptr_util.h>
#include <base/test/simple_test_tick_clock.h>
#include <base/time/time.h>
#include <cros_config/fake_cros_config.h>
#include <testing/gtest/include/gtest/gtest.h>

#include "biod/biod_config.h"
#include "biod/fake_power_manager_client.h"

namespace biod {

class PowerButtonFilterTest : public testing::Test {
 public:
  PowerButtonFilterTest() = default;
  PowerButtonFilterTest(const PowerButtonFilterTest&) = delete;
  PowerButtonFilterTest& operator=(const PowerButtonFilterTest&) = delete;

  ~PowerButtonFilterTest() = default;

  void SetUp() override {
    power_manager_client_ = new FakePowerManagerClient();
    test_clock_ = new base::SimpleTestTickClock();
  }

 protected:
  // Ownership passed to PowerButtonFilter instance.
  FakePowerManagerClient* power_manager_client_ = nullptr;
  // Ownership passed to PowerButtonFilter instance.
  brillo::FakeCrosConfig* cros_config_prefs_ = nullptr;
  // Ownership passed to PowerButtonFilter instance
  base::SimpleTestTickClock* test_clock_ = nullptr;

  std::unique_ptr<PowerButtonFilterInterface> InitializePowerButtonFilter(
      bool should_set_fp_type, bool is_fp_overlapped = true) {
    // Start at an arbitrary non-zero time.
    test_clock_->SetNowTicks((base::TimeTicks() + base::Hours(1)));
    if (should_set_fp_type) {
      cros_config_prefs_ = new brillo::FakeCrosConfig();
      std::string fp_type = is_fp_overlapped
                                ? biod::kFingerprintSensorTypeOverlapped
                                : biod::kFingerprintSensorTypeStandAlone;
      cros_config_prefs_->SetString(biod::kCrosConfigFPPath,
                                    biod::kFingerprintSensorTypePrefName,
                                    fp_type);
    }
    return PowerButtonFilter::create_power_button_filter_for_test(
        base::WrapUnique(power_manager_client_),
        base::WrapUnique(cros_config_prefs_), base::WrapUnique(test_clock_));
  }
};

// Tests PowerButtonFilter reports true on ShouldFilterFingerprintMatch() if
// it has seen power button down event in the last |kAuthIgnoreTimeoutmsecs|.
TEST_F(PowerButtonFilterTest, TestFilterOnPowerButtonDownEvent) {
  std::unique_ptr<PowerButtonFilterInterface> power_button_filter =
      InitializePowerButtonFilter(true);
  power_manager_client_->GeneratePowerButtonEvent(true,
                                                  test_clock_->NowTicks());
  // Advance time by |kAuthIgnoreTimeoutmsecs - 1|.
  test_clock_->Advance(base::Milliseconds(biod::kAuthIgnoreTimeoutmsecs - 1));
  EXPECT_TRUE(power_button_filter->ShouldFilterFingerprintMatch());
  // Now |power_button_filter| should return false on
  // ShouldFilterFingerprintMatch() as we have already suppressed one touch.
  EXPECT_FALSE(power_button_filter->ShouldFilterFingerprintMatch());
  // Generate one more power button event.
  power_manager_client_->GeneratePowerButtonEvent(true,
                                                  test_clock_->NowTicks());
  // Now that there is one more power button event,
  // ShouldFilterFingerprintMatch() should return true.
  EXPECT_TRUE(power_button_filter->ShouldFilterFingerprintMatch());
}

// Tests PowerButtonFilter reports false on ShouldFilterFingerprintMatch() if
// it has only seen power button up event in the last |kAuthIgnoreTimeoutmsecs|.
// This test guarantees that PowerButtonFilter does not consider power button
// up event as a new power button press.
TEST_F(PowerButtonFilterTest, TestFilterOnPowerButtonUpEvent) {
  std::unique_ptr<PowerButtonFilterInterface> power_button_filter =
      InitializePowerButtonFilter(true);
  power_manager_client_->GeneratePowerButtonEvent(false,
                                                  test_clock_->NowTicks());
  // Advance time by |kAuthIgnoreTimeoutmsecs - 1|.
  test_clock_->Advance(base::Milliseconds(biod::kAuthIgnoreTimeoutmsecs - 1));
  EXPECT_FALSE(power_button_filter->ShouldFilterFingerprintMatch());
}

// Tests PowerButtonFilter reports false on ShouldFilterFingerprintMatch() if
// it has not seen power button down event in the last
// |kAuthIgnoreTimeoutmsecs|.
TEST_F(PowerButtonFilterTest, TestFilterAfterkAuthIgnoreTimeoutmsecs) {
  std::unique_ptr<PowerButtonFilterInterface> power_button_filter =
      InitializePowerButtonFilter(true);
  power_manager_client_->GeneratePowerButtonEvent(true,
                                                  test_clock_->NowTicks());
  // Advance time by |kAuthIgnoreTimeoutmsecs| + 1.
  test_clock_->Advance(base::Milliseconds(biod::kAuthIgnoreTimeoutmsecs + 1));
  EXPECT_FALSE(power_button_filter->ShouldFilterFingerprintMatch());
}

// Tests PowerButtonFilter reports false on ShouldFilterFingerprintMatch() on
// devices with stand-alone fingerprint device, even when a power button event
// is seen in the last |kAuthIgnoreTimeoutmsecs|.
TEST_F(PowerButtonFilterTest, TestPowerButtonNotSeenOnStandAloneFp) {
  std::unique_ptr<PowerButtonFilterInterface> power_button_filter =
      InitializePowerButtonFilter(true, false);
  power_manager_client_->GeneratePowerButtonEvent(true,
                                                  test_clock_->NowTicks());
  // Advance time by |kAuthIgnoreTimeoutmsecs| - 1.
  test_clock_->Advance(base::Milliseconds(biod::kAuthIgnoreTimeoutmsecs - 1));
  EXPECT_FALSE(power_button_filter->ShouldFilterFingerprintMatch());
}

// Tests PowerButtonFilter reports expected value on
// ShouldFilterFingerprintMatch() if it has seen power button down event on
// devices with/without the use flag.
TEST_F(PowerButtonFilterTest, TestPowerButtonDownFilterWithUseFlag) {
  std::unique_ptr<PowerButtonFilterInterface> power_button_filter =
      InitializePowerButtonFilter(false);
  power_manager_client_->GeneratePowerButtonEvent(true,
                                                  test_clock_->NowTicks());
  // Advance time by |kAuthIgnoreTimeoutmsecs| - 1.
  test_clock_->Advance(base::Milliseconds(biod::kAuthIgnoreTimeoutmsecs - 1));
#if defined(FP_ON_POWER_BUTTON)
  EXPECT_TRUE(power_button_filter->ShouldFilterFingerprintMatch());
#else
  EXPECT_FALSE(power_button_filter->ShouldFilterFingerprintMatch());
#endif
}

}  // namespace biod
