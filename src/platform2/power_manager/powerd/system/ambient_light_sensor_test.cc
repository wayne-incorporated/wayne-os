// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor.h"

#include <memory>
#include <optional>
#include <utility>

#include <gtest/gtest.h>

#include "power_manager/powerd/system/ambient_light_observer.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

class TestObserver : public AmbientLightObserver {
 public:
  TestObserver() = default;
  TestObserver(const TestObserver&) = delete;
  TestObserver& operator=(const TestObserver&) = delete;
  ~TestObserver() override = default;

  bool Updated() {
    bool updated = updated_;
    updated_ = false;
    return updated;
  }

  // AmbientLightObserver implementation:
  void OnAmbientLightUpdated(AmbientLightSensorInterface* sensor) override {
    updated_ = true;
  }

 private:
  bool updated_ = false;
};

class TestDelegate : public AmbientLightSensorDelegate {
 public:
  // AmbientLightSensorDelegate implementation:
  bool IsColorSensor() const override { return is_color_sensor_; }
  base::FilePath GetIlluminancePath() const override {
    return base::FilePath();
  }

  void SetLuxAndColorTemperature(std::optional<int> lux,
                                 std::optional<int> color_temperature) {
    if (color_temperature.has_value())
      is_color_sensor_ = true;

    if (!set_lux_callback_)
      return;

    set_lux_callback_.Run(lux, color_temperature);
  }

 private:
  bool is_color_sensor_ = false;
};

}  // namespace

class AmbientLightSensorTest : public TestEnvironment {
 public:
  AmbientLightSensorTest() = default;
  AmbientLightSensorTest(const AmbientLightSensorTest&) = delete;
  AmbientLightSensorTest& operator=(const AmbientLightSensorTest&) = delete;

  ~AmbientLightSensorTest() override = default;

 protected:
  void SetUp() override {
    sensor_ = std::make_unique<system::AmbientLightSensor>();
    auto delegate = std::make_unique<TestDelegate>();
    delegate_ = delegate.get();
    sensor_->SetDelegate(std::move(delegate));
    sensor_->AddObserver(&observer_);
  }

  void TearDown() override { sensor_->RemoveObserver(&observer_); }

  TestObserver observer_;
  TestDelegate* delegate_;
  std::unique_ptr<AmbientLightSensor> sensor_;
};

TEST_F(AmbientLightSensorTest, IsColorSensor) {
  EXPECT_FALSE(sensor_->IsColorSensor());
  EXPECT_FALSE(observer_.Updated());
}

TEST_F(AmbientLightSensorTest, UpdateWithoutData) {
  delegate_->SetLuxAndColorTemperature(std::nullopt, std::nullopt);
  EXPECT_TRUE(observer_.Updated());

  EXPECT_EQ(-1, sensor_->GetAmbientLightLux());
  EXPECT_EQ(-1, sensor_->GetColorTemperature());
}

TEST_F(AmbientLightSensorTest, UpdateWithLux) {
  delegate_->SetLuxAndColorTemperature(100, std::nullopt);
  EXPECT_TRUE(observer_.Updated());

  EXPECT_EQ(100, sensor_->GetAmbientLightLux());
  EXPECT_EQ(-1, sensor_->GetColorTemperature());

  delegate_->SetLuxAndColorTemperature(std::nullopt, std::nullopt);
  EXPECT_TRUE(observer_.Updated());

  // lux doesn't change.
  EXPECT_EQ(100, sensor_->GetAmbientLightLux());
  EXPECT_EQ(-1, sensor_->GetColorTemperature());
}

TEST_F(AmbientLightSensorTest, UpdateWithColorTemperature) {
  EXPECT_FALSE(sensor_->IsColorSensor());
  delegate_->SetLuxAndColorTemperature(std::nullopt, 200);
  EXPECT_TRUE(sensor_->IsColorSensor());
  EXPECT_TRUE(observer_.Updated());

  EXPECT_EQ(-1, sensor_->GetAmbientLightLux());
  EXPECT_EQ(200, sensor_->GetColorTemperature());

  delegate_->SetLuxAndColorTemperature(std::nullopt, std::nullopt);
  EXPECT_TRUE(observer_.Updated());

  // lux doesn't change.
  EXPECT_EQ(-1, sensor_->GetAmbientLightLux());
  EXPECT_EQ(200, sensor_->GetColorTemperature());
}

TEST_F(AmbientLightSensorTest, UpdateWithLuxAndColorTemperature) {
  delegate_->SetLuxAndColorTemperature(100, 200);
  EXPECT_TRUE(observer_.Updated());

  EXPECT_EQ(100, sensor_->GetAmbientLightLux());
  EXPECT_EQ(200, sensor_->GetColorTemperature());

  delegate_->SetLuxAndColorTemperature(std::nullopt, std::nullopt);
  EXPECT_TRUE(observer_.Updated());

  // lux doesn't change.
  EXPECT_EQ(100, sensor_->GetAmbientLightLux());
  EXPECT_EQ(200, sensor_->GetColorTemperature());
}

}  // namespace power_manager::system
