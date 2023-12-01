// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEMS_SETUP_TEST_HELPER_H_
#define MEMS_SETUP_TEST_HELPER_H_

#include <initializer_list>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <libmems/iio_context.h>
#include <libmems/iio_device.h>
#include <libmems/test_fakes.h>
#include "mems_setup/configuration.h"
#include "mems_setup/delegate.h"
#include "mems_setup/sensor_kind.h"
#include "mems_setup/test_fakes.h"

namespace mems_setup {
namespace testing {

class FakeSysfsTrigger : public libmems::fakes::FakeIioDevice {
 public:
  FakeSysfsTrigger(libmems::fakes::FakeIioContext* ctx,
                   std::unique_ptr<libmems::fakes::FakeIioDevice> trigger)
      : FakeIioDevice(ctx, "iio_sysfs_trigger", -1),
        mock_context_(ctx),
        mock_trigger_(std::move(trigger)) {}

  bool WriteNumberAttribute(const std::string& name, int64_t value) override;
  void AddMockTrigger();

 private:
  libmems::fakes::FakeIioContext* mock_context_;
  std::unique_ptr<libmems::fakes::FakeIioDevice> mock_trigger_;
};

class SensorTestBase {
 public:
  Configuration* GetConfiguration();

 protected:
  std::unique_ptr<libmems::fakes::FakeIioContext> mock_context_;
  std::unique_ptr<mems_setup::fakes::FakeDelegate> mock_delegate_;
  libmems::fakes::FakeIioDevice* mock_device_;

  libmems::fakes::FakeIioDevice* mock_trigger1_;
  FakeSysfsTrigger* mock_sysfs_trigger_;

  std::unique_ptr<Configuration> config_;

  SensorKind sensor_kind_;

  SensorTestBase(const char* name, int id);

  void SetSingleSensor(const char* location);
  void SetSharedSensor();
  void SetColorLightSensor();

  void ConfigureVpd(
      std::initializer_list<std::pair<const char*, const char*>> values);
};

}  // namespace testing
}  // namespace mems_setup

#endif  // MEMS_SETUP_TEST_HELPER_H_
