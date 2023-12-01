// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_MOCK_EC_COMMAND_FACTORY_H_
#define LIBEC_MOCK_EC_COMMAND_FACTORY_H_

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <libec/ec_command_factory.h>

namespace ec {

class MockEcCommandFactory : public ec::EcCommandFactoryInterface {
 public:
  MockEcCommandFactory() = default;
  ~MockEcCommandFactory() override = default;

  MOCK_METHOD(std::unique_ptr<ec::EcCommandInterface>,
              FpContextCommand,
              (CrosFpDeviceInterface * cros_fp, const std::string& user_id),
              (override));
  MOCK_METHOD(std::unique_ptr<ec::FlashProtectCommand>,
              FlashProtectCommand,
              (CrosFpDeviceInterface * cros_fp,
               flash_protect::Flags flags,
               flash_protect::Flags mask),
              (override));
  MOCK_METHOD(std::unique_ptr<ec::FpInfoCommand>,
              FpInfoCommand,
              (),
              (override));
  MOCK_METHOD(std::unique_ptr<ec::FpSeedCommand>,
              FpSeedCommand,
              (const brillo::SecureVector& seed, uint16_t seed_version),
              (override));
  MOCK_METHOD(std::unique_ptr<ec::FpFrameCommand>,
              FpFrameCommand,
              (int index, uint32_t frame_size, uint16_t max_read_size),
              (override));
  MOCK_METHOD(std::unique_ptr<ec::FpTemplateCommand>,
              FpTemplateCommand,
              (std::vector<uint8_t> tmpl, uint16_t max_write_size),
              (override));
  MOCK_METHOD(std::unique_ptr<ec::ChargeControlSetCommand>,
              ChargeControlSetCommand,
              (uint32_t mode, uint8_t lower, uint8_t upper),
              (override));
  MOCK_METHOD(std::unique_ptr<ec::ChargeCurrentLimitSetCommand>,
              ChargeCurrentLimitSetCommand,
              (uint32_t limit_mA),
              (override));
  MOCK_METHOD(std::unique_ptr<ec::DisplayStateOfChargeCommand>,
              DisplayStateOfChargeCommand,
              (),
              (override));
};

}  // namespace ec

#endif  // LIBEC_MOCK_EC_COMMAND_FACTORY_H_
