// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_EC_COMMAND_FACTORY_H_
#define LIBEC_EC_COMMAND_FACTORY_H_

#include <memory>
#include <string>
#include <vector>

#include "libec/charge_control_set_command.h"
#include "libec/charge_current_limit_set_command.h"
#include "libec/display_soc_command.h"
#include "libec/fingerprint/cros_fp_device_interface.h"
#include "libec/fingerprint/fp_context_command_factory.h"
#include "libec/fingerprint/fp_frame_command.h"
#include "libec/fingerprint/fp_info_command.h"
#include "libec/fingerprint/fp_seed_command.h"
#include "libec/fingerprint/fp_template_command.h"
#include "libec/flash_protect_command.h"

namespace ec {

class EcCommandFactoryInterface {
 public:
  virtual ~EcCommandFactoryInterface() = default;

  virtual std::unique_ptr<EcCommandInterface> FpContextCommand(
      CrosFpDeviceInterface* cros_fp, const std::string& user_id) = 0;

  virtual std::unique_ptr<FlashProtectCommand> FlashProtectCommand(
      CrosFpDeviceInterface* cros_fp,
      flash_protect::Flags flags,
      flash_protect::Flags mask) = 0;
  static_assert(
      std::is_base_of<EcCommandInterface, ec::FlashProtectCommand>::value,
      "All commands created by this class should derive from "
      "EcCommandInterface");

  virtual std::unique_ptr<FpInfoCommand> FpInfoCommand() = 0;
  static_assert(std::is_base_of<EcCommandInterface, ec::FpInfoCommand>::value,
                "All commands created by this class should derive from "
                "EcCommandInterface");

  virtual std::unique_ptr<FpSeedCommand> FpSeedCommand(
      const brillo::SecureVector& seed, uint16_t seed_version) = 0;
  static_assert(std::is_base_of<EcCommandInterface, ec::FpSeedCommand>::value,
                "All commands created by this class should derive from "
                "EcCommandInterface");

  virtual std::unique_ptr<ec::FpFrameCommand> FpFrameCommand(
      int index, uint32_t frame_size, uint16_t max_read_size) = 0;
  static_assert(std::is_base_of<EcCommandInterface, ec::FpFrameCommand>::value,
                "All commands created by this class should derive from "
                "EcCommandInterface");

  virtual std::unique_ptr<ec::FpTemplateCommand> FpTemplateCommand(
      std::vector<uint8_t> tmpl, uint16_t max_write_size) = 0;
  static_assert(
      std::is_base_of<EcCommandInterface, ec::FpTemplateCommand>::value,
      "All commands created by this class should derive from "
      "EcCommandInterface");

  virtual std::unique_ptr<ec::ChargeControlSetCommand> ChargeControlSetCommand(
      uint32_t mode, uint8_t lower, uint8_t upper) = 0;
  static_assert(
      std::is_base_of<EcCommandInterface, ec::ChargeControlSetCommand>::value,
      "All commands created by this class should derive from "
      "EcCommandInterface");

  virtual std::unique_ptr<ec::ChargeCurrentLimitSetCommand>
  ChargeCurrentLimitSetCommand(uint32_t limit_mA) = 0;
  static_assert(std::is_base_of<EcCommandInterface,
                                ec::ChargeCurrentLimitSetCommand>::value,
                "All commands created by this class should derive from "
                "EcCommandInterface");

  virtual std::unique_ptr<ec::DisplayStateOfChargeCommand>
  DisplayStateOfChargeCommand() = 0;
  static_assert(std::is_base_of<EcCommandInterface,
                                ec::DisplayStateOfChargeCommand>::value,
                "All commands created by this class should derive from "
                "EcCommandInterface");

  // TODO(b/144956297): Add factory methods for all of the EC
  // commands we use so that we can easily mock them for testing.
};

class BRILLO_EXPORT EcCommandFactory : public EcCommandFactoryInterface {
 public:
  EcCommandFactory() = default;
  ~EcCommandFactory() override = default;
  // Disallow copies
  EcCommandFactory(const EcCommandFactory&) = delete;
  EcCommandFactory& operator=(const EcCommandFactory&) = delete;

  std::unique_ptr<EcCommandInterface> FpContextCommand(
      CrosFpDeviceInterface* cros_fp, const std::string& user_id) override;

  std::unique_ptr<ec::FlashProtectCommand> FlashProtectCommand(
      CrosFpDeviceInterface* cros_fp,
      flash_protect::Flags flags,
      flash_protect::Flags mask) override;

  std::unique_ptr<ec::FpInfoCommand> FpInfoCommand() override;

  std::unique_ptr<ec::FpSeedCommand> FpSeedCommand(
      const brillo::SecureVector& seed, uint16_t seed_version) override;

  std::unique_ptr<ec::FpFrameCommand> FpFrameCommand(
      int index, uint32_t frame_size, uint16_t max_read_size) override;

  std::unique_ptr<ec::FpTemplateCommand> FpTemplateCommand(
      std::vector<uint8_t> tmpl, uint16_t max_write_size) override;

  std::unique_ptr<ec::ChargeControlSetCommand> ChargeControlSetCommand(
      uint32_t mode, uint8_t lower, uint8_t upper) override;

  std::unique_ptr<ec::ChargeCurrentLimitSetCommand>
  ChargeCurrentLimitSetCommand(uint32_t limit_mA) override;

  std::unique_ptr<ec::DisplayStateOfChargeCommand> DisplayStateOfChargeCommand()
      override;
};

}  // namespace ec

#endif  // LIBEC_EC_COMMAND_FACTORY_H_
