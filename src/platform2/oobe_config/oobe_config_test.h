// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_OOBE_CONFIG_TEST_H_
#define OOBE_CONFIG_OOBE_CONFIG_TEST_H_

#include "oobe_config/oobe_config.h"

#include <memory>

#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>
#include <libhwsec/factory/tpm2_simulator_factory_for_test.h>

#include "oobe_config/filesystem/file_handler_for_testing.h"

namespace oobe_config {

class OobeConfigTest : public ::testing::Test {
 protected:
  void SetUp() override;

  // Depending on the parameters, this simulates powerwash as it will look like
  // coming from or going to different versions:
  // - If both parameters are true (default), this simulates a rollback going to
  // the current code version, preserving both TPM and OpenSSL encrypted files.
  // - If only `preserve_openssl` is true, simulates a rollback going to an
  // older version. Older versions do not preserve tpm file.
  // - If only `preserve_tpm` is true, simulates a rollback coming from a future
  // version of this code on a device with rollback TPM space. On devices with
  // rollback TPM space, OpenSSL file will not be created in the future.
  void SimulatePowerwash(bool preserve_openssl = true,
                         bool preserve_tpm = true);

  // Creates TPM rollback space. Only works if compiled to use TPM2.
  void CreateRollbackSpace();

  hwsec::Tpm2SimulatorFactoryForTest hwsec_factory_;
  std::unique_ptr<hwsec::OobeConfigFrontend> hwsec_oobe_config_;

  FileHandlerForTesting file_handler_;
  std::unique_ptr<OobeConfig> oobe_config_;
};

}  // namespace oobe_config

#endif  // OOBE_CONFIG_OOBE_CONFIG_TEST_H_
