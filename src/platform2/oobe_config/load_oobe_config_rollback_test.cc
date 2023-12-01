// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/load_oobe_config_rollback.h"

#include <memory>
#include <string>

#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "oobe_config/oobe_config.h"
#include "oobe_config/oobe_config_test.h"

namespace oobe_config {

class LoadOobeConfigRollbackTest : public OobeConfigTest {
 protected:
  void SetUp() override {
    OobeConfigTest::SetUp();

    load_config_ = std::make_unique<LoadOobeConfigRollback>(oobe_config_.get(),
                                                            file_handler_);
  }

  void FakePreceedingRollback() {
    ASSERT_TRUE(oobe_config_->EncryptedRollbackSave());
    SimulatePowerwash();
    load_config_ = std::make_unique<LoadOobeConfigRollback>(oobe_config_.get(),
                                                            file_handler_);
  }

  void DeletePstoreData() { ASSERT_TRUE(file_handler_.RemoveRamoopsData()); }

  std::unique_ptr<LoadOobeConfigRollback> load_config_;
};

TEST_F(LoadOobeConfigRollbackTest, NoRollbackNoJson) {
  std::string config, enrollment_domain;
  ASSERT_FALSE(load_config_->GetOobeConfigJson(&config, &enrollment_domain));
}

TEST_F(LoadOobeConfigRollbackTest, DecryptAndParse) {
  FakePreceedingRollback();

  std::string config, enrollment_domain;
  ASSERT_TRUE(load_config_->GetOobeConfigJson(&config, &enrollment_domain));
}

TEST_F(LoadOobeConfigRollbackTest, SecondRequestDoesNotNeedPstore) {
  FakePreceedingRollback();

  std::string config, enrollment_domain;
  ASSERT_TRUE(load_config_->GetOobeConfigJson(&config, &enrollment_domain));

  // Delete pstore data to make decryption impossible. This fakes the scenario
  // where a reboot happens during rollback OOBE.
  DeletePstoreData();

  // Requesting config should still work because it re-uses previous data.
  std::string config_saved;
  ASSERT_TRUE(
      load_config_->GetOobeConfigJson(&config_saved, &enrollment_domain));
  ASSERT_EQ(config_saved, config);
}

TEST_F(LoadOobeConfigRollbackTest, DecryptionFailsGracefully) {
  FakePreceedingRollback();
  // Delete pstore data to fake the scenario where the device crashed or shut
  // down during rollback. Pstore data is gone, so decryption will fail.
  DeletePstoreData();

  std::string config, enrollment_domain;
  ASSERT_FALSE(load_config_->GetOobeConfigJson(&config, &enrollment_domain));
}

}  // namespace oobe_config
