// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/load_oobe_config_rollback.h"

#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/values.h>

#include "oobe_config/oobe_config.h"
#include "oobe_config/rollback_data.pb.h"

using base::FilePath;
using std::string;
using std::unique_ptr;

namespace oobe_config {

LoadOobeConfigRollback::LoadOobeConfigRollback(OobeConfig* oobe_config,
                                               FileHandler file_handler)
    : file_handler_(std::move(file_handler)), oobe_config_(oobe_config) {}

bool LoadOobeConfigRollback::GetOobeConfigJson(string* config,
                                               string* enrollment_domain) {
  LOG(INFO) << "Looking for rollback state.";

  *config = "";
  *enrollment_domain = "";

  // Restore path is created by tmpfiles config.
  CHECK(file_handler_.HasRestorePath());

  if ((file_handler_.HasOpensslEncryptedRollbackData() ||
       file_handler_.HasTpmEncryptedRollbackData()) &&
      !file_handler_.HasDecryptedRollbackData()) {
    LOG(INFO) << "Decrypting rollback data.";

    bool restore_result = oobe_config_->EncryptedRollbackRestore();

    if (!restore_result) {
      LOG(ERROR)
          << "Failed to decrypt rollback data. This is expected in rare cases, "
             "e.g. when the TPM was cleared again during rollback OOBE.";
      metrics_uma_.RecordRestoreResult(
          MetricsUMA::OobeRestoreResult::kStage1Failure);
      return false;
    }
  }

  if (file_handler_.HasDecryptedRollbackData()) {
    string rollback_data_str;
    if (!file_handler_.ReadDecryptedRollbackData(&rollback_data_str)) {
      LOG(ERROR) << "Could not read decrypted rollback data file.";
      metrics_uma_.RecordRestoreResult(
          MetricsUMA::OobeRestoreResult::kStage3Failure);
      return false;
    }
    RollbackData rollback_data;
    if (!rollback_data.ParseFromString(rollback_data_str)) {
      LOG(ERROR) << "Couldn't parse proto.";
      metrics_uma_.RecordRestoreResult(
          MetricsUMA::OobeRestoreResult::kStage3Failure);
      return false;
    }
    // We get the data for Chrome and assemble the config.
    if (!AssembleConfig(rollback_data, config)) {
      LOG(ERROR) << "Failed to assemble config.";
      metrics_uma_.RecordRestoreResult(
          MetricsUMA::OobeRestoreResult::kStage3Failure);
      return false;
    }

    LOG(INFO) << "Rollback restore completed successfully.";
    metrics_uma_.RecordRestoreResult(MetricsUMA::OobeRestoreResult::kSuccess);
    return true;
  }

  return false;
}

bool LoadOobeConfigRollback::AssembleConfig(const RollbackData& rollback_data,
                                            string* config) {
  // Possible values are defined in
  // chrome/browser/resources/chromeos/login/components/oobe_types.js.
  // TODO(zentaro): Export these strings as constants.
  base::Value::Dict dictionary;
  // Always skip next screen.
  dictionary.Set("welcomeNext", true);
  // Always skip network selection screen if possible.
  dictionary.Set("networkUseConnected", true);
  // Set whether metrics should be enabled if it exists in |rollback_data|.
  dictionary.Set("eulaSendStatistics", rollback_data.eula_send_statistics());
  // Set whether the EULA as already accepted and can be skipped if the field is
  // present in |rollback_data|.
  dictionary.Set("eulaAutoAccept", rollback_data.eula_auto_accept());
  // Tell Chrome that it still has to create some robot accounts that were
  // destroyed during rollback.
  dictionary.Set("enrollmentRestoreAfterRollback", true);
  // Send network config to Chrome. Chrome takes care of how to reconfigure the
  // networks.
  dictionary.Set("networkConfig", rollback_data.network_config());

  return base::JSONWriter::Write(dictionary, config);
}

}  // namespace oobe_config
