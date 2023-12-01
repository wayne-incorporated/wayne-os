// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>
#include <base/files/scoped_temp_dir.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/files/file_path.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>

#include "oobe_config/filesystem/file_handler_for_testing.h"
#include "oobe_config/load_oobe_config_rollback.h"
#include "oobe_config/oobe_config.h"
#include "oobe_config/rollback_data.pb.h"

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
};

namespace oobe_config {

// Fuzzes content of RollbackData proto. There is a separate fuzzer for
// encryption and decryption, we can skip that part of
// `load_oobe_config_rollback` and only fuzz everything that happens after
// reading the unencrypted proto from disk.
DEFINE_PROTO_FUZZER(const RollbackData& input) {
  static Environment env;

  std::string serialized_input;
  CHECK(input.SerializeToString(&serialized_input));

  // TODO(b/234826714): Pass data directly to load_config instead of relying on
  // files. Could use a fake file handler to easily do so.
  FileHandlerForTesting file_handler;
  CHECK(file_handler.WriteDecryptedRollbackData(serialized_input));

  OobeConfig oobe_config(nullptr, file_handler);
  LoadOobeConfigRollback load_config(&oobe_config, file_handler);

  std::string config, enrollment_domain;
  CHECK(load_config.GetOobeConfigJson(&config, &enrollment_domain));

  auto root = base::JSONReader::Read(config);
  CHECK(root);
  auto dict = root->GetIfDict();
  CHECK(dict != nullptr);

  auto networkConfig = dict->FindString("networkConfig");
  CHECK(networkConfig != nullptr);
  CHECK_EQ(*networkConfig, input.network_config());
}

}  // namespace oobe_config
