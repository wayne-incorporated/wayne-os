// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/biod_storage.h"

#include <stddef.h>
#include <stdint.h>

#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/values.h>
#include <openssl/sha.h>

using Record = biod::BiodStorageInterface::Record;
using RecordMetadata = biod::BiodStorageInterface::RecordMetadata;

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  int MAX_LEN = 255;
  int MAX_DATA_LEN = 45000;

  FuzzedDataProvider data_provider(data, size);

  int id_len = data_provider.ConsumeIntegralInRange<int32_t>(1, MAX_LEN);
  int user_id_len = data_provider.ConsumeIntegralInRange<int32_t>(1, MAX_LEN);
  int label_len = data_provider.ConsumeIntegralInRange<int32_t>(1, MAX_LEN);
  int data_len = data_provider.ConsumeIntegralInRange<int32_t>(
      MAX_DATA_LEN - 1000, MAX_DATA_LEN);

  const int version = data_provider.ConsumeIntegral<int>();
  const std::string id = data_provider.ConsumeBytesAsString(id_len);
  const std::string user_id = data_provider.ConsumeBytesAsString(user_id_len);
  const std::string label = data_provider.ConsumeBytesAsString(label_len);
  std::vector<uint8_t> validation_val =
      data_provider.ConsumeBytes<uint8_t>(SHA256_DIGEST_LENGTH);

  std::vector<uint8_t> biod_data;

  if (data_provider.remaining_bytes() > data_len)
    biod_data = data_provider.ConsumeBytes<uint8_t>(data_len);
  else
    biod_data = data_provider.ConsumeRemainingBytes<uint8_t>();

  biod::BiodStorage biod_storage = biod::BiodStorage("BiometricsManager");
  biod_storage.set_allow_access(true);

  RecordMetadata record_metadata = {version, id, user_id, label,
                                    validation_val};

  base::FilePath root_path("/tmp/biod_storage_fuzzing_data");
  biod_storage.SetRootPathForTesting(root_path);
  bool status =
      biod_storage.WriteRecord(record_metadata, base::Value(biod_data));
  if (status) {
    biod_storage.ReadRecordsForSingleUser(user_id);
  }

  return 0;
}
