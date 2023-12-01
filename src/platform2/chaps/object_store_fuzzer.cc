// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "chaps/object_store_impl.h"

class Environment {
 public:
  Environment() {
    // Disable logging.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
  }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);
  chaps::ObjectStoreImpl store;
  chaps::ChapsMetrics metrics;
  base::ScopedTempDir tmp_dir;
  CHECK(tmp_dir.CreateUniqueTempDir());
  store.Init(tmp_dir.GetPath(), &metrics);
  std::string encryption_key = data_provider.ConsumeBytesAsString(32);
  if (encryption_key.size() < 32) {
    // We won't have any data to fuzz further, so no reason to even continue.
    return 0;
  }
  store.SetEncryptionKey(brillo::SecureBlob(encryption_key));

  // Randomly decide on operations to perform and save our last few blob_id's so
  // that we can have valid ones to target better as well.
  constexpr int kMaxBlobLength = 128;
  std::vector<int> inserted_blob_ids;
  // Grab the 3 bools for randomness on the final 3 operations now.
  bool load_public_objects = data_provider.ConsumeBool();
  bool load_private_objects = data_provider.ConsumeBool();
  bool delete_all_objects = data_provider.ConsumeBool();
  while (data_provider.remaining_bytes()) {
    if (data_provider.ConsumeBool()) {
      // Insert a new object.
      int blob_id;
      if (store.InsertObjectBlob(
              {data_provider.ConsumeRandomLengthString(kMaxBlobLength),
               data_provider.ConsumeBool()},
              &blob_id)) {
        inserted_blob_ids.push_back(blob_id);
      }
    }
    if (data_provider.ConsumeBool()) {
      // Update an object, randomly decide to update an existing one or use a
      // random new ID.
      if (!inserted_blob_ids.empty() && data_provider.ConsumeBool()) {
        // Use an existing ID.
        int blob_id =
            inserted_blob_ids[data_provider.ConsumeIntegralInRange<int>(
                0, inserted_blob_ids.size() - 1)];
        store.UpdateObjectBlob(
            blob_id, {data_provider.ConsumeRandomLengthString(kMaxBlobLength),
                      data_provider.ConsumeBool()});
      } else {
        // Generate a random blob ID for an update, if this succeeds add it to
        // the list of inserted IDs.
        int blob_id = data_provider.ConsumeIntegral<int>();
        if (store.UpdateObjectBlob(
                blob_id,
                {data_provider.ConsumeRandomLengthString(kMaxBlobLength),
                 data_provider.ConsumeBool()})) {
          inserted_blob_ids.push_back(blob_id);
        }
      }
    }
    if (data_provider.ConsumeBool()) {
      // Delete an object.
      if (!inserted_blob_ids.empty() && data_provider.ConsumeBool()) {
        // Delete an existing object and remove it's ID from our list.
        int random_index = data_provider.ConsumeIntegralInRange<int>(
            0, inserted_blob_ids.size() - 1);
        int blob_id = inserted_blob_ids[random_index];
        inserted_blob_ids.erase(inserted_blob_ids.begin() + random_index);
        store.DeleteObjectBlob(blob_id);
      } else {
        // Delete a random object ID.
        store.DeleteObjectBlob(data_provider.ConsumeIntegral<int>());
      }
    }
  }

  // Randomly decide to load objects and delete them all.
  std::map<int, chaps::ObjectBlob> blobs;
  if (load_public_objects) {
    store.LoadPublicObjectBlobs(&blobs);
  }
  if (load_private_objects) {
    store.LoadPrivateObjectBlobs(&blobs);
  }
  if (delete_all_objects) {
    store.DeleteAllObjectBlobs();
  }

  return 0;
}
