// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef CRYPTOHOME_PERSISTENT_LOOKUP_TABLE_H_
#define CRYPTOHOME_PERSISTENT_LOOKUP_TABLE_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>

#include "cryptohome/platform.h"

namespace cryptohome {

// Return values used by various functions of PersistentLookupTable.
enum PLTError {
  PLT_SUCCESS = 0,
  PLT_KEY_NOT_FOUND,
  PLT_STORAGE_ERROR,
};

// This class is used to look up and store values, given uint64_t keys.
// We use a directory to store the values.
//
// Each value is stored in a file. Each key will have a directory with the
// name being a string version of the key, and inside it
// whenever an update is made to a value, a new version is stored in a file name
// where the version number is incremented by 1.
//
// The lowest valid file version number is 1.
//
// Periodically older versions of keys will be deleted (this
// will happen only if there is > 1 version of a key).
//
// For further context, it is expected that this data structure will be used
// to store the leaf nodes of a hash tree. Each leaf node will contain sign-in
// credential meta data (this includes low-entropy (e.g PIN) as well as
// high-entropy (i.e user passphrase) credentials). Each leaf node of the hash
// tree will be referenced by a bit-string label.
//
// The key's bit-string can be used to determine the leaf's position in the hash
// tree. That, coupled with the fan-out factory of the tree (K), can be used to
// determine the labels required to compute the auxilliary hashes needed to
// determine the root hash.
//
// As an example, consider the following bit string label for a tree with
// fan-out = 4 : "0101001" By dropping the last log2(K) = 2 bits, and using the
// remainder as a prefix, we can calculate the auxiliary labels needed:
//
// "01010" + {"00", "10", "11"} = "0101000", "0101010", "0101011".
//
// These can be used to obtain the hash of inner label "01010". This step can
// then be performed recursively to obtain the root hash for label "".
//
// The values will be stored in files with names of the form "<version>.value",
// where |version| denotes the version number of that key value.
//
// NOTE: An empty value file is used as a marker that a key has been removed,
// and marked for deletion. It is forbidden to store key values which are
// empty.
class PersistentLookupTable {
 public:
  PersistentLookupTable(Platform* platform, base::FilePath basedir);
  ~PersistentLookupTable() = default;

  // Initializes the lookup table data structure and backing storage directory.
  // Load in the contents of an existing table if one already exists.
  //
  // This function also removes all old versions of all keys.
  bool InitOnBoot();

  // Retrieves a value, which will be placed in |value|, given a |key|.
  // This function returns:
  // - PLT_SUCCESS if we could successfully retrieve the key value,
  // - PLT_KEY_NOT_FOUND if |key| doesn't exist.
  // - PLT_STORAGE_ERROR for errors reading the PLT.
  //
  // The |value| vector is supplied by the caller, and is filled only when the
  // return type is PLT_SUCCESS.
  //
  // Also note that during RemoveKey(), an empty value is written to
  // the key directory to ensure that the key deletion is persisted.
  // GetValue() inspects the read |value| to make sure that it isn't the empty
  // version, and it returns PLT_KEY_NOT_FOUND if so.
  PLTError GetValue(const uint64_t key, std::vector<uint8_t>* value);

  // Stores a new value at a given key location.
  // This function returns:
  // - PLT_SUCCESS on success,
  // - PLT_STORAGE_ERROR on failure.
  //
  // It is expected that this function will persist the updated value to disk.
  PLTError StoreValue(const uint64_t key, const std::vector<uint8_t>& new_val);

  // Removes a key and its corresponding value from the look-up table.
  // All versions of the key will need to be removed from the table and
  // its associated storage.
  //
  // In order to ensure that a delete does not get lost across corruption, we
  // first write an empty file as a new version to the key directory.
  // We then invoke the directory deletion. This way, even if there was a
  // failure between creating a new file version and calling the directory
  // delete, we still have a way of ascertaining that the key has been removed.
  //
  // This function returns:
  // - PLT_SUCCESS if we are able to delete the key successfully,
  // - PLT_STORAGE_ERROR if we encountered an issue deleting the key.
  PLTError RemoveKey(const uint64_t key);

  // Returns |true| if an entry exists for |key|, and |false| otherwise.
  bool KeyExists(const uint64_t key);

  // Obtains a list of currently used keys and places them in |key_list|.
  void GetUsedKeys(std::vector<uint64_t>* key_list);

 private:
  friend class PersistentLookupTableTest;
  FRIEND_TEST(PersistentLookupTableTest, CreateDirStoreValues);
  FRIEND_TEST(PersistentLookupTableTest, RestoreTable);

  // Finds the latest verified version number for a key.
  // Returns a non-zero version number on success, 0 otherwise.
  // NOTE: We assume that the minimum version number is 1.
  // A return value of 0 may mean either:
  // - The key directory doesn't exist, or
  // - The directory exists, but no valid file exists inside it.
  uint32_t FindLatestVersion(const uint64_t key);

  // Delete all the versions of a key, except the version specified in
  // |version_to_save|. If |version_to_save| is 0, remove the entire key
  // directory.
  void DeleteOldKeyVersions(const uint64_t key, uint32_t version_to_save);

  Platform* platform_;

  // Convenience member to store the lookup table directory path.
  base::FilePath table_dir_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_PERSISTENT_LOOKUP_TABLE_H_
