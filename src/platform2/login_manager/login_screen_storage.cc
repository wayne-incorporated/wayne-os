// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/login_screen_storage.h"

#include <utility>

#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <crypto/sha2.h>
#include <dbus/bus.h>

#include "login_manager/dbus_util.h"
#include "login_manager/login_screen_storage/login_screen_storage_index.pb.h"
#include "login_manager/secret_util.h"

namespace login_manager {

const char kLoginScreenStorageIndexFilename[] = "index";

LoginScreenStorage::LoginScreenStorage(
    const base::FilePath& persistent_storage_path,
    std::unique_ptr<secret_util::SharedMemoryUtil> shared_memory_util)
    : persistent_storage_path_(persistent_storage_path),
      shared_memory_util_(std::move(shared_memory_util)) {}

bool LoginScreenStorage::Store(brillo::ErrorPtr* error,
                               const std::string& key,
                               const LoginScreenStorageMetadata& metadata,
                               uint64_t value_size,
                               const base::ScopedFD& value_fd) {
  LoginScreenStorageIndex index = ReadIndexFromFile();
  std::vector<uint8_t> value;
  if (!shared_memory_util_->ReadDataFromSharedMemory(value_fd, value_size,
                                                     &value)) {
    *error = CreateError(DBUS_ERROR_IO_ERROR,
                         "couldn't read value from shared memory.");
    return false;
  }

  // Removing the old value from both storages to make sure it's not duplicated.
  RemoveKeyFromLoginScreenStorage(&index, key);

  if (metadata.clear_on_session_exit()) {
    in_memory_storage_[key] = std::move(value);
    return true;
  }

  base::FilePath storage_dir_path(persistent_storage_path_);
  if (!base::DirectoryExists(storage_dir_path) &&
      !base::CreateDirectory(storage_dir_path)) {
    *error = CreateError(DBUS_ERROR_IO_ERROR,
                         "couldn't create login screen storage directory.");
    return false;
  }

  index.add_keys(key);
  if (!WriteIndexToFile(index)) {
    *error =
        CreateError(DBUS_ERROR_IO_ERROR, "Couldn't write index file to disk.");
    // Removing a key that has already been saved.
    RemoveKeyFromLoginScreenStorage(&index, key);
    return false;
  }

  if (base::WriteFile(GetPersistentStoragePathForKey(key),
                      reinterpret_cast<char*>(value.data()),
                      value.size()) != value.size()) {
    *error = CreateError(DBUS_ERROR_IO_ERROR,
                         "couldn't write key/value pair to the disk.");
    return false;
  }

  return true;
}

bool LoginScreenStorage::Retrieve(brillo::ErrorPtr* error,
                                  const std::string& key,
                                  uint64_t* out_value_size,
                                  base::ScopedFD* out_value_fd) {
  auto value_iter = in_memory_storage_.find(key);
  if (value_iter != in_memory_storage_.end()) {
    *out_value_size = value_iter->second.size();
    return CreateSharedMemoryWithData(error, value_iter->second, out_value_fd);
  }

  base::FilePath value_path = GetPersistentStoragePathForKey(key);
  std::string value;
  if (!base::PathExists(value_path) ||
      !base::ReadFileToStringWithMaxSize(
          value_path, &value, secret_util::kSharedMemorySecretSizeLimit)) {
    *error = CreateError(DBUS_ERROR_INVALID_ARGS,
                         "no value was found for the given key.");
    return false;
  }
  *out_value_size = value.size();
  return CreateSharedMemoryWithData(
      error, std::vector<uint8_t>(value.begin(), value.end()), out_value_fd);
}

std::vector<std::string> LoginScreenStorage::ListKeys() {
  std::vector<std::string> keys;
  for (const auto& kv : in_memory_storage_) {
    keys.push_back(kv.first);
  }
  LoginScreenStorageIndex index = ReadIndexFromFile();
  auto persistent_keys = index.keys();
  keys.insert(keys.end(), persistent_keys.begin(), persistent_keys.end());
  return keys;
}

void LoginScreenStorage::Delete(const std::string& key) {
  LoginScreenStorageIndex index = ReadIndexFromFile();
  RemoveKeyFromLoginScreenStorage(&index, key);
}

base::FilePath LoginScreenStorage::GetPersistentStoragePathForKey(
    const std::string& key) {
  return base::FilePath(persistent_storage_path_)
      .Append(secret_util::StringToSafeFilename(key));
}

void LoginScreenStorage::RemoveKeyFromLoginScreenStorage(
    LoginScreenStorageIndex* index, const std::string& key) {
  in_memory_storage_.erase(key);

  // Removing key from the persistent storage.
  auto* keys = index->mutable_keys();
  auto removed_key_it = std::find(keys->begin(), keys->end(), key);
  if (removed_key_it != keys->end()) {
    keys->erase(removed_key_it);
    // Deleting the file first and then updating the index. So if a crash
    // happens in between, we don't have an incorrect state (a key is present,
    // but not listed by |ListKeys()|).
    base::DeleteFile(GetPersistentStoragePathForKey(key));
    WriteIndexToFile(*index);
  }
}

LoginScreenStorageIndex LoginScreenStorage::ReadIndexFromFile() {
  std::string index_blob;
  LoginScreenStorageIndex index;
  if (base::ReadFileToString(
          persistent_storage_path_.Append(kLoginScreenStorageIndexFilename),
          &index_blob))
    index.ParseFromString(index_blob);
  return index;
}

bool LoginScreenStorage::WriteIndexToFile(
    const LoginScreenStorageIndex& index) {
  const std::string index_blob = index.SerializeAsString();
  return base::WriteFile(
      persistent_storage_path_.Append(kLoginScreenStorageIndexFilename),
      index_blob.data(), index_blob.size());
}

bool LoginScreenStorage::CreateSharedMemoryWithData(
    brillo::ErrorPtr* error,
    const std::vector<uint8_t>& data,
    base::ScopedFD* out_shared_memory_fd) {
  *out_shared_memory_fd = shared_memory_util_->WriteDataToSharedMemory(data);
  if (!out_shared_memory_fd->is_valid()) {
    *error = CreateError(DBUS_ERROR_IO_ERROR, "couldn't create shared memory.");
    return false;
  }
  return true;
}

}  //  namespace login_manager
