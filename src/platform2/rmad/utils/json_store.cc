// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/json_store.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/json/json_file_value_serializer.h>
#include <base/json/json_string_value_serializer.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/values.h>
#include <brillo/file_utils.h>

namespace rmad {

namespace {

JsonStore::ReadError TranslateJsonFileReadErrors(const base::Value* value,
                                                 int error_code) {
  if (!value) {
    switch (error_code) {
      case JSONFileValueDeserializer::JSON_ACCESS_DENIED:
        return JsonStore::READ_ERROR_FILE_ACCESS_DENIED;
      case JSONFileValueDeserializer::JSON_CANNOT_READ_FILE:
        return JsonStore::READ_ERROR_FILE_OTHER;
      case JSONFileValueDeserializer::JSON_FILE_LOCKED:
        return JsonStore::READ_ERROR_FILE_LOCKED;
      case JSONFileValueDeserializer::JSON_NO_SUCH_FILE:
        return JsonStore::READ_ERROR_NO_SUCH_FILE;
      default:
        // JSONParser::JsonParseError errors.
        return JsonStore::READ_ERROR_JSON_PARSE;
    }
  }
  if (!value->is_dict())
    return JsonStore::READ_ERROR_JSON_TYPE;
  return JsonStore::READ_ERROR_NONE;
}

bool SerializeValue(const base::Value::Dict& value, std::string* output) {
  JSONStringValueSerializer serializer(output);
  serializer.set_pretty_print(false);
  return serializer.Serialize(value);
}

}  // namespace

struct JsonStore::ReadResult {
 public:
  ReadResult() = default;
  ~ReadResult() = default;

  std::unique_ptr<base::Value> value;
  JsonStore::ReadError read_error;
};

JsonStore::JsonStore(const base::FilePath& file_path) : file_path_(file_path) {
  InitFromFile();
}

bool JsonStore::SetValue(const std::string& key, base::Value&& value) {
  if (read_only_) {
    return false;
  }
  const base::Value* result = data_.Find(key);
  if (!result || *result != value) {
    std::optional<base::Value> result_backup =
        result ? std::make_optional(result->Clone()) : std::nullopt;
    data_.Set(key, std::move(value));
    bool ret = WriteToFile();
    if (!ret) {
      if (result_backup) {
        data_.Set(key, std::move(*result_backup));
      } else {
        data_.Remove(key);
      }
      read_only_ = true;
    }
    return ret;
  }
  return true;
}

bool JsonStore::GetValue(const std::string& key,
                         const base::Value** value) const {
  const base::Value* result = data_.Find(key);
  if (!result) {
    return false;
  }
  if (value) {
    *value = result;
  }
  return true;
}

bool JsonStore::GetValue(const std::string& key, base::Value* value) const {
  const base::Value* result;
  if (!GetValue(key, &result)) {
    return false;
  }
  if (value) {
    *value = result->Clone();
  }
  return true;
}

base::Value::Dict JsonStore::GetValues() const {
  return data_.Clone();
}

bool JsonStore::RemoveKey(const std::string& key) {
  if (read_only_) {
    return false;
  }

  const base::Value* result = data_.Find(key);
  if (result) {
    base::Value result_backup = result->Clone();
    data_.Remove(key);
    bool ret = WriteToFile();
    if (!ret) {
      data_.Set(key, std::move(result_backup));
      read_only_ = true;
    }
    return ret;
  }
  return false;
}

bool JsonStore::Clear() {
  data_ = base::Value::Dict();
  return WriteToFile(true);
}

bool JsonStore::ClearAndDeleteFile() {
  return Clear() && base::DeleteFile(file_path_);
}

bool JsonStore::Sync() const {
  return brillo::SyncFileOrDirectory(file_path_, false, true);
}

bool JsonStore::InitFromFile() {
  std::unique_ptr<JsonStore::ReadResult> read_result = ReadFromFile();
  data_ = base::Value::Dict();
  read_only_ = false;
  read_error_ = read_result->read_error;
  switch (read_error_) {
    case READ_ERROR_JSON_PARSE:
    case READ_ERROR_JSON_TYPE:
    case READ_ERROR_FILE_ACCESS_DENIED:
    case READ_ERROR_FILE_LOCKED:
    case READ_ERROR_FILE_OTHER:
      read_only_ = true;
      break;
    case READ_ERROR_NONE:
      // A result with non-dict-type value will have READ_ERROR_JSON_TYPE error.
      data_ = std::move(read_result->value->GetDict());
      break;
    case READ_ERROR_NO_SUCH_FILE:
      break;
    case READ_ERROR_MAX_ENUM:
      NOTREACHED();
      break;
  }
  // Check if we can write to the file.
  if (!read_only_) {
    read_only_ &= WriteToFile();
  }
  VLOG(2) << "JsonStore::InitFromFile complete.";
  return !read_only_;
}

std::unique_ptr<JsonStore::ReadResult> JsonStore::ReadFromFile() {
  auto read_result = std::make_unique<JsonStore::ReadResult>();
  JSONFileValueDeserializer deserializer(file_path_);
  int error_code = 0;
  std::string error_msg;
  read_result->value = deserializer.Deserialize(&error_code, &error_msg);
  read_result->read_error =
      TranslateJsonFileReadErrors(read_result->value.get(), error_code);
  return read_result;
}

bool JsonStore::WriteToFile(bool force) {
  if (read_only_ && !force)
    return false;

  std::string serialized_data;
  if (!SerializeValue(data_, &serialized_data)) {
    DLOG(ERROR) << "JsonStore::WriteToFile failed to serialize data.";
    return false;
  }
  return base::WriteFile(file_path_, serialized_data);
}

}  // namespace rmad
