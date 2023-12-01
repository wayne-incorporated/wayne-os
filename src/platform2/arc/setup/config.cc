// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/config.h"

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

namespace arc {

namespace {

// Performs a best-effort conversion of the input string to a boolean type,
// setting |*out| to the result of the conversion.  Returns true for successful
// conversions.
bool StringToBool(const std::string str, bool* out) {
  if (str == "0" || base::EqualsCaseInsensitiveASCII(str, "false")) {
    *out = false;
    return true;
  }
  if (str == "1" || base::EqualsCaseInsensitiveASCII(str, "true")) {
    *out = true;
    return true;
  }
  return false;
}

}  // namespace

Config::Config(const base::FilePath& config_json,
               std::unique_ptr<base::Environment> config_env)
    : env_(std::move(config_env)) {
  if (!config_json.empty())
    CHECK(ParseJsonFile(config_json));
}

Config::~Config() = default;

bool Config::GetString(base::StringPiece name, std::string* out) const {
  base::Value* config = FindConfig(name);
  if (config) {
    if (const std::string* val = config->GetIfString()) {
      *out = *val;
      return true;
    }
    return false;
  }
  return env_->GetVar(name, out);
}

bool Config::GetInt(base::StringPiece name, int* out) const {
  base::Value* config = FindConfig(name);
  if (config) {
    if (std::optional<int> val = config->GetIfInt()) {
      *out = *val;
      return true;
    }
    return false;
  }
  std::string env_str;
  return env_->GetVar(name, &env_str) && base::StringToInt(env_str, out);
}

bool Config::GetBool(base::StringPiece name, bool* out) const {
  base::Value* config = FindConfig(name);
  if (config) {
    if (std::optional<bool> val = config->GetIfBool()) {
      *out = *val;
      return true;
    }
    return false;
  }
  std::string env_str;
  return env_->GetVar(name, &env_str) && StringToBool(env_str, out);
}

std::string Config::GetStringOrDie(base::StringPiece name) const {
  std::string ret;
  CHECK(GetString(name, &ret)) << name;
  return ret;
}

int Config::GetIntOrDie(base::StringPiece name) const {
  int ret;
  CHECK(GetInt(name, &ret)) << name;
  return ret;
}

bool Config::GetBoolOrDie(base::StringPiece name) const {
  bool ret;
  CHECK(GetBool(name, &ret)) << name;
  return ret;
}

bool Config::ParseJsonFile(const base::FilePath& config_json) {
  std::string json_str;
  if (!base::ReadFileToString(config_json, &json_str)) {
    PLOG(ERROR) << "Failed to read json string from " << config_json.value();
    return false;
  }

  auto result = base::JSONReader::ReadAndReturnValueWithError(
      json_str, base::JSON_PARSE_RFC);
  if (!result.has_value()) {
    LOG(ERROR) << "Failed to parse json: " << result.error().message;
    return false;
  }

  if (!result->is_dict()) {
    LOG(ERROR) << "Failed to read json as dictionary";
    return false;
  }

  for (const auto& item : result->GetDict()) {
    if (!json_
             .emplace(item.first,
                      base::Value::ToUniquePtrValue(std::move(item.second)))
             .second) {
      LOG(ERROR) << "The config " << item.first
                 << " appeared twice in the file.";
      return false;
    }
  }
  return true;
}

base::Value* Config::FindConfig(base::StringPiece name) const {
  auto it = json_.find(name);
  if (it == json_.end())
    return nullptr;
  return it->second.get();
}

}  // namespace arc
