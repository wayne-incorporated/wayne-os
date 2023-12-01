// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/utils.h"

#include <string>
#include <vector>

#include <base/strings/stringprintf.h>
#include <re2/re2.h>

namespace federated {

namespace {
using ::chromeos::federated::mojom::ExamplePtr;
using ::chromeos::federated::mojom::FloatList;
using ::chromeos::federated::mojom::Int64List;
using ::chromeos::federated::mojom::ValueList;

constexpr char kVersionPrefix[] = "chromeos";
}  // namespace

// TODO(alanlxl):  just random numbers, need a discussion
constexpr size_t kMaxStreamingExampleCount = 4000;
constexpr size_t kMinExampleCount = 1;

constexpr char kSessionStartedState[] = "started";
constexpr char kSessionStoppedState[] = "stopped";
constexpr char kUserDatabasePath[] = "/run/daemon-store/federated";
constexpr char kDatabaseFileName[] = "examples.db";

// Get the database file path with the given sanitized_username.
base::FilePath GetDatabasePath(const std::string& sanitized_username) {
  return base::FilePath(kUserDatabasePath)
      .Append(sanitized_username)
      .Append(kDatabaseFileName);
}

base::FilePath GetBaseDir(const std::string& sanitized_username,
                          const std::string& client_name) {
  return base::FilePath(kUserDatabasePath)
      .Append(sanitized_username)
      .Append(client_name);
}

tensorflow::Example ConvertToTensorFlowExampleProto(const ExamplePtr& example) {
  tensorflow::Example tf_example;
  auto& feature = *tf_example.mutable_features()->mutable_feature();

  for (const auto& iter : example->features->feature) {
    if (iter.second->which() == ValueList::Tag::kInt64List) {
      const std::vector<int64_t>& value_list =
          iter.second->get_int64_list()->value;
      *feature[iter.first].mutable_int64_list()->mutable_value() = {
          value_list.begin(), value_list.end()};
    } else if (iter.second->which() == ValueList::Tag::kFloatList) {
      const std::vector<double>& value_list =
          iter.second->get_float_list()->value;
      *feature[iter.first].mutable_float_list()->mutable_value() = {
          value_list.begin(), value_list.end()};
    } else if (iter.second->which() == ValueList::Tag::kStringList) {
      const std::vector<std::string>& value_list =
          iter.second->get_string_list()->value;
      *feature[iter.first].mutable_bytes_list()->mutable_value() = {
          value_list.begin(), value_list.end()};
    }
  }
  return tf_example;
}

std::optional<std::string> ConvertBrellaLibVersion(
    const std::string& release_version) {
  int major_version, minor_version, sub_version;
  if (!RE2::FullMatch(release_version, R"((\d{1,9})\.(\d{1,6})\.(\d{1,4}))",
                      &major_version, &minor_version, &sub_version)) {
    LOG(ERROR) << "Cannot parse release_version " << release_version;
    return std::nullopt;
  }
  return base::StringPrintf("%s_%d%06d%04d", kVersionPrefix, major_version,
                            minor_version, sub_version);
}

}  // namespace federated
