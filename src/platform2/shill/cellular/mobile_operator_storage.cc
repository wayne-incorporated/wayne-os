// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mobile_operator_storage.h"

#include <memory>
#include <utility>

#include <base/containers/contains.h>

#include "shill/logging.h"
#include "shill/protobuf_lite_streams.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kCellular;
}  // namespace Logging

MobileOperatorStorage::MobileOperatorStorage() = default;

MobileOperatorStorage::~MobileOperatorStorage() = default;

MobileOperatorStorage* MobileOperatorStorage::GetInstance() {
  static base::NoDestructor<MobileOperatorStorage> instance;
  return instance.get();
}

const mobile_operator_db::MobileOperatorDB* MobileOperatorStorage::GetDatabase(
    const base::FilePath& absolute_path) {
  SLOG(3) << __func__ << " : " << absolute_path.value().c_str();
  const auto database_path = absolute_path.value();
  if (!base::Contains(databases_, database_path)) {
    const char* database_path_cstr = database_path.c_str();
    std::unique_ptr<google::protobuf::io::CopyingInputStreamAdaptor>
        database_stream;
    database_stream.reset(protobuf_lite_file_input_stream(database_path_cstr));
    if (!database_stream) {
      LOG(ERROR) << "Failed to read mobile operator database: "
                 << database_path_cstr;
      return nullptr;
    }

    shill::mobile_operator_db::MobileOperatorDB database;
    if (!database.ParseFromZeroCopyStream(database_stream.get())) {
      LOG(ERROR) << "Could not parse mobile operator database: "
                 << database_path_cstr;
      return nullptr;
    }
    databases_[database_path] =
        std::make_unique<const shill::mobile_operator_db::MobileOperatorDB>(
            std::move(database));
    SLOG(1) << "Successfully loaded database: " << database_path_cstr;
  }
  return databases_[database_path].get();
}

void MobileOperatorStorage::ClearDatabases() {
  databases_.clear();
}

}  // namespace shill
