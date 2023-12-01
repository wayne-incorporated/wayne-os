// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/pdo.h"

#include <string>

#include <base/files/file_util.h>
#include <re2/re2.h>

namespace {
// PDOs can have index 1 to 7.
constexpr int kMaxPdoIndex = 7;
constexpr char kPdoTypeRegex[] = R"((\d):(\w+))";

// Helper function to map type names to their corresponding enum.
typecd::Pdo::Type ParseType(const std::string& type) {
  if (type == "fixed_supply")
    return typecd::Pdo::Type::kFixedSupply;
  else if (type == "variable_supply")
    return typecd::Pdo::Type::kVariableSupply;
  else if (type == "battery")
    return typecd::Pdo::Type::kBattery;
  else if (type == "programmable_supply")
    return typecd::Pdo::Type::kPPS;
  else
    return typecd::Pdo::Type::kNone;
}

}  // namespace

namespace typecd {

std::unique_ptr<Pdo> Pdo::MakePdo(const base::FilePath& syspath) {
  if (!base::DirectoryExists(syspath)) {
    LOG(ERROR) << "Invalid path for PDO: " << syspath;
    return nullptr;
  }

  int index;
  std::string type_str;
  if (!RE2::FullMatch(syspath.BaseName().value(), kPdoTypeRegex, &index,
                      &type_str))
    return nullptr;

  auto type = ParseType(type_str);
  if (type == Type::kNone) {
    LOG(ERROR) << "Invalid PDO type, path: " << syspath;
    return nullptr;
  }

  if (index < 1 || index > kMaxPdoIndex) {
    LOG(ERROR) << "Invalid PDO index, path: " << syspath;
    return nullptr;
  }

  return std::make_unique<Pdo>(syspath, type, index);
}

Pdo::Pdo(const base::FilePath& syspath, Pdo::Type type, int index)
    : syspath_(syspath), type_(type), index_(index) {}

}  // namespace typecd
