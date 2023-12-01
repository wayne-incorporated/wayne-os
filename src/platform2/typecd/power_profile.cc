// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/power_profile.h"

#include <utility>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/logging.h>

namespace {

constexpr char kSinkCapsDir[] = "sink-capabilities";
constexpr char kSourceCapsDir[] = "source-capabilities";

}  // namespace

namespace typecd {

PowerProfile::PowerProfile(const base::FilePath& syspath) : syspath_(syspath) {
  ParseSourceCaps();
  ParseSinkCaps();
  LOG(INFO) << "Registered a power profile with path: " << syspath_;
}

void PowerProfile::ParseSinkCaps() {
  auto source_dir = syspath_.Append(kSinkCapsDir);
  base::FileEnumerator iter(source_dir, false,
                            base::FileEnumerator::DIRECTORIES);
  for (auto path = iter.Next(); !path.empty(); path = iter.Next()) {
    auto pdo = CreatePdo(path);
    if (!pdo)
      continue;

    sink_caps_.emplace(pdo->GetIndex(), std::move(pdo));
  }
}

void PowerProfile::ParseSourceCaps() {
  auto source_dir = syspath_.Append(kSourceCapsDir);
  base::FileEnumerator iter(source_dir, false,
                            base::FileEnumerator::DIRECTORIES);
  for (auto path = iter.Next(); !path.empty(); path = iter.Next()) {
    auto pdo = CreatePdo(path);
    if (!pdo)
      continue;

    source_caps_.emplace(pdo->GetIndex(), std::move(pdo));
  }
}

std::unique_ptr<Pdo> PowerProfile::CreatePdo(const base::FilePath& path) {
  return Pdo::MakePdo(path);
}

}  // namespace typecd
