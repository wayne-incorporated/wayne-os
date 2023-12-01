// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/shill_config.h"

namespace shill {

namespace {

const char kDefaultRunDirectory[] = RUNDIR;
const char kDefaultStorageDirectory[] = "/var/cache/shill";
const char kDefaultUserStorageDirectory[] = RUNDIR "/user_profiles/";

}  // namespace

Config::Config() = default;

Config::~Config() = default;

std::string Config::GetRunDirectory() const {
  return kDefaultRunDirectory;
}

std::string Config::GetStorageDirectory() const {
  return kDefaultStorageDirectory;
}

std::string Config::GetUserStorageDirectory() const {
  return kDefaultUserStorageDirectory;
}

}  // namespace shill
