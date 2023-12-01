// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/landlock_policy.h"

namespace login_manager {

namespace {

// Landlock allowlisted paths.
constexpr base::StringPiece kAllowedPaths[] = {
    "/dev",       "/home/chronos",
    "/home/user", "/media",
    "/mnt",       "/proc",
    "/run",       "/sys/fs/cgroup/",
    "/tmp",       "/var/cache",
    "/var/lib",   "/var/lock",
    "/var/log",   "/var/spool/support",
    "/var/tmp"};

constexpr char kRootPath[] = "/";

}  // anonymous namespace

LandlockPolicy::LandlockPolicy() = default;

LandlockPolicy::~LandlockPolicy() = default;

base::span<const base::StringPiece>
LandlockPolicy::GetPolicySnapshotForTesting() {
  return base::make_span(kAllowedPaths);
}

void LandlockPolicy::SetupPolicy(minijail* j) {
  minijail_add_fs_restriction_rx(j, kRootPath);

  // TODO(b/286058542): allowlist paths for dev-mode only once the list of
  // required paths is narrowed down.

  // Add paths to the Minijail.
  for (const auto& path : kAllowedPaths) {
    minijail_add_fs_restriction_advanced_rw(j, path.data());
  }
}

}  // namespace login_manager
