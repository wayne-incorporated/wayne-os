// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef CRYPTOHOME_MIGRATION_TYPE_H_
#define CRYPTOHOME_MIGRATION_TYPE_H_

namespace cryptohome {

// Determines type of ext4 migration.
enum class MigrationType {
  FULL,     // Migrate all files.
  MINIMAL,  // Migrate only allowlisted files.
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_MIGRATION_TYPE_H_
