// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/data_migrator/logging.h"

#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace arc::data_migrator {

TEST(ArcVmDataMigratorLoggingTest, RedactAndroidDataPaths) {
  std::vector<std::pair<const char*, const char*>> test_cases = {{
      // Relative paths are correctly redacted.
      {"Failed to migrate: data/com.android.vending/",
       "Failed to migrate: data/***"},
      {"Failed to migrate: app/~~uzze_fyNHX-27ZxbI-1Kpg==/",
       "Failed to migrate: app/***"},
      {"Failed to migrate: media/0/Pictures/capybara.jpg",
       "Failed to migrate: media/0/***"},
      {"Failed to migrate: media/0/Android/data/com.android.vending/",
       "Failed to migrate: media/0/Android/data/***"},
      {"Failed to migrate: media/0/Android/obb/com.android.vending/",
       "Failed to migrate: media/0/Android/obb/***"},
      {"Failed to migrate: media/0/Android/foo/com.android.vending/",
       "Failed to migrate: media/0/***"},
      {"Failed to migrate: user/0/com.android.vending/",
       "Failed to migrate: user/0/***"},
      {"Failed to migrate: user_de/0/com.android.vending/",
       "Failed to migrate: user_de/0/***"},

      // Relative paths preceded with a double quote are correctly redacted.
      {"Failed to migrate \"data/com.android.vending/\"",
       "Failed to migrate \"data/***\""},
      {"Failed to migrate \"media/0/Pictures/capybara.jpg\"",
       "Failed to migrate \"media/0/***\""},
      {"Failed to migrate \"media/0/Android/data/com.android.vending/\"",
       "Failed to migrate \"media/0/Android/data/***\""},

      // Relative paths preceded with a colon are correctly redacted.
      {"Failed to migrate:data/com.android.vending/",
       "Failed to migrate:data/***"},
      {"Failed to migrate:media/0/Pictures/capybara.jpg",
       "Failed to migrate:media/0/***"},
      {"Failed to migrate:media/0/Android/data/com.android.vending/",
       "Failed to migrate:media/0/Android/data/***"},

      // Absolute paths are correctly redacted.
      {"Failed to delete "
       "/home/root/0123456789abcdef0123456789abcdef01234567/"
       "android-data/data/data/com.android.vending/app_FinskySetup: ",
       "Failed to delete "
       "/home/root/0123456789abcdef0123456789abcdef01234567/"
       "android-data/data/data/***: "},
      {"Failed to delete "
       "/tmp/arcvm-data-migration-mount/data/com.android.vending",
       "Failed to delete "
       "/tmp/arcvm-data-migration-mount/data/***"},

      // File names with whitespaces are redacted.
      {"lsetxattr: /tmp/arcvm-data-migration-mount/media/0/Pictures/My folder: "
       "No space left on device (28)",
       "lsetxattr: /tmp/arcvm-data-migration-mount/media/0/***: No space left "
       "on device (28)"},
      {"Failed to migrate \"media/0/Pictures/My folder\"",
       "Failed to migrate \"media/0/***\""},
      {"Failed to migrate: media/0/Pictures/My folder",
       "Failed to migrate: media/0/***"},

      // Full line of logs found in the experiments are correctly redacted.
      {"2023-03-14T05:28:44.912544Z ERR arcvm_data_migrator[4529]: ERROR "
       "arcvm_data_migrator: [migration_helper.cc(225)] Failed to migrate "
       "\"app/~~uzze_fyNHX-27ZxbI-1Kpg==/"
       "com.google.android.gms-hhsLWn0btCJHs_A8gd0Cew==/oat/x86_64/base.vdex\"",
       "2023-03-14T05:28:44.912544Z ERR arcvm_data_migrator[4529]: ERROR "
       "arcvm_data_migrator: [migration_helper.cc(225)] Failed to migrate "
       "\"app/***\""},
      {"2023-03-14T05:28:44.851026Z ERR arcvm_data_migrator[4529]: ERROR "
       "arcvm_data_migrator: [platform.cc(1067)] lsetxattr: "
       "/tmp/arcvm-data-migration-mount/app/~~uzze_fyNHX-27ZxbI-1Kpg==/"
       "com.google.android.gms-hhsLWn0btCJHs_A8gd0Cew==/lib/x86: No space left "
       "on device (28)",
       "2023-03-14T05:28:44.851026Z ERR arcvm_data_migrator[4529]: ERROR "
       "arcvm_data_migrator: [platform.cc(1067)] lsetxattr: "
       "/tmp/arcvm-data-migration-mount/app/***: No space left on device (28)"},
  }};

  for (const auto& [before, after] : test_cases) {
    EXPECT_EQ(RedactAndroidDataPaths(before), after);
  }
}

}  // namespace arc::data_migrator
