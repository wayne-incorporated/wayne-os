// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include "usb_bouncer/entry_manager.h"
#include "usb_bouncer/entry_manager_test_util.h"
#include "usb_bouncer/usb_bouncer.pb.h"

DEFINE_PROTO_FUZZER(const usb_bouncer::RuleDB& input) {
  usb_bouncer::EntryManagerTestUtil entry_manager_test_util;

  entry_manager_test_util.RefreshDB(true /*include_user_db_*/, true /*new_db*/);
  entry_manager_test_util.ReplaceDB(input);

  entry_manager_test_util.Get()->HandleUserLogin();
  entry_manager_test_util.Get()->GarbageCollect();
  entry_manager_test_util.Get()->GenerateRules();
}
