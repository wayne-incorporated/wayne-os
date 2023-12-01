// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crossystem.h"

#include <base/no_destructor.h>
#include <libcrossystem/crossystem.h>

namespace {

crossystem::Crossystem* GetDefaultInstance() {
  static base::NoDestructor<crossystem::Crossystem> instance;
  return instance.get();
}

crossystem::Crossystem* shared_instance = nullptr;

}  // namespace

namespace crossystem {

crossystem::Crossystem* GetInstance() {
  if (shared_instance == nullptr)
    shared_instance = GetDefaultInstance();
  return shared_instance;
}

crossystem::Crossystem* ReplaceInstanceForTest(
    crossystem::Crossystem* instance) {
  auto original_instance =
      shared_instance == nullptr ? GetDefaultInstance() : shared_instance;
  shared_instance = instance;
  return original_instance;
}

}  // namespace crossystem
