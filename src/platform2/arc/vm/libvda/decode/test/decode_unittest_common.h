// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_DECODE_TEST_DECODE_UNITTEST_COMMON_H_
#define ARC_VM_LIBVDA_DECODE_TEST_DECODE_UNITTEST_COMMON_H_

#include <memory>

#include "arc/vm/libvda/libvda_decode.h"

struct ImplDeleter {
  void operator()(void* impl) { deinitialize(impl); }
};

using ImplPtr = std::unique_ptr<void, ImplDeleter>;

struct SessionDeleter {
  explicit SessionDeleter(void* impl) : impl_(impl) {}

  void operator()(vda_session_info_t* session) {
    close_decode_session(impl_, session);
  }

 private:
  void* impl_;
};

using SessionPtr = std::unique_ptr<vda_session_info_t, SessionDeleter>;

ImplPtr SetupImpl(vda_impl_type_t impl_type);

SessionPtr SetupSession(const ImplPtr& impl, vda_profile_t profile);

#endif  // ARC_VM_LIBVDA_DECODE_TEST_DECODE_UNITTEST_COMMON_H_
