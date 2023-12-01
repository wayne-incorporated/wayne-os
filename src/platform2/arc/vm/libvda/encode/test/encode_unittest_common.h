// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_ENCODE_TEST_ENCODE_UNITTEST_COMMON_H_
#define ARC_VM_LIBVDA_ENCODE_TEST_ENCODE_UNITTEST_COMMON_H_

#include <memory>

#include "arc/vm/libvda/libvda_encode.h"

struct ImplDeleter {
  void operator()(void* impl) { deinitialize_encode(impl); }
};

using ImplPtr = std::unique_ptr<void, ImplDeleter>;

struct SessionDeleter {
  explicit SessionDeleter(void* impl) : impl_(impl) {}

  void operator()(vea_session_info_t* session) {
    close_encode_session(impl_, session);
  }

 private:
  void* impl_;
};

using SessionPtr = std::unique_ptr<vea_session_info_t, SessionDeleter>;

ImplPtr SetupImpl(vea_impl_type_t impl_type);

SessionPtr SetupSession(const ImplPtr& impl, vea_config_t* config);

#endif  // ARC_VM_LIBVDA_ENCODE_TEST_ENCODE_UNITTEST_COMMON_H_
