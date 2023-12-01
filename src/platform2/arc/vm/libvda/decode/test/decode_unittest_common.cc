// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/decode/test/decode_unittest_common.h"

ImplPtr SetupImpl(vda_impl_type_t impl_type) {
  return ImplPtr(initialize(impl_type));
}

SessionPtr SetupSession(const ImplPtr& impl, vda_profile_t profile) {
  return SessionPtr(init_decode_session(impl.get(), profile),
                    SessionDeleter(impl.get()));
}
