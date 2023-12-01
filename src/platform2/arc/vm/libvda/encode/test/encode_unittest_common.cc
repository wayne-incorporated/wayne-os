// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/encode/test/encode_unittest_common.h"

ImplPtr SetupImpl(vea_impl_type_t impl_type) {
  return ImplPtr(initialize_encode(impl_type));
}

SessionPtr SetupSession(const ImplPtr& impl, vea_config_t* config) {
  return SessionPtr(init_encode_session(impl.get(), config),
                    SessionDeleter(impl.get()));
}
