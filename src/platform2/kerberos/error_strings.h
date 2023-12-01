// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_ERROR_STRINGS_H_
#define KERBEROS_ERROR_STRINGS_H_

#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace kerberos {

const char* GetErrorString(ErrorType error);

}  // namespace kerberos

#endif  // KERBEROS_ERROR_STRINGS_H_
