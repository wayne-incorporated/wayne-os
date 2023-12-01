// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_PROTO_UTILS_H_
#define DLCSERVICE_PROTO_UTILS_H_

#include <string>

#include <dlcservice/proto_bindings/dlcservice.pb.h>

#include "dlcservice/dlc_base.h"

namespace dlcservice {

InstallRequest CreateInstallRequest(const DlcId& id,
                                    const std::string omaha_url = "",
                                    bool reserve = false);

}  // namespace dlcservice

#endif  // DLCSERVICE_PROTO_UTILS_H_
