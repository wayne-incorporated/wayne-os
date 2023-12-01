// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/proto_utils.h"

#include <string>

namespace dlcservice {

InstallRequest CreateInstallRequest(const DlcId& id,
                                    const std::string omaha_url,
                                    bool reserve) {
  InstallRequest install_request;
  install_request.set_id(id);
  install_request.set_omaha_url(omaha_url);
  install_request.set_reserve(reserve);
  return install_request;
}

}  // namespace dlcservice
