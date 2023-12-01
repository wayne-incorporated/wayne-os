// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_TYPES_H_
#define DLCSERVICE_TYPES_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace dlcservice {

class DlcInterface;
using DlcId = std::string;
using DlcType = std::unique_ptr<DlcInterface>;
using DlcMap = std::map<DlcId, DlcType>;
using DlcIdList = std::vector<DlcId>;

}  // namespace dlcservice

#endif  // DLCSERVICE_TYPES_H_
