// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_VPD_PROCESS_H_
#define LOGIN_MANAGER_VPD_PROCESS_H_

#include <string>
#include <utility>
#include <vector>

#include "login_manager/policy_service.h"

namespace login_manager {

class VpdProcess {
 public:
  using KeyValuePairs = std::vector<std::pair<std::string, std::string>>;
  using CompletionCallback = base::Callback<void(bool)>;

  // Update values in RW_VPD by running the update_rw_vpd utility in a separate
  // process. Keys with empty string values are deleted. update_rw_vpd will not
  // perform unnecessary writes if the already cache matches the update unless
  // |ignore_cache| is set to true which will unconditionally update the VPD.
  //
  // Takes ownership of |completion| if process starts successfully. Returns
  // whether fork() was successful.
  virtual bool RunInBackground(const KeyValuePairs& updates,
                               bool ignore_cache,
                               const CompletionCallback& completion) = 0;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_VPD_PROCESS_H_
