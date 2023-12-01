// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_CGPT_WRAPPER_INTERFACE_H_
#define MINIOS_CGPT_WRAPPER_INTERFACE_H_

#include <optional>
#include <string>

#include <vboot/cgpt_params.h>

namespace minios {

// Abstract wrapper to intercept cgpt calls.
class CgptWrapperInterface {
 public:
  virtual ~CgptWrapperInterface() = default;
  virtual void CgptFind(CgptFindParams* params) const = 0;
  virtual int CgptGetPartitionDetails(CgptAddParams* params) const = 0;
};

}  // namespace minios

#endif  // MINIOS_CGPT_WRAPPER_INTERFACE_H_
