// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_CGPT_WRAPPER_H_
#define MINIOS_CGPT_WRAPPER_H_

#include "minios/cgpt_wrapper_interface.h"

#include <vboot/crossystem.h>
#include <vboot/vboot_host.h>

namespace minios {

class CgptWrapper : public CgptWrapperInterface {
 public:
  CgptWrapper() = default;
  CgptWrapper(const CgptWrapper&) = delete;
  CgptWrapper& operator=(const CgptWrapper&) = delete;

  ~CgptWrapper() override = default;

  // CgptWrapperInterface overrides.
  void CgptFind(CgptFindParams* params) const override {
    return ::CgptFind(params);
  }
  int CgptGetPartitionDetails(CgptAddParams* params) const override {
    return ::CgptGetPartitionDetails(params);
  };
};

}  // namespace minios

#endif  // MINIOS_CGPT_WRAPPER_H_
