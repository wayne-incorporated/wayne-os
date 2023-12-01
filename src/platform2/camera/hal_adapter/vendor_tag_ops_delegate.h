/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_ADAPTER_VENDOR_TAG_OPS_DELEGATE_H_
#define CAMERA_HAL_ADAPTER_VENDOR_TAG_OPS_DELEGATE_H_

#include <hardware/camera3.h>

#include "camera/mojo/camera_common.mojom.h"
#include "common/utils/cros_camera_mojo_utils.h"

namespace cros {

class VendorTagOpsDelegate
    : public internal::MojoReceiver<mojom::VendorTagOps> {
 public:
  VendorTagOpsDelegate(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                       vendor_tag_ops_t* ops);

  VendorTagOpsDelegate(const VendorTagOpsDelegate&) = delete;
  VendorTagOpsDelegate& operator=(const VendorTagOpsDelegate&) = delete;

  ~VendorTagOpsDelegate() override = default;

 private:
  void GetTagCount(GetTagCountCallback callback) override;

  void GetAllTags(GetAllTagsCallback callback) override;

  void GetSectionName(uint32_t tag, GetSectionNameCallback callback) override;

  void GetTagName(uint32_t tag, GetTagNameCallback callback) override;

  void GetTagType(uint32_t tag, GetTagTypeCallback callback) override;

  vendor_tag_ops_t* vendor_tag_ops_;
};

}  // namespace cros

#endif  // CAMERA_HAL_ADAPTER_VENDOR_TAG_OPS_DELEGATE_H_
