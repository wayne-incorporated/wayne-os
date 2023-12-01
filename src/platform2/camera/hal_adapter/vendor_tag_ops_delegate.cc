/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal_adapter/vendor_tag_ops_delegate.h"

#include <string>
#include <utility>
#include <vector>

#include "cros-camera/common.h"

#include <base/check.h>
#include <base/check_op.h>

namespace cros {

VendorTagOpsDelegate::VendorTagOpsDelegate(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    vendor_tag_ops_t* ops)
    : internal::MojoReceiver<VendorTagOps>(task_runner), vendor_tag_ops_(ops) {}

void VendorTagOpsDelegate::GetTagCount(GetTagCountCallback callback) {
  DCHECK_NE(vendor_tag_ops_, nullptr);
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(vendor_tag_ops_->get_tag_count(vendor_tag_ops_));
}

void VendorTagOpsDelegate::GetAllTags(GetAllTagsCallback callback) {
  DCHECK_NE(vendor_tag_ops_, nullptr);
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::vector<uint32_t> tags(vendor_tag_ops_->get_tag_count(vendor_tag_ops_));
  vendor_tag_ops_->get_all_tags(vendor_tag_ops_, tags.data());
  std::move(callback).Run(tags);
}

void VendorTagOpsDelegate::GetSectionName(uint32_t tag,
                                          GetSectionNameCallback callback) {
  DCHECK_NE(vendor_tag_ops_, nullptr);
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(
      std::string(vendor_tag_ops_->get_section_name(vendor_tag_ops_, tag)));
}

void VendorTagOpsDelegate::GetTagName(uint32_t tag,
                                      GetTagNameCallback callback) {
  DCHECK_NE(vendor_tag_ops_, nullptr);
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(
      std::string(vendor_tag_ops_->get_tag_name(vendor_tag_ops_, tag)));
}

void VendorTagOpsDelegate::GetTagType(uint32_t tag,
                                      GetTagTypeCallback callback) {
  DCHECK_NE(vendor_tag_ops_, nullptr);
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(vendor_tag_ops_->get_tag_type(vendor_tag_ops_, tag));
}

}  // namespace cros
