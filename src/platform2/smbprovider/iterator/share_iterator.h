// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_ITERATOR_SHARE_ITERATOR_H_
#define SMBPROVIDER_ITERATOR_SHARE_ITERATOR_H_

#include "smbprovider/iterator/directory_iterator.h"
#include "smbprovider/smbprovider_helper.h"

namespace smbprovider {

// ShareIterator is an implementation of BaseDirectoryIterator that only
// iterates through shares.
class ShareIterator : public BaseDirectoryIterator {
  using BaseDirectoryIterator::BaseDirectoryIterator;

 public:
  ShareIterator(ShareIterator&& other) = default;
  ShareIterator(const ShareIterator&) = delete;
  ShareIterator& operator=(const ShareIterator&) = delete;

 protected:
  bool ShouldIncludeEntryType(uint32_t smbc_type) const override {
    return IsSmbShare(smbc_type);
  }
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_ITERATOR_SHARE_ITERATOR_H_
