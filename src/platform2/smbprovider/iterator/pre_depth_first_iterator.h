// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_ITERATOR_PRE_DEPTH_FIRST_ITERATOR_H_
#define SMBPROVIDER_ITERATOR_PRE_DEPTH_FIRST_ITERATOR_H_

#include <string>

#include "smbprovider/iterator/depth_first_iterator.h"

namespace smbprovider {

struct DirectoryEntry;
class SambaInterface;

// PreDepthFirstIterator is a class that implements a preorder traversal of
// an SMB filesystem by extending the DepthFirstIterator class.
//
// Example:
//    PreDepthFirstIterator it("smb://testShare/test/dogs",
//                              SambaInterface.get());
//    result = it.Init();
//    while (result == 0)  {
//      if it.IsDone: return 0
//      // Do something with it.Get();
//      result = it.Next();
//    }
//    return result;
class PreDepthFirstIterator : public DepthFirstIterator {
 public:
  PreDepthFirstIterator(const std::string& dir_path,
                        SambaInterface* samba_interface);

 protected:
  // Preorder traversal override of DepthFirstIterator.
  int32_t OnPush(const DirectoryEntry& entry) override;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_ITERATOR_PRE_DEPTH_FIRST_ITERATOR_H_
