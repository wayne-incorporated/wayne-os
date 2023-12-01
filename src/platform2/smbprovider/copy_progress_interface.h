// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_COPY_PROGRESS_INTERFACE_H_
#define SMBPROVIDER_COPY_PROGRESS_INTERFACE_H_

#include <string>

namespace smbprovider {

// Keeps track of an in-progress copy operation.
//
// A copy is started by constructing a CopyProgress (either file or recursive)
// and calling StartCopy(). The copy is continued by calling ContinueCopy().
class CopyProgressInterface {
 public:
  virtual ~CopyProgressInterface() = default;

  // Starts a copy of |source| to |target|. Returns true if ContinueCopy must be
  // called again. Returns false if the copy is complete or has failed. |error|
  // is 0 if the copy completed successfully, and errno otherwise.
  virtual bool StartCopy(const std::string& source,
                         const std::string& target,
                         int32_t* error) = 0;

  // Continues the copy. Returns true if ContinueCopy must be called again.
  // Returns false if the copy is complete or has failed. |error| is 0 if the
  // copy completed successfully, and errno otherwise.
  virtual bool ContinueCopy(int32_t* error) = 0;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_COPY_PROGRESS_INTERFACE_H_
