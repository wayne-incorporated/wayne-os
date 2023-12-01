// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_SCOPED_NS_H_
#define PATCHPANEL_SCOPED_NS_H_

#include <sys/types.h>

#include <memory>
#include <string>

#include <base/files/scoped_file.h>

namespace patchpanel {

// Utility class for running code blocks within a network namespace or a mount
// namespace.
class ScopedNS {
 public:
  // Records the current mount (network) namespace and enters another namespace
  // identified by the input argument. Will go back to the current namespace if
  // the returned object goes out of scope. Returns nullptr on failure.
  static std::unique_ptr<ScopedNS> EnterMountNS(pid_t pid);
  static std::unique_ptr<ScopedNS> EnterNetworkNS(pid_t pid);
  static std::unique_ptr<ScopedNS> EnterNetworkNS(
      const std::string& netns_name);

  ScopedNS(const ScopedNS&) = delete;
  ScopedNS& operator=(const ScopedNS&) = delete;

  ~ScopedNS();

 private:
  ScopedNS(int nstype,
           const std::string& current_ns_path,
           const std::string& target_ns_path);

  int nstype_;
  bool valid_;
  base::ScopedFD ns_fd_;
  base::ScopedFD self_fd_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_SCOPED_NS_H_
