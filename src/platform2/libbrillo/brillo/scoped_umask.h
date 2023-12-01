// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_SCOPED_UMASK_H_
#define LIBBRILLO_BRILLO_SCOPED_UMASK_H_

#include <sys/types.h>

#include <brillo/brillo_export.h>

namespace brillo {

// ScopedUmask is a helper class for temporarily setting the umask before a
// set of operations. umask(2) is never expected to fail.
class BRILLO_EXPORT ScopedUmask {
 public:
  explicit ScopedUmask(mode_t new_umask);
  ScopedUmask(const ScopedUmask&) = delete;
  ScopedUmask& operator=(const ScopedUmask&) = delete;

  ~ScopedUmask();

 private:
  mode_t saved_umask_;

  // Avoid reusing ScopedUmask for multiple masks. DISALLOW_COPY_AND_ASSIGN
  // deletes the copy constructor and operator=, but there are other situations
  // where reassigning a new ScopedUmask to an existing ScopedUmask object
  // is problematic:
  //
  // /* starting umask: default_value
  // auto a = std::make_unique<ScopedUmask>(first_value);
  // ... code here ...
  // a.reset(ScopedUmask(new_value));
  //
  // Here, the order of destruction of the old object and the construction of
  // the new object is inverted. The recommended usage would be:
  //
  // {
  //    ScopedUmask a(old_value);
  //    ... code here ...
  // }
  //
  // {
  //    ScopedUmask a(new_value);
  //    ... code here ...
  // }
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_SCOPED_UMASK_H_
