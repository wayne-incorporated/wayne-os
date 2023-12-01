// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_SESSION_H_
#define BIOD_SESSION_H_

#include <string>
#include <utility>

#include "base/memory/weak_ptr.h"

namespace biod {

// Invokes the function object F with a given BiometricsManager object when
// this session (EnrollSession or AuthSession) object goes out of scope. It's
// possible that this will do nothing in the case that the session has ended
// due to failure/finishing or the BiometricsManager object is no longer
// valid.

class BiometricsManager;

template <typename F>
class Session {
 public:
  Session() = default;

  Session(Session<F>&& rhs)
      : biometrics_manager_(rhs.biometrics_manager_),
        error_(std::move(rhs.error_)) {
    rhs.biometrics_manager_.reset();
  }

  explicit Session(const base::WeakPtr<BiometricsManager>& biometrics_manager)
      : biometrics_manager_(biometrics_manager) {}

  ~Session() { End(); }

  Session<F>& operator=(Session<F>&& rhs) {
    End();
    biometrics_manager_ = rhs.biometrics_manager_;
    error_ = std::move(rhs.error_);
    rhs.biometrics_manager_.reset();
    return *this;
  }

  explicit operator bool() const { return biometrics_manager_.get(); }

  // Has the same effect of letting this object go out of scope, but allows
  // one to reuse the storage of this object.
  void End() {
    if (biometrics_manager_) {
      F f;
      f(biometrics_manager_.get());
      biometrics_manager_.reset();
    }
    error_.clear();
  }

  void set_error(const std::string& error) { error_ = error; }

  std::string error() const { return error_; }

 private:
  base::WeakPtr<BiometricsManager> biometrics_manager_;
  std::string error_;
};

}  // namespace biod

#endif  // BIOD_SESSION_H_
