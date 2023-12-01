// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_SESSION_H_
#define LIBHWSEC_STRUCTURES_SESSION_H_

#include <utility>

#include "libhwsec/structures/no_default_init.h"

namespace hwsec {

using SessionToken = uint32_t;

struct Session {
  NoDefault<SessionToken> token;
};

class ScopedSession {
 public:
  explicit ScopedSession(ScopedSession&& scoped_session)
      : session_(std::move(scoped_session.session_)) {}
  ~ScopedSession() = default;

  ScopedSession& operator()(ScopedSession&& scoped_session) {
    session_ = std::move(scoped_session.session_);
    return *this;
  }

 private:
  explicit ScopedSession(Session session) : session_(session) {}
  Session session_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_SESSION_H_
