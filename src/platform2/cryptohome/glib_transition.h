// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_GLIB_TRANSITION_H_
#define CRYPTOHOME_GLIB_TRANSITION_H_

#include <utility>

#include <base/functional/callback.h>
#include "cryptohome/cryptohome_event_source.h"

namespace cryptohome {

constexpr char kClosureEventType[] = "ClosureEvent";

class ClosureEvent : public CryptohomeEventBase {
 public:
  explicit ClosureEvent(base::OnceClosure closure)
      : closure_(std::move(closure)) {
    // Nothing to do here
  }

  virtual ~ClosureEvent() {}

  virtual const char* GetEventName() const { return kClosureEventType; }

  virtual void Run() { std::move(closure_).Run(); }

 private:
  base::OnceClosure closure_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_GLIB_TRANSITION_H_
