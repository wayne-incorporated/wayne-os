// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_RULE_H_
#define PERMISSION_BROKER_RULE_H_

#include <string>

struct udev_device;

namespace permission_broker {

// A Rule represents a single unit of policy used to decide to which paths
// access is granted. Each time a Rule processes a path it can return one of
// these values: |ALLOW|, |ALLOW_WITH_DETACH|, |ALLOW_WITH_LOCKDOWN|, |DENY|, or
// |IGNORE|. If a Rule returns |ALLOW|, it means that the policy it represents
// would allow access to the requested path. If |ALLOW_WITH_DETACH| is returned,
// then it would allow access to this device if the kernel driver is detached
// from this device before using it. If |ALLOW_WITH_LOCKDOWN| is returned, then
// the policy it represents would allow access to the requested path only if
// further measures are taken to restrict access. If |DENY| is returned, then
// the rule is explicitly denying access to the resource. |IGNORE| means that
// the Rule makes no decision one way or another.
class Rule {
 public:
  enum Result { ALLOW, ALLOW_WITH_DETACH, ALLOW_WITH_LOCKDOWN, DENY, IGNORE };

  static const char* ResultToString(const Result& result);

  virtual ~Rule() = default;
  const std::string& name() const;

  virtual Result ProcessDevice(udev_device* device) = 0;

 protected:
  explicit Rule(const std::string& name);
  Rule(const Rule&) = delete;
  Rule& operator=(const Rule&) = delete;

 private:
  const std::string name_;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_RULE_H_
