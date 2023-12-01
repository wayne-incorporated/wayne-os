// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SHIMS_ENVIRONMENT_H_
#define SHILL_SHIMS_ENVIRONMENT_H_

#include <map>
#include <string>

#include <base/no_destructor.h>

namespace shill {

namespace shims {

// Environment access utilities.
class Environment {
 public:
  virtual ~Environment();

  // This is a singleton -- use Environment::GetInstance()->Foo().
  static Environment* GetInstance();

  // Sets |value| to the value of environment variable |name| and returns
  // true. Returns false if variable |name| is not set.
  virtual bool GetVariable(const std::string& name, std::string* value);

  // Parses and returns the environment as a name->value string map.
  virtual std::map<std::string, std::string> AsMap();

 protected:
  Environment();
  Environment(const Environment&) = delete;
  Environment& operator=(const Environment&) = delete;

 private:
  friend class base::NoDestructor<Environment>;
};

}  // namespace shims

}  // namespace shill

#endif  // SHILL_SHIMS_ENVIRONMENT_H_
