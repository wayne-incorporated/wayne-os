// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SHILL_CONFIG_H_
#define SHILL_SHILL_CONFIG_H_

#include <string>

namespace shill {

class Config {
 public:
  Config();
  Config(const Config&) = delete;
  Config& operator=(const Config&) = delete;

  virtual ~Config();

  virtual std::string GetRunDirectory() const;
  virtual std::string GetStorageDirectory() const;
  virtual std::string GetUserStorageDirectory() const;
};

}  // namespace shill

#endif  // SHILL_SHILL_CONFIG_H_
