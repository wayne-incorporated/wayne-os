// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_SYSTEM_PROPERTIES_H_
#define DLCSERVICE_SYSTEM_PROPERTIES_H_

namespace dlcservice {

class SystemProperties {
 public:
  SystemProperties() = default;
  virtual ~SystemProperties() = default;

  virtual bool IsOfficialBuild();

 private:
  SystemProperties(const SystemProperties&) = delete;
  SystemProperties& operator=(const SystemProperties&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_SYSTEM_PROPERTIES_H_
