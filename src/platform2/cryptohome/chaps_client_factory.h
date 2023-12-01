// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHAPS_CLIENT_FACTORY_H_
#define CRYPTOHOME_CHAPS_CLIENT_FACTORY_H_

namespace chaps {
class TokenManagerClient;
}

namespace cryptohome {

class ChapsClientFactory {
 public:
  ChapsClientFactory();
  ChapsClientFactory(const ChapsClientFactory&) = delete;
  ChapsClientFactory& operator=(const ChapsClientFactory&) = delete;

  virtual ~ChapsClientFactory();
  virtual chaps::TokenManagerClient* New();
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHAPS_CLIENT_FACTORY_H_
