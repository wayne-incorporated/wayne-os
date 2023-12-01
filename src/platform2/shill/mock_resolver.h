// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_RESOLVER_H_
#define SHILL_MOCK_RESOLVER_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/resolver.h"

namespace shill {

class MockResolver : public Resolver {
 public:
  MockResolver();
  MockResolver(const MockResolver&) = delete;
  MockResolver& operator=(const MockResolver&) = delete;

  ~MockResolver() override;

  MOCK_METHOD(bool,
              SetDNSFromLists,
              (const std::vector<std::string>&,
               const std::vector<std::string>&),
              (override));
  MOCK_METHOD(bool,
              SetDNSProxyAddresses,
              (const std::vector<std::string>&),
              (override));
  MOCK_METHOD(bool, ClearDNS, (), (override));
  MOCK_METHOD(void,
              set_ignored_search_list,
              (const std::vector<std::string>&),
              (override));
  MOCK_METHOD(void, set_path, (const base::FilePath&), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_RESOLVER_H_
