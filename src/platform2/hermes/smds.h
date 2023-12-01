// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_SMDS_H_
#define HERMES_SMDS_H_

#include <memory>

#include <google-lpa/lpa/smdx/smds_client.h>
#include <google-lpa/lpa/smdx/smds_client_factory.h>

namespace hermes {

class SmdsFactory : public lpa::smds::SmdsClientFactory {
 public:
  std::unique_ptr<lpa::smds::SmdsClient> NewSmdsClient() override;
};

class Smds : public lpa::smds::SmdsClient {};

}  // namespace hermes

#endif  // HERMES_SMDS_H_
