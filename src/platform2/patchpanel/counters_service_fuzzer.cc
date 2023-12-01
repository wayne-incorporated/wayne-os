// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <base/at_exit.h>
#pragma GCC diagnostic pop
#include <base/logging.h>

#include "patchpanel/counters_service.h"
#include "patchpanel/datapath.h"
#include "patchpanel/iptables.h"

namespace patchpanel {
namespace {

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
  base::AtExitManager at_exit;
};

class FakeDatapath : public Datapath {
 public:
  explicit FakeDatapath(const char* data, size_t size)
      : Datapath(nullptr, nullptr, nullptr), data_(data, size) {}

  FakeDatapath(const FakeDatapath&) = delete;
  FakeDatapath& operator=(const FakeDatapath&) = delete;
  ~FakeDatapath() = default;

  std::string DumpIptables(IpFamily family, Iptables::Table table) override {
    return data_;
  }

 private:
  std::string data_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FakeDatapath datapath(reinterpret_cast<const char*>(data), size);
  CountersService counters_svc(&datapath);
  counters_svc.GetCounters({});

  return 0;
}

}  // namespace
}  // namespace patchpanel
