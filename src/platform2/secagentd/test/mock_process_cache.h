// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_TEST_MOCK_PROCESS_CACHE_H_
#define SECAGENTD_TEST_MOCK_PROCESS_CACHE_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "gmock/gmock.h"  // IWYU pragma: keep
#include "secagentd/bpf/bpf_types.h"
#include "secagentd/process_cache.h"
#include "secagentd/proto/security_xdr_events.pb.h"

namespace secagentd::testing {

class MockProcessCache : public ProcessCacheInterface {
 public:
  MOCK_METHOD(void,
              PutFromBpfExec,
              (const bpf::cros_process_start&),
              (override));
  MOCK_METHOD(std::vector<std::unique_ptr<cros_xdr::reporting::Process>>,
              GetProcessHierarchy,
              (uint64_t, bpf::time_ns_t, int),
              (override));
  MOCK_METHOD(void, EraseProcess, (uint64_t, bpf::time_ns_t), (override));

  MOCK_METHOD(bool,
              IsEventFiltered,
              (const cros_xdr::reporting::Process*,
               const cros_xdr::reporting::Process*),
              (override));

  MOCK_METHOD(void, InitializeFilter, (bool underscorify), (override));
};

}  // namespace secagentd::testing

#endif  // SECAGENTD_TEST_MOCK_PROCESS_CACHE_H_
