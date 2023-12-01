// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_EXTERNAL_TASK_H_
#define SHILL_MOCK_EXTERNAL_TASK_H_

#include <map>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/external_task.h"

namespace shill {

class MockExternalTask : public ExternalTask {
 public:
  MockExternalTask(ControlInterface* control,
                   ProcessManager* process_manager,
                   const base::WeakPtr<RpcTaskDelegate>& task_delegate,
                   base::OnceCallback<void(pid_t, int)> death_callback);
  MockExternalTask(const MockExternalTask&) = delete;
  MockExternalTask& operator=(const MockExternalTask&) = delete;

  ~MockExternalTask() override;

  MOCK_METHOD(bool,
              Start,
              (const base::FilePath&,
               const std::vector<std::string>&,
               (const std::map<std::string, std::string>&),
               bool,
               Error*),
              (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void, OnDelete, ());
};

}  // namespace shill

#endif  // SHILL_MOCK_EXTERNAL_TASK_H_
