// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/external_task.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_adaptors.h"
#include "shill/mock_control.h"
#include "shill/net/mock_process_manager.h"
#include "shill/test_event_dispatcher.h"

using testing::_;
using testing::Mock;
using testing::Return;

namespace shill {

class ExternalTaskTest : public testing::Test, public RpcTaskDelegate {
 public:
  ExternalTaskTest()
      : weak_ptr_factory_(this),
        external_task_(
            new ExternalTask(&control_,
                             &process_manager_,
                             weak_ptr_factory_.GetWeakPtr(),
                             base::BindOnce(&ExternalTaskTest::TaskDiedCallback,
                                            weak_ptr_factory_.GetWeakPtr()))),
        test_rpc_task_destroyed_(false) {}

  ~ExternalTaskTest() override = default;

  void TearDown() override {
    if (!external_task_) {
      return;
    }

    if (external_task_->pid_) {
      EXPECT_CALL(process_manager_, StopProcess(external_task_->pid_));
    }
  }

  void set_test_rpc_task_destroyed(bool destroyed) {
    test_rpc_task_destroyed_ = destroyed;
  }

  // Defined out-of-line, due to dependency on TestRpcTask.
  void FakeUpRunningProcess(unsigned int tag, int pid);

  void ExpectStop(unsigned int tag, int pid) {
    EXPECT_CALL(process_manager_, StopProcess(pid));
  }

  void VerifyStop() {
    if (external_task_) {
      EXPECT_EQ(0, external_task_->pid_);
      EXPECT_FALSE(external_task_->rpc_task_);
    }
    EXPECT_TRUE(test_rpc_task_destroyed_);
    // Make sure EXPECTations were met before the fixture's dtor.
    Mock::VerifyAndClearExpectations(&process_manager_);
  }

 protected:
  // Implements RpcTaskDelegate interface.
  MOCK_METHOD(void, GetLogin, (std::string*, std::string*), (override));
  MOCK_METHOD(void,
              Notify,
              (const std::string&, (const std::map<std::string, std::string>&)),
              (override));

  MOCK_METHOD(void, TaskDiedCallback, (pid_t, int));

  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockProcessManager process_manager_;
  base::WeakPtrFactory<ExternalTaskTest> weak_ptr_factory_;
  std::unique_ptr<ExternalTask> external_task_;
  bool test_rpc_task_destroyed_;
};

namespace {

class TestRpcTask : public RpcTask {
 public:
  TestRpcTask(ControlInterface* control, ExternalTaskTest* test);
  virtual ~TestRpcTask();

 private:
  ExternalTaskTest* test_;
};

TestRpcTask::TestRpcTask(ControlInterface* control, ExternalTaskTest* test)
    : RpcTask(control, test), test_(test) {
  test_->set_test_rpc_task_destroyed(false);
}

TestRpcTask::~TestRpcTask() {
  test_->set_test_rpc_task_destroyed(true);
  test_ = nullptr;
}

}  // namespace

void ExternalTaskTest::FakeUpRunningProcess(unsigned int tag, int pid) {
  external_task_->pid_ = pid;
  external_task_->rpc_task_.reset(new TestRpcTask(&control_, this));
}

TEST_F(ExternalTaskTest, Destructor) {
  const unsigned int kTag = 123;
  const int kPID = 123456;
  FakeUpRunningProcess(kTag, kPID);
  ExpectStop(kTag, kPID);
  external_task_.reset();
  VerifyStop();
}

TEST_F(ExternalTaskTest, Start) {
  const std::string kCommand = "/run/me";
  const std::vector<std::string> kCommandOptions{"arg1", "arg2"};
  const std::map<std::string, std::string> kCommandEnv{{"env1", "val1"},
                                                       {"env2", "val2"}};
  std::map<std::string, std::string> expected_env;
  expected_env.emplace(kRpcTaskServiceVariable,
                       RpcTaskMockAdaptor::kRpcConnId.value());
  expected_env.emplace(kRpcTaskPathVariable,
                       RpcTaskMockAdaptor::kRpcId.value());
  expected_env.insert(kCommandEnv.begin(), kCommandEnv.end());
  const int kPID = 234678;
  EXPECT_CALL(process_manager_,
              StartProcess(_, base::FilePath(kCommand), kCommandOptions,
                           expected_env, _, false, _))
      .WillOnce(Return(-1))
      .WillOnce(Return(kPID));
  Error error;
  EXPECT_FALSE(external_task_->Start(base::FilePath(kCommand), kCommandOptions,
                                     kCommandEnv, false, &error));
  EXPECT_EQ(Error::kInternalError, error.type());
  EXPECT_FALSE(external_task_->rpc_task_);

  error.Reset();
  EXPECT_TRUE(external_task_->Start(base::FilePath(kCommand), kCommandOptions,
                                    kCommandEnv, false, &error));
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kPID, external_task_->pid_);
  EXPECT_NE(nullptr, external_task_->rpc_task_);
}

TEST_F(ExternalTaskTest, Stop) {
  const unsigned int kTag = 123;
  const int kPID = 123456;
  FakeUpRunningProcess(kTag, kPID);
  ExpectStop(kTag, kPID);
  external_task_->Stop();
  ASSERT_NE(nullptr, external_task_);
  VerifyStop();
}

TEST_F(ExternalTaskTest, StopNotStarted) {
  EXPECT_CALL(process_manager_, StopProcess(_)).Times(0);
  external_task_->Stop();
  EXPECT_FALSE(test_rpc_task_destroyed_);
}

TEST_F(ExternalTaskTest, GetLogin) {
  std::string username;
  std::string password;
  EXPECT_CALL(*this, GetLogin(&username, &password));
  EXPECT_CALL(*this, Notify(_, _)).Times(0);
  external_task_->GetLogin(&username, &password);
}

TEST_F(ExternalTaskTest, Notify) {
  const std::string kReason("you may already have won!");
  const std::map<std::string, std::string>& kArgs{{"arg1", "val1"},
                                                  {"arg2", "val2"}};
  EXPECT_CALL(*this, GetLogin(_, _)).Times(0);
  EXPECT_CALL(*this, Notify(kReason, kArgs));
  external_task_->Notify(kReason, kArgs);
}

TEST_F(ExternalTaskTest, OnTaskDied) {
  const int kPID = 99999;
  const int kExitStatus = 1;
  external_task_->pid_ = kPID;
  EXPECT_CALL(process_manager_, StopProcess(_)).Times(0);
  EXPECT_CALL(*this, TaskDiedCallback(kPID, kExitStatus));
  external_task_->OnTaskDied(kExitStatus);
  EXPECT_EQ(0, external_task_->pid_);
}

}  // namespace shill
