// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/dbus/dbus_test_environment.h"

#include <limits>
#include <optional>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/util/test_support_callbacks.h"

using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

namespace reporting::test {

DBusTestEnvironment::DBusTestEnvironment()
    : dbus_task_runner_(base::ThreadPool::CreateSequencedTaskRunner(
          {base::TaskPriority::BEST_EFFORT, base::MayBlock()})) {
  test::TestEvent<scoped_refptr<NiceMock<dbus::MockBus>>> dbus_waiter;
  dbus_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&DBusTestEnvironment::CreateMockDBus, dbus_waiter.cb()));
  mock_bus_ = dbus_waiter.result();

  EXPECT_CALL(*mock_bus_, GetDBusTaskRunner())
      .WillRepeatedly(Return(dbus_task_runner_.get()));

  EXPECT_CALL(*mock_bus_, GetOriginTaskRunner())
      .WillRepeatedly(Return(dbus_task_runner_.get()));

  // We actually want AssertOnOriginThread and AssertOnDBusThread to work
  // properly (actually assert they are on dbus_thread_). If the unit tests
  // end up creating calls on the wrong thread, the unit test will just hang
  // anyways, and it's easier to debug if we make the program crash at that
  // point. Since these are ON_CALLs, VerifyAndClearMockExpectations doesn't
  // clear them.
  ON_CALL(*mock_bus_, AssertOnOriginThread())
      .WillByDefault(Invoke(this, &DBusTestEnvironment::AssertOnDBusThread));
  ON_CALL(*mock_bus_, AssertOnDBusThread())
      .WillByDefault(Invoke(this, &DBusTestEnvironment::AssertOnDBusThread));

  mock_chrome_proxy_ = base::WrapRefCounted(new NiceMock<dbus::MockObjectProxy>(
      mock_bus_.get(), chromeos::kChromeReportingServiceName,
      dbus::ObjectPath(chromeos::kChromeReportingServicePath)));
}

scoped_refptr<::testing::NiceMock<::dbus::MockBus>>
DBusTestEnvironment::mock_bus() const {
  return mock_bus_;
}

scoped_refptr<::testing::NiceMock<dbus::MockObjectProxy>>
DBusTestEnvironment::mock_chrome_proxy() const {
  return mock_chrome_proxy_;
}

// static
void DBusTestEnvironment::CreateMockDBus(
    base::OnceCallback<void(scoped_refptr<NiceMock<dbus::MockBus>>)> ready_cb) {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  std::move(ready_cb).Run(base::WrapRefCounted<NiceMock<dbus::MockBus>>(
      new NiceMock<dbus::MockBus>(options)));
}

void DBusTestEnvironment::AssertOnDBusThread() const {
  ASSERT_TRUE(dbus_task_runner_->RunsTasksInCurrentSequence());
}
}  // namespace reporting::test
