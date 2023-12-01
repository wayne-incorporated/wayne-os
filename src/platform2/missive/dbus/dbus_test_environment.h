// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_DBUS_DBUS_TEST_ENVIRONMENT_H_
#define MISSIVE_DBUS_DBUS_TEST_ENVIRONMENT_H_

#include <base/memory/scoped_refptr.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace reporting::test {

class DBusTestEnvironment {
 public:
  DBusTestEnvironment();

  scoped_refptr<::testing::NiceMock<::dbus::MockBus>> mock_bus() const;
  scoped_refptr<::testing::NiceMock<dbus::MockObjectProxy>> mock_chrome_proxy()
      const;

 private:
  static void CreateMockDBus(
      base::OnceCallback<
          void(scoped_refptr<::testing::NiceMock<dbus::MockBus>>)> ready_cb);

  void AssertOnDBusThread() const;

  const scoped_refptr<base::SequencedTaskRunner> dbus_task_runner_;

  scoped_refptr<::testing::NiceMock<dbus::MockBus>> mock_bus_;
  scoped_refptr<::testing::NiceMock<dbus::MockObjectProxy>> mock_chrome_proxy_;
};
}  // namespace reporting::test

#endif  // MISSIVE_DBUS_DBUS_TEST_ENVIRONMENT_H_
