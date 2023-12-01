// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/dbus_properties_proxy.h"

#include <utility>

#include <base/memory/weak_ptr.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "shill/dbus/fake_properties_proxy.h"

namespace {

const char kInterface[] = "Modem";
const char kProperty1[] = "State";
const char kProperty2[] = "Model";
const brillo::VariantDictionary kTestDictionary = {
    {kProperty1, brillo::Any(1)},
    {kProperty2, brillo::Any("2")},
};

}  // namespace

namespace shill {

class DBusPropertiesProxyTest : public testing::Test {
 public:
  DBusPropertiesProxyTest()
      : dbus_properties_proxy_(
            DBusPropertiesProxy::CreateDBusPropertiesProxyForTesting(
                std::make_unique<FakePropertiesProxy>())) {
    static_cast<FakePropertiesProxy*>(
        dbus_properties_proxy_->GetDBusPropertiesProxyForTesting())
        ->SetDictionaryForTesting(kInterface, kTestDictionary);
  }
  ~DBusPropertiesProxyTest() override = default;

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  std::unique_ptr<DBusPropertiesProxy> dbus_properties_proxy_;
  FakePropertiesProxy* fake_properties_proxy_;
  base::WeakPtrFactory<DBusPropertiesProxyTest> weak_factory_{this};
};

TEST_F(DBusPropertiesProxyTest, GetAll) {
  KeyValueStore properties = dbus_properties_proxy_->GetAll(kInterface);
  EXPECT_EQ(properties.properties(), kTestDictionary);
}

TEST_F(DBusPropertiesProxyTest, GetAllAsync) {
  KeyValueStore properties;
  base::RunLoop run_loop;
  dbus_properties_proxy_->GetAllAsync(
      kInterface,
      base::BindOnce(
          [](base::OnceClosure callback, KeyValueStore* result,
             const KeyValueStore& dict) {
            *result = dict;
            std::move(callback).Run();
          },
          run_loop.QuitClosure(), &properties),
      base::BindOnce([](base::OnceClosure callback,
                        const Error& error) { std::move(callback).Run(); },
                     run_loop.QuitClosure()));
  EXPECT_EQ(properties.properties(), kTestDictionary);
}

TEST_F(DBusPropertiesProxyTest, Get) {
  brillo::Any property1 = dbus_properties_proxy_->Get(kInterface, kProperty1);
  EXPECT_EQ(property1, kTestDictionary.at(kProperty1));
  brillo::Any property2 = dbus_properties_proxy_->Get(kInterface, kProperty2);
  EXPECT_EQ(property2, kTestDictionary.at(kProperty2));
}

TEST_F(DBusPropertiesProxyTest, GetFailed) {
  const char kBadInterface[] = "bad interface";
  const char kBadProperty[] = "bad property";
  brillo::Any property =
      dbus_properties_proxy_->Get(kBadInterface, kBadProperty);
  EXPECT_TRUE(property.IsEmpty());
}

TEST_F(DBusPropertiesProxyTest, GetAsync) {
  brillo::Any property1;
  base::RunLoop run_loop;
  dbus_properties_proxy_->GetAsync(
      kInterface, kProperty1,
      base::BindOnce(
          [](base::OnceClosure callback, brillo::Any* result,
             const brillo::Any& value) {
            *result = value;
            std::move(callback).Run();
          },
          run_loop.QuitClosure(), &property1),
      base::BindOnce([](base::OnceClosure callback,
                        const Error& error) { std::move(callback).Run(); },
                     run_loop.QuitClosure()));
  EXPECT_EQ(property1, kTestDictionary.at(kProperty1));
}

TEST_F(DBusPropertiesProxyTest, GetAsyncFailed) {
  const char kBadInterface[] = "bad interface";
  const char kBadProperty[] = "bad property";
  brillo::Any property;
  Error error;
  base::RunLoop run_loop;
  dbus_properties_proxy_->GetAsync(
      kBadInterface, kBadProperty,
      base::BindOnce(
          [](base::OnceClosure callback, brillo::Any* result,
             const brillo::Any& value) { std::move(callback).Run(); },
          run_loop.QuitClosure(), &property),
      base::BindOnce(
          [](base::OnceClosure callback, Error* errorp, const Error& error) {
            *errorp = error;
            std::move(callback).Run();
          },
          run_loop.QuitClosure(), &error));
  EXPECT_TRUE(property.IsEmpty());
  EXPECT_EQ(error.type(), Error::kOperationFailed);
}

}  // namespace shill
