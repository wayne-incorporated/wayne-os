// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/result_aggregator.h"

#include <base/functional/bind.h>
#include <base/memory/ref_counted.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_event_dispatcher.h"
#include "shill/test_event_dispatcher.h"
#include "shill/testing.h"

namespace shill {

using testing::_;
using testing::StrictMock;

namespace {

constexpr base::TimeDelta kTimeout = base::TimeDelta();

}  // namespace

class ResultAggregatorTest : public ::testing::Test {
 public:
  ResultAggregatorTest()
      : aggregator_(new ResultAggregator(
            base::BindOnce(&ResultAggregatorTest::ReportResult,
                           base::Unretained(this)),
            FROM_HERE,
            "Aggregated result: ")) {}
  ~ResultAggregatorTest() override = default;

  void TearDown() override {
    aggregator_ = nullptr;  // Ensure ReportResult is invoked before our dtor.
  }

  MOCK_METHOD(void, ReportResult, (const Error&));

 protected:
  scoped_refptr<ResultAggregator> aggregator_;
};

class ResultAggregatorTestWithDispatcher : public ResultAggregatorTest {
 public:
  ResultAggregatorTestWithDispatcher() = default;
  ~ResultAggregatorTestWithDispatcher() override = default;

  void InitializeResultAggregatorWithTimeout() {
    aggregator_ = new ResultAggregator(
        base::BindOnce(&ResultAggregatorTest::ReportResult,
                       base::Unretained(this)),
        FROM_HERE, "Aggregated result: ", &dispatcher_, kTimeout);
  }

 protected:
  EventDispatcherForTest dispatcher_;
};

class ResultAggregatorTestWithMockDispatcher : public ResultAggregatorTest {
 public:
  ResultAggregatorTestWithMockDispatcher() = default;
  ~ResultAggregatorTestWithMockDispatcher() override = default;

 protected:
  StrictMock<MockEventDispatcher> dispatcher_;
};

class ResultGenerator {
 public:
  explicit ResultGenerator(const scoped_refptr<ResultAggregator>& aggregator)
      : aggregator_(aggregator) {}
  ResultGenerator(const ResultGenerator&) = delete;
  ResultGenerator& operator=(const ResultGenerator&) = delete;

  ~ResultGenerator() = default;

  void GenerateResult(const Error::Type error_type) {
    aggregator_->ReportResult(Error(error_type));
  }

 private:
  scoped_refptr<ResultAggregator> aggregator_;
};

TEST_F(ResultAggregatorTestWithMockDispatcher, Unused) {
  EXPECT_CALL(*this, ReportResult(ErrorTypeIs(Error::kSuccess))).Times(0);
}

TEST_F(ResultAggregatorTestWithMockDispatcher, BothSucceed) {
  EXPECT_CALL(*this, ReportResult(ErrorTypeIs(Error::kSuccess)));
  ResultGenerator first_generator(aggregator_);
  ResultGenerator second_generator(aggregator_);
  first_generator.GenerateResult(Error::kSuccess);
  second_generator.GenerateResult(Error::kSuccess);
}

TEST_F(ResultAggregatorTestWithMockDispatcher, FirstFails) {
  EXPECT_CALL(*this, ReportResult(ErrorTypeIs(Error::kOperationTimeout)));
  ResultGenerator first_generator(aggregator_);
  ResultGenerator second_generator(aggregator_);
  first_generator.GenerateResult(Error::kOperationTimeout);
  second_generator.GenerateResult(Error::kSuccess);
}

TEST_F(ResultAggregatorTestWithMockDispatcher, SecondFails) {
  EXPECT_CALL(*this, ReportResult(ErrorTypeIs(Error::kOperationTimeout)));
  ResultGenerator first_generator(aggregator_);
  ResultGenerator second_generator(aggregator_);
  first_generator.GenerateResult(Error::kSuccess);
  second_generator.GenerateResult(Error::kOperationTimeout);
}

TEST_F(ResultAggregatorTestWithMockDispatcher, BothFail) {
  EXPECT_CALL(*this, ReportResult(ErrorTypeIs(Error::kOperationTimeout)));
  ResultGenerator first_generator(aggregator_);
  ResultGenerator second_generator(aggregator_);
  first_generator.GenerateResult(Error::kOperationTimeout);
  second_generator.GenerateResult(Error::kPermissionDenied);
}

TEST_F(ResultAggregatorTestWithMockDispatcher,
       TimeoutCallbackPostedOnConstruction) {
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, kTimeout));
  auto result_aggregator = base::MakeRefCounted<ResultAggregator>(
      base::BindOnce(&ResultAggregatorTest::ReportResult,
                     base::Unretained(this)),
      FROM_HERE, "Aggregated result: ", &dispatcher_, kTimeout);
}

TEST_F(ResultAggregatorTestWithDispatcher,
       TimeoutReceivedWithoutAnyResultsReceived) {
  InitializeResultAggregatorWithTimeout();
  EXPECT_CALL(*this, ReportResult(ErrorTypeIs(Error::kOperationTimeout)));
  ResultGenerator generator(aggregator_);
  dispatcher_.DispatchPendingEvents();  // Invoke timeout callback.
}

TEST_F(ResultAggregatorTestWithDispatcher, TimeoutAndOtherResultReceived) {
  // Timeout should override any other error results.
  InitializeResultAggregatorWithTimeout();
  EXPECT_CALL(*this, ReportResult(ErrorTypeIs(Error::kOperationTimeout)));
  ResultGenerator first_generator(aggregator_);
  ResultGenerator second_generator(aggregator_);
  first_generator.GenerateResult(Error::kSuccess);
  dispatcher_.DispatchPendingEvents();  // Invoke timeout callback.
  second_generator.GenerateResult(Error::kPermissionDenied);
}

TEST_F(ResultAggregatorTestWithDispatcher,
       TimeoutCallbackNotInvokedIfAllActionsComplete) {
  {
    auto result_aggregator = base::MakeRefCounted<ResultAggregator>(
        base::BindOnce(&ResultAggregatorTest::ReportResult,
                       base::Unretained(this)),
        FROM_HERE, "Aggregated result: ", &dispatcher_, kTimeout);
    // The result aggregator receives the one callback it expects, and goes
    // out of scope. At this point, it should invoke the ReportResult callback
    // with the error type kPermissionDenied that it copied.
    ResultGenerator generator(result_aggregator);
    generator.GenerateResult(Error::kPermissionDenied);
    EXPECT_CALL(*this, ReportResult(ErrorTypeIs(Error::kPermissionDenied)));
  }
  // The timeout callback should be canceled after the ResultAggregator went
  // out of scope and was destructed.
  EXPECT_CALL(*this, ReportResult(ErrorTypeIs(Error::kOperationTimeout)))
      .Times(0);
  dispatcher_.DispatchPendingEvents();
}

}  // namespace shill
