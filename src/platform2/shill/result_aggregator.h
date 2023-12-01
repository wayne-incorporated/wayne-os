// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_RESULT_AGGREGATOR_H_
#define SHILL_RESULT_AGGREGATOR_H_

#include <string>

#include <base/cancelable_callback.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/memory/scoped_refptr.h>
#include <base/time/time.h>

#include "shill/callbacks.h"
#include "shill/error.h"

namespace shill {

class EventDispatcher;

// The ResultAggregator is used to aggregate the result of multiple
// asynchronous operations. To use: construct a ResultAggregator, and
// Bind its ReportResult methods to some Callbacks. The ResultAggregator
// can also be constructed with an EventDispatcher pointer and timeout delay if
// we want to wait for a limited period of time for asynchronous operations
// to complete.
//
// When the Callbacks are destroyed, they will drop their references
// to the ResultAggregator. When all references to the ResultAggregator are
// destroyed, or if a timeout occurs, the ResultAggregator will invoke
// |callback_|. |callback_| will only be invoked exactly once by whichever of
// these two events occurs first.
//
// |callback_| will see Error type of Success if all Callbacks reported
// Success to ResultAggregator. If the timeout occurs, |callback_| will see
// Error type of OperationTimeout. Otherwise, |callback_| will see the first of
// the Errors reported to ResultAggregator.
//
// Note: If no callbacks invoked ReportResult and the ResultAggregator is
// destructed (before timing out), the ResultAggregator will be destructed
// silently and will not invoke |callback_|. This can cause unexpected
// behavior if the user expects |callback_| to be invoked after the
// result_aggregator goes out of scope. For example:
//
// void Manager::Foo() {
//   auto result_aggregator(base::MakeRefCounted<ResultAggregator>(
//       BindOnce(&Manager::Func, AsWeakPtr()), dispatcher_, 1000));
//   if (condition) {
//     LOG(ERROR) << "Failed!"
//     return;
//   }
//   ResultCallback aggregator_callback(
//       BindOnce(&ResultAggregator::ReportResult, result_aggregator));
//   devices_[0]->OnBeforeSuspend(std::move(aggregator_callback));
// }
//
// If |condition| is true and the function returns without passing the
// reference to |result_aggregator| to devices_[0], |result_aggregator| will
// be destructed upon returning from Manager::Foo and will never call
// Manager::Func(). This is problematic if the owner of |result_aggregator|
// expects Manager::Func to be called when |result_aggregator| goes out of
// scope.
//
// Another anomaly that can occur is it the ResultCallback that is being
// passed around is allowed to go out to scope without being run. If at least
// one object ran the ResultCallback, the ResultAggregator will invoke
// |callback_| upon going out of scope, even though there exists an object
// that was passed a ResultCallback but did not actually run it. This is
// incorrect behavior, as we assume that |callback_| will only be run if
// the ResultAggregator times out or if all objects that were passed the
// ResultCallback run it.
//
// In order to ensure that ResultAggregator behaves as it is meant to, follow
// these conventions when using it:
//   1) Always run any ResultCallback that is passed around before letting it
//      go out of scope.
//   2) If the ResultAggregator will go out of scope without passing any
//      ResultCallback objects (i.e. references to itself) to other objects,
//      invoke the callback the ResultAggregator was constructed with directly
//      before letting ResultAggregator go out of scope.

class ResultAggregator : public base::RefCounted<ResultAggregator> {
 public:
  ResultAggregator(ResultCallback callback,
                   base::Location location,
                   std::string error_prefix);
  ResultAggregator(ResultCallback callback,
                   base::Location location,
                   std::string error_prefix,
                   EventDispatcher* dispatcher,
                   base::TimeDelta timeout);
  ResultAggregator(const ResultAggregator&) = delete;
  ResultAggregator& operator=(const ResultAggregator&) = delete;

  virtual ~ResultAggregator();

  void ReportResult(const Error& error);

 private:
  // Callback for timeout registered with EventDispatcher.
  void Timeout();

  base::WeakPtrFactory<ResultAggregator> weak_ptr_factory_;
  ResultCallback callback_;
  base::CancelableOnceClosure timeout_callback_;
  bool got_result_;
  bool timed_out_;
  base::Location location_;
  std::string error_prefix_;
  Error error_;
};

}  // namespace shill

#endif  // SHILL_RESULT_AGGREGATOR_H_
