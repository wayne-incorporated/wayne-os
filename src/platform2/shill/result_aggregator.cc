// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/result_aggregator.h"

#include <utility>

#include "shill/event_dispatcher.h"
#include "shill/logging.h"

#include <base/check.h>
#include <base/logging.h>
#include <base/time/time.h>

namespace shill {

ResultAggregator::ResultAggregator(ResultCallback callback,
                                   base::Location location,
                                   std::string error_prefix)
    : ResultAggregator(std::move(callback),
                       std::move(location),
                       std::move(error_prefix),
                       nullptr,
                       base::TimeDelta()) {}

ResultAggregator::ResultAggregator(ResultCallback callback,
                                   base::Location location,
                                   std::string error_prefix,
                                   EventDispatcher* dispatcher,
                                   base::TimeDelta timeout)
    : weak_ptr_factory_(this),
      callback_(std::move(callback)),
      timeout_callback_(base::BindOnce(&ResultAggregator::Timeout,
                                       weak_ptr_factory_.GetWeakPtr())),
      got_result_(false),
      timed_out_(false),
      location_(std::move(location)),
      error_prefix_(std::move(error_prefix)) {
  CHECK(!callback_.is_null());
  if (dispatcher) {
    dispatcher->PostDelayedTask(FROM_HERE, timeout_callback_.callback(),
                                timeout);
  }
}

ResultAggregator::~ResultAggregator() {
  if (got_result_ && !timed_out_) {
    std::move(callback_).Run(error_);
  }
  // timeout_callback_ will automatically be canceled when its destructor
  // is invoked.
}

void ResultAggregator::ReportResult(const Error& error) {
  LOG(INFO) << Error::GetLocationAsString(error.location()) << error;
  got_result_ = true;
  if (error_.IsSuccess() && error.IsFailure()) {  // Only copy first |error|.
    error_.Populate(error.type(), error_prefix_ + error.message(), location_);
  } else {
    LOG(WARNING) << "Dropping error type " << error;
  }
}

void ResultAggregator::Timeout() {
  LOG(WARNING) << "Results aggregator timed out";
  timed_out_ = true;
  error_.Populate(Error::kOperationTimeout,
                  error_prefix_ + "Results aggregator timed out", location_);
  std::move(callback_).Run(error_);
}

}  // namespace shill
