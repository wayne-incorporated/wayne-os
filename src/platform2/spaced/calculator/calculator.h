// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SPACED_CALCULATOR_CALCULATOR_H_
#define SPACED_CALCULATOR_CALCULATOR_H_

#include <atomic>

// Calculator provides an interface for applications to represent disk
// space calculations. The calculator |size_| is atomic to make it thread-safe;
// this allows offload of calculations to an asynchronous thread.
class Calculator {
 public:
  Calculator() = default;
  Calculator(const Calculator&) = delete;
  Calculator& operator=(const Calculator&) = delete;

  virtual ~Calculator() = default;

  int64_t GetSize() { return size_; }

 protected:
  void SetSize(int64_t size) { size_ = size; }

 private:
  std::atomic<int64_t> size_;
};

#endif  // SPACED_CALCULATOR_CALCULATOR_H_
