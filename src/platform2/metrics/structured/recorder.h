// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_STRUCTURED_RECORDER_H_
#define METRICS_STRUCTURED_RECORDER_H_

namespace metrics {
namespace structured {

class EventBase;

class Recorder {
 public:
  virtual ~Recorder() {}
  virtual bool Record(const EventBase& event) = 0;
};

}  // namespace structured
}  // namespace metrics

#endif  // METRICS_STRUCTURED_RECORDER_H_
