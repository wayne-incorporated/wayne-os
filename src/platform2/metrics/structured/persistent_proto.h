// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_STRUCTURED_PERSISTENT_PROTO_H_
#define METRICS_STRUCTURED_PERSISTENT_PROTO_H_

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/memory/scoped_refptr.h>
#include <base/time/time.h>

namespace metrics {
namespace structured {

// PersistentProto wraps a proto class and persists it to disk. Usage summary:
//  - pproto->Method() will call Method on the underlying proto.
//  - Call Write() to write to disk.
//
// Reading. The backing file is read from disk once at initialization. If no
// proto file exists on disk, or it is invalid, a blank proto is constructed
// and immediately written to disk.
//
// Writing. Writes must be triggered manually by calling |Write|.
//
// WARNING. Every proto this class can be used with needs to be listed at the
// bottom of the cc file.
template <class T>
class PersistentProto {
 public:
  explicit PersistentProto(const std::string& path);
  ~PersistentProto();

  PersistentProto(const PersistentProto&) = delete;
  PersistentProto& operator=(const PersistentProto&) = delete;

  T* get() { return proto_.get(); }

  T* operator->() {
    CHECK(proto_);
    return proto_.get();
  }

  T operator*() {
    CHECK(proto_);
    return *proto_;
  }

  constexpr bool has_value() const { return proto_.get() != nullptr; }

  constexpr explicit operator bool() const { return has_value(); }

  void Write();

 private:
  void OnQueueWrite();

  // Path on disk to read from and write to.
  const std::string path_;

  // The proto itself.
  std::unique_ptr<T> proto_;
};

}  // namespace structured
}  // namespace metrics

#endif  // METRICS_STRUCTURED_PERSISTENT_PROTO_H_
