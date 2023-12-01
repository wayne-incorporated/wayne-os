// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_STRUCTURED_KEY_DATA_H_
#define METRICS_STRUCTURED_KEY_DATA_H_

#include <memory>
#include <optional>
#include <string>

#include <base/files/file_path.h>

#include "metrics/structured/persistent_proto.h"
#include "metrics/structured/proto/storage.pb.h"

namespace metrics {
namespace structured {

// KeyData is the central class for managing keys and generating hashes for
// structured metrics.
//
// The class maintains one key and its rotation data for every project defined
// in /tools/metrics/structured.xml. This can be used to generate:
//  - a user ID for the project with KeyData::Id.
//  - a hash of a given value for an event with KeyData::HmacMetric.
//
// KeyData performs key rotation. Every project is associated with a rotation
// period, which is 90 days unless specified in structured.xml. Keys are rotated
// with a resolution of one day. They are guaranteed not to be used for
// HmacMetric or UserProjectId for longer than their rotation period, except in
// cases of local clock changes.
//
// When first created, every project's key rotation date is selected uniformly
// so that there is an even distribution of rotations across users. This means
// that, for most users, the first rotation period will be shorter than the
// standard full rotation period for that project.
//
// Key storage is backed by a PersistentProto, stored at the path given to the
// constructor.
//
// TODO(crbug.com/1148168): Consider splitting this across multiple
// PersistentProtos if we have multiple cros clients.
class KeyData {
 public:
  explicit KeyData(const std::string& path);
  ~KeyData();

  KeyData(const KeyData&) = delete;
  KeyData& operator=(const KeyData&) = delete;

  // Returns a digest of |value| for |metric| in the context of
  // |project_name_hash|. Terminology: a metric is a (name, value) pair, and an
  // event is a bundle of metrics. Each event is associated with a project.
  //
  //  - |project_name_hash| is the uint64 name hash of a project.
  //  - |metric_name_hash| is the uint64 name hash of a metric.
  //  - |value| is the string value to hash.
  //
  // The result is the HMAC digest of the |value| salted with |metric|, using
  // the key for |project_name_hash|. That is:
  //
  //   HMAC_SHA256(key(project_name_hash), concat(value, hex(event),
  //   hex(metric)))
  //
  // Returns 0u in case of an error.
  uint64_t HmacMetric(uint64_t project_name_hash,
                      uint64_t metric_name_hash,
                      const std::string& value);

  // Returns an ID for this (user, |project_name_hash|) pair.
  // |project_name_hash| is the name of a project, represented by the first 8
  // bytes of the MD5 hash of its name defined in structured.xml.
  //
  // The derived ID is the first 8 bytes of SHA256(key(project_name_hash)).
  // Returns 0u in case of an error.
  //
  // This ID is intended as the only ID for the events of a particular
  // structured metrics project. However, events are uploaded from the device
  // alongside the UMA client ID, which is only removed after the event reaches
  // the server. This means events are associated with the client ID when
  // uploaded from the device. See the class comment of
  // StructuredMetricsProvider for more details.
  uint64_t Id(uint64_t project_name_hash);

 private:
  // Ensure that a valid key exists for |project|, and return it. Either returns
  // a string of size |kKeySize| or std::nullopt, which indicates an error.
  std::optional<std::string> ValidateAndGetKey(uint64_t project_name_hash);

  // Regenerate |key|, also updating the |last_rotation| and |rotation_period|.
  // This triggers a save.
  void UpdateKey(KeyProto* key, int last_rotation, int rotation_period);

  // Storage for keys.
  std::unique_ptr<PersistentProto<KeyDataProto>> proto_;
};

}  // namespace structured
}  // namespace metrics

#endif  // METRICS_STRUCTURED_KEY_DATA_H_
