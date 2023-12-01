// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_UTILS_H_
#define FEDERATED_UTILS_H_

#include <optional>
#include <string>

#include <base/files/file_path.h>

#include "federated/mojom/example.mojom.h"
#include "federated/protos/example.pb.h"
#include "federated/protos/feature.pb.h"

namespace federated {

// The maximum of example count that are consumed in one federated computation
// round.
extern const size_t kMaxStreamingExampleCount;
// The minimum of example count that are required in one federated computation
// round.
extern const size_t kMinExampleCount;
extern const char kSessionStartedState[];
extern const char kSessionStoppedState[];
extern const char kUserDatabasePath[];
extern const char kDatabaseFileName[];

// Gets the database file path with the given sanitized_username.
base::FilePath GetDatabasePath(const std::string& sanitized_username);

// Gets the base_dir inside the cryptohome.
// `base_dir` is used for opstats db which is created by brella library and
// serves as an on-device record of brella execution history and logs. Because
// the CrOS example storage is on cryptohome hence per-sanitized_username, the
// opstats db should also be like this.
base::FilePath GetBaseDir(const std::string& sanitized_username,
                          const std::string& client_name);

// Converts the mojom Example struct to a TensorFlow Example proto.
tensorflow::Example ConvertToTensorFlowExampleProto(
    const chromeos::federated::mojom::ExamplePtr& example);

// Packs the given chromeos release version to a long integer and returns in
// string format with the platform prefix "chromeos_". Returns std::nullopt if
// the release_version doesn't match the pattern.
// A release_version should be like: 15217.123.2. The minor version could be
// several hundreds, let's reserve 6 digits for it. The sub version is rarely
// greater than 1, let's reserve 4 digits. Theoretically the major version could
// be infinite, but given it's now 15xxx and we need to pack them in an int64,
// let's allow up to 9 digits and not pad it.
// Then 15217.123.2 => chromeos_152170001230002
std::optional<std::string> ConvertBrellaLibVersion(
    const std::string& release_version);

}  // namespace federated

#endif  // FEDERATED_UTILS_H_
