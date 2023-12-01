/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_LOG_UTILS_H_
#define HARDWARE_VERIFIER_LOG_UTILS_H_

#include <string>

#include <base/logging.h>
#include <google/protobuf/message.h>

namespace hardware_verifier {

// A helper function to dump the given protobuf message.
inline void VLogProtobuf(int verbosity,
                         const std::string& msg_name,
                         const google::protobuf::Message& msg) {
  VLOG(verbosity) << "<--- Begin: dump of |" << msg_name << "|\n\n"
                  << msg.DebugString() << "\n<--- End.";
}

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_LOG_UTILS_H_
