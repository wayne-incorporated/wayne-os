// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_QUOTE_H_
#define CROS_DISKS_QUOTE_H_

#include <ostream>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/logging.h>

namespace cros_disks {

// Helper struct that holds a non-owning const reference to a T and allows to
// print a quoted version of it to an output stream.
//
// Don't use it directly. Call quote() instead.
template <typename T>
struct Quoter {
  const T& ref;
  const bool redacted = false;
};

// Allows to print a quoted version of its argument to an output stream for
// logging purpose.
//
// T must be a quotable type, ie a string, a FilePath or a vector of quotable
// elements.
//
// The returned Quoter should be streamed directly without being stored.
// The typical usage pattern is:
//
// LOG(ERROR) << "Cannot do something with " << quote(stuff) << ": Reason why";
template <typename T>
Quoter<T> quote(const T& ref) {
  return {ref};
}

// Allows to print a quoted version of its argument to an output stream for
// logging purpose, or a redacted version if the current log level is less than
// INFO.
//
// T must be a quotable type, ie a string, a FilePath or a vector of quotable
// elements.
//
// The returned Quoter should be streamed directly without being stored.
// The typical usage pattern is:
//
// LOG(ERROR) << "Cannot do something with " << redact(stuff) << ": Reason why";
template <typename T>
Quoter<T> redact(const T& ref, const bool redacted = !LOG_IS_ON(INFO)) {
  return {ref, redacted};
}

// Outputs a quoted C-style string, or (null) for a null pointer.
std::ostream& operator<<(std::ostream& out, Quoter<const char*> quoter);

// Outputs a quoted standard string.
std::ostream& operator<<(std::ostream& out, Quoter<std::string> quoter);

// Outputs a quoted file path.
std::ostream& operator<<(std::ostream& out, Quoter<base::FilePath> quoter);

// Outputs a quoted string literal.
// This is needed because quote("some string literal") doesn't decay the passed
// string literal to a const char* but keeps it as a reference to a const
// char[N].
template <size_t N>
std::ostream& operator<<(std::ostream& out, Quoter<char[N]> quoter) {
  const char* const s = quoter.ref;
  return out << redact(s, quoter.redacted);
}

// Outputs a sequence of quoted items.
template <typename T, typename = decltype(std::declval<const T&>().begin())>
std::ostream& operator<<(std::ostream& out, Quoter<T> quoter) {
  out << '[';
  const char* sep = "";
  for (const auto& item : quoter.ref) {
    out << std::exchange(sep, ", ") << redact(item, quoter.redacted);
  }
  return out << ']';
}

}  // namespace cros_disks

#endif  // CROS_DISKS_QUOTE_H_
