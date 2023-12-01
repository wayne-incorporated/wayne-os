// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_DNS_DNS_QUERY_H_
#define PATCHPANEL_DNS_DNS_QUERY_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "brillo/brillo_export.h"

namespace base {
class BigEndianReader;
}  // namespace base

namespace patchpanel {

namespace dns_protocol {
struct Header;
}  // namespace dns_protocol

class IOBufferWithSize;

// Represents on-the-wire DNS query message as an object.
class BRILLO_EXPORT DnsQuery {
 public:
  // Constructs an empty query from a raw packet in |buffer|. If the raw packet
  // represents a valid DNS query in the wire format (RFC 1035), Parse() will
  // populate the empty query.
  explicit DnsQuery(scoped_refptr<IOBufferWithSize> buffer);

  ~DnsQuery();

  // Returns true and populates the query if the internally stored raw packet
  // can be parsed. This should only be called when DnsQuery is constructed from
  // the raw buffer.
  // |valid_bytes| indicates the number of initialized bytes in the raw buffer.
  // E.g. if the buffer holds a packet received from the network, the buffer may
  // be allocated with the maximum size of a UDP packet, but |valid_bytes|
  // indicates the number of bytes actually received from the network. If the
  // parsing requires reading more than the number of initialized bytes, this
  // method fails and returns false.
  bool Parse(size_t valid_bytes);

  // DnsQuery field accessors.
  uint16_t id() const;
  base::StringPiece qname() const;
  uint16_t qtype() const;

  // Returns the Question section of the query.  Used when matching the
  // response.
  base::StringPiece question() const;

  // Returns the size of the question section.
  size_t question_size() const;

  // IOBuffer accessor to be used for writing out the query. The buffer has
  // the same byte layout as the DNS query wire format.
  IOBufferWithSize* io_buffer() const { return io_buffer_.get(); }

 private:
  bool ReadHeader(base::BigEndianReader* reader, dns_protocol::Header* out);
  // After read, |out| is in the DNS format, e.g.
  // "\x03""www""\x08""chromium""\x03""com""\x00". Use DNSDomainToString to
  // convert to the dotted format "www.chromium.com" with no trailing dot.
  bool ReadName(base::BigEndianReader* reader, std::string* out);

  // Size of the DNS name (*NOT* hostname) we are trying to resolve; used
  // to calculate offsets.
  size_t qname_size_ = 0;

  // Contains query bytes to be consumed by higher level Write() call.
  scoped_refptr<IOBufferWithSize> io_buffer_;

  // Pointer to the dns header section.
  dns_protocol::Header* header_ = nullptr;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_DNS_DNS_QUERY_H_
