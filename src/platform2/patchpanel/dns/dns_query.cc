// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/dns/dns_query.h"

#include <utility>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/sys_byteorder.h"
// Ignore Wconversion warnings in libbase headers.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include "base/big_endian.h"
#include "base/numerics/safe_conversions.h"
#pragma GCC diagnostic pop

#include "patchpanel/dns/dns_protocol.h"
#include "patchpanel/dns/dns_util.h"
#include "patchpanel/dns/io_buffer.h"

#include <base/check.h>

namespace patchpanel {

namespace {

const size_t kHeaderSize = sizeof(dns_protocol::Header);

size_t QuestionSize(size_t qname_size) {
  // QNAME + QTYPE + QCLASS
  return qname_size + sizeof(uint16_t) + sizeof(uint16_t);
}

}  // namespace

DnsQuery::DnsQuery(scoped_refptr<IOBufferWithSize> buffer)
    : io_buffer_(std::move(buffer)) {}

DnsQuery::~DnsQuery() = default;

bool DnsQuery::Parse(size_t valid_bytes) {
  if (io_buffer_ == nullptr || io_buffer_->data() == nullptr) {
    return false;
  }
  CHECK(valid_bytes <= base::checked_cast<size_t>(io_buffer_->size()));
  // We should only parse the query once if the query is constructed from a raw
  // buffer. If we have constructed the query from data or the query is already
  // parsed after constructed from a raw buffer, |header_| is not null.
  DCHECK(header_ == nullptr);
  base::BigEndianReader reader(
      reinterpret_cast<const uint8_t*>(io_buffer_->data()), valid_bytes);
  dns_protocol::Header header;
  if (!ReadHeader(&reader, &header)) {
    return false;
  }
  if (header.flags & dns_protocol::kFlagResponse) {
    return false;
  }
  if (header.qdcount > 1) {
    LOG(ERROR) << "Not supporting parsing a DNS query with multiple questions.";
    return false;
  }
  std::string qname;
  if (!ReadName(&reader, &qname)) {
    return false;
  }
  uint16_t qtype;
  uint16_t qclass;
  if (!reader.ReadU16(&qtype) || !reader.ReadU16(&qclass) ||
      qclass != dns_protocol::kClassIN) {
    return false;
  }
  // |io_buffer_| now contains the raw packet of a valid DNS query, we just
  // need to properly initialize |qname_size_| and |header_|.
  qname_size_ = qname.size();
  header_ = reinterpret_cast<dns_protocol::Header*>(io_buffer_->data());
  return true;
}

uint16_t DnsQuery::id() const {
  return base::NetToHost16(header_->id);
}

base::StringPiece DnsQuery::qname() const {
  return base::StringPiece(io_buffer_->data() + kHeaderSize, qname_size_);
}

uint16_t DnsQuery::qtype() const {
  uint16_t type;
  base::ReadBigEndian<uint16_t>(
      reinterpret_cast<const uint8_t*>(io_buffer_->data() + kHeaderSize +
                                       qname_size_),
      &type);
  return type;
}

base::StringPiece DnsQuery::question() const {
  return base::StringPiece(io_buffer_->data() + kHeaderSize,
                           QuestionSize(qname_size_));
}

size_t DnsQuery::question_size() const {
  return QuestionSize(qname_size_);
}

bool DnsQuery::ReadHeader(base::BigEndianReader* reader,
                          dns_protocol::Header* header) {
  return (
      reader->ReadU16(&header->id) && reader->ReadU16(&header->flags) &&
      reader->ReadU16(&header->qdcount) && reader->ReadU16(&header->ancount) &&
      reader->ReadU16(&header->nscount) && reader->ReadU16(&header->arcount));
}

bool DnsQuery::ReadName(base::BigEndianReader* reader, std::string* out) {
  DCHECK(out != nullptr);
  out->clear();
  out->reserve(dns_protocol::kMaxNameLength);
  uint8_t label_length;
  if (!reader->ReadU8(&label_length)) {
    return false;
  }
  out->append(reinterpret_cast<char*>(&label_length), 1);
  while (label_length) {
    base::StringPiece label;
    if (!reader->ReadPiece(&label, label_length)) {
      return false;
    }
    out->append(label.data(), label.size());
    if (!reader->ReadU8(&label_length)) {
      return false;
    }
    out->append(reinterpret_cast<char*>(&label_length), 1);
  }
  return true;
}

}  // namespace patchpanel
