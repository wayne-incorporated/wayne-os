// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/http_server/connection_delegate.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <cinttypes>
#include <iomanip>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>

#include "p2p/common/constants.h"
#include "p2p/common/server_message.h"
#include "p2p/common/util.h"
#include "p2p/http_server/server.h"

using std::map;
using std::string;
using std::vector;

using base::Time;
using base::TimeDelta;

using p2p::common::ClockInterface;
using p2p::constants::kBytesPerKB;
using p2p::constants::kBytesPerMB;
using p2p::util::P2PServerMessageType;
using p2p::util::P2PServerRequestResult;

namespace p2p {

namespace http_server {

ConnectionDelegate::ConnectionDelegate(int dirfd,
                                       int fd,
                                       const string& pretty_addr,
                                       ServerInterface* server,
                                       int64_t max_download_rate)
    : ConnectionDelegateInterface(),
      dirfd_(dirfd),
      fd_(fd),
      pretty_addr_(pretty_addr),
      server_(server),
      max_download_rate_(max_download_rate),
      total_bytes_sent_(0) {
  CHECK_NE(-1, fd_);
  CHECK(server_ != NULL);
}

ConnectionDelegateInterface* ConnectionDelegate::Construct(
    int dirfd,
    int fd,
    const string& pretty_addr,
    ServerInterface* server,
    int64_t max_download_rate) {
  return new ConnectionDelegate(dirfd, fd, pretty_addr, server,
                                max_download_rate);
}

ConnectionDelegate::~ConnectionDelegate() {
  CHECK_EQ(-1, fd_);
}

bool ConnectionDelegate::ReadLine(string* str) {
  CHECK(str != NULL);

  while (true) {
    char buf[kLineBufSize];
    ssize_t num_recv;
    int n;

    num_recv = recv(fd_, buf, sizeof buf, MSG_PEEK);
    if (num_recv == -1) {
      PLOG(ERROR) << "Error reading";
      return false;
    }
    CHECK_GE(num_recv, 0);

    // When num_recv is 0 the other end has closed the socket. If we reach this
    // point, even with a partial line in str, we didn't get a full line and
    // should return since no fruther data will come from the file descriptor.
    if (num_recv == 0)
      return false;

    for (n = 0; n < num_recv; ++n) {
      str->push_back(buf[n]);

      if (buf[n] == '\n') {
        num_recv = recv(fd_, buf, n + 1, 0);  // skip processed data
        CHECK(num_recv == n + 1);
        return true;
      }

      if (str->size() > kMaxLineLength) {
        LOG(ERROR) << "Max line length (" << kMaxLineLength << ") exceeded";
        return false;
      }
    }
    num_recv = recv(fd_, buf, n, 0);  // skip
    CHECK(num_recv == n);
  }
}

// Removes "\r\n" from the passed in string. Returns false if
// the string didn't end in "\r\n".
static bool TrimCRLF(string* str) {
  CHECK(str != NULL);
  const char* c = str->c_str();
  size_t len = str->size();
  if (len < 2)
    return false;
  if (strcmp(c + len - 2, "\r\n") != 0)
    return false;
  str->resize(len - 2);
  return true;
}

P2PServerRequestResult ConnectionDelegate::ParseHttpRequest() {
  string request_line;
  map<string, string> headers;
  size_t sp1_pos, sp2_pos;
  string request_method;
  string request_uri;
  string request_http_version;

  if (!ReadLine(&request_line) || !TrimCRLF(&request_line))
    return p2p::util::kP2PRequestResultMalformed;

  VLOG(1) << "Request line: `" << request_line << "'";

  sp1_pos = request_line.find(" ");
  if (sp1_pos == string::npos) {
    LOG(ERROR) << "Malformed request line, didn't find starting space"
               << " (request_line=`" << request_line << "')";
    return p2p::util::kP2PRequestResultMalformed;
  }
  sp2_pos = request_line.rfind(" ");
  if (sp2_pos == string::npos) {
    LOG(ERROR) << "Malformed request line, didn't find ending space"
               << " (request_line=`" << request_line << "')";
    return p2p::util::kP2PRequestResultMalformed;
  }
  if (sp2_pos == sp1_pos) {
    LOG(ERROR) << "Malformed request line, initial space is the same as "
               << "ending space (request_line=`" << request_line << "')";
    return p2p::util::kP2PRequestResultMalformed;
  }
  CHECK(sp2_pos > sp1_pos);

  request_method = string(request_line, 0, sp1_pos);
  request_uri = string(request_line, sp1_pos + 1, sp2_pos - sp1_pos - 1);
  request_http_version = string(request_line, sp2_pos + 1, string::npos);

  VLOG(1) << "Parsed request line. "
          << "method=`" << request_method << "' "
          << "uri=`" << request_uri << "' "
          << "http_version=`" << request_http_version << "'";

  while (true) {
    string line;
    size_t colon_pos;

    if (!ReadLine(&line) || !TrimCRLF(&line))
      return p2p::util::kP2PRequestResultMalformed;

    if (line == "")
      break;

    // TODO(zeuthen): support header continuation. This TODO item is tracked in
    // https://code.google.com/p/chromium/issues/detail?id=246326
    colon_pos = line.find(": ");
    if (colon_pos == string::npos) {
      LOG(ERROR) << "Malformed HTTP header (line=`" << line << "')";
      return p2p::util::kP2PRequestResultMalformed;
    }

    string key = string(line, 0, colon_pos);
    string value = string(line, colon_pos + 2, string::npos);

    // HTTP headers are case-insensitive so lower-case.
    std::transform(key.begin(), key.end(), key.begin(),
                   static_cast<int (*)(int c)>(std::tolower));

    VLOG(1) << "Header[" << headers.size() << "] `" << key << "' -> `" << value
            << "'";
    headers[key] = value;

    if (headers.size() == kMaxHeaders) {
      LOG(ERROR) << "Exceeded maximum (" << kMaxHeaders
                 << ") number of HTTP headers";
      return p2p::util::kP2PRequestResultMalformed;
    }
  }

  // OK, looks like a valid HTTP request. Service the client.
  return ServiceHttpRequest(request_method, request_uri, request_http_version,
                            headers);
}

void ConnectionDelegate::Run() {
  P2PServerRequestResult req_res = ParseHttpRequest();

  // Report P2P.Server.RequestResult every time a HTTP request is handled.
  server_->ReportServerMessage(p2p::util::kP2PServerRequestResult, req_res);

  if (shutdown(fd_, SHUT_RDWR) != 0) {
    PLOG(ERROR) << "Error shutting down socket";
  }
  if (close(fd_) != 0) {
    PLOG(ERROR) << "Error closing socket";
  }
  fd_ = -1;

  server_->ConnectionTerminated(this);

  delete this;
}

bool ConnectionDelegate::SendResponse(int http_response_code,
                                      const string& http_response_status,
                                      const map<string, string>& headers,
                                      const string& body) {
  string response;
  const char* buf;
  size_t num_to_send;
  size_t num_total_sent;
  size_t body_size = body.size();
  bool has_content_length = false;
  bool has_server = false;

  response = "HTTP/1.1 ";
  response += std::to_string(http_response_code);
  response += " ";
  response += http_response_status;
  response += "\r\n";
  for (auto const& h : headers) {
    response += h.first + ": " + h.second + "\r\n";

    const char* header_name = h.first.c_str();
    if (strcasecmp(header_name, "Content-Length") == 0)
      has_content_length = true;
    else if (strcasecmp(header_name, "Server") == 0)
      has_server = true;
  }

  if (body_size > 0 && !has_content_length) {
    response += string("Content-Length: ");
    response += std::to_string(body_size) + "\r\n";
  }

  if (!has_server)
    response += "Server: p2p\r\n";

  response += "Connection: close\r\n";
  response += "\r\n";
  response += body;

  buf = response.c_str();
  num_to_send = response.size();
  num_total_sent = 0;
  while (num_to_send > 0) {
    ssize_t num_sent = send(fd_, buf + num_total_sent, num_to_send, 0);
    if (num_sent == -1) {
      PLOG(ERROR) << "Error sending";
      return false;
    }
    CHECK_GT(num_sent, 0);
    num_to_send -= num_sent;
    num_total_sent += num_sent;
  }
  return true;
}

/* ------------------------------------------------------------------------ */

bool ConnectionDelegate::SendSimpleResponse(
    int http_response_code, const string& http_response_status) {
  map<string, string> headers;
  return SendResponse(http_response_code, http_response_status, headers, "");
}

/* ------------------------------------------------------------------------ */

// Attempt to parse |range_str| as a "ranges-specifier" as defined in
// section 14.35 of RFC 2616. This is typically used in the "Range"
// header of HTTP requests. See
//
//  http://tools.ietf.org/html/rfc2616#section-14.35
//
// NOTE: To keep things simpler, we deliberately do _not_ support the
// full byte range specification.
static bool ParseRange(const string& range_str,
                       uint64_t file_size,
                       uint64_t* range_start,
                       uint64_t* range_end) {
  const char* s = range_str.c_str();

  CHECK(range_start != NULL);
  CHECK(range_end != NULL);

  if (sscanf(s, "bytes=%" SCNu64 "-%" SCNu64, range_start, range_end) == 2) {
    return *range_start <= *range_end;
  } else if (sscanf(s, "bytes=%" SCNu64 "-", range_start) == 1 &&
             *range_start <= file_size - 1) {
    *range_end = file_size - 1;
    return true;
  }

  return false;
}

bool ConnectionDelegate::SendFile(int file_fd, size_t num_bytes_to_send) {
  ClockInterface* clock;
  total_time_spent_ = TimeDelta();
  int seconds_spent_waiting = 0;
  char buf[kPayloadBufferSize];

  clock = server_->Clock();

  total_bytes_sent_ = 0;
  while (total_bytes_sent_ < num_bytes_to_send) {
    size_t num_to_read =
        std::min(sizeof buf, num_bytes_to_send - total_bytes_sent_);
    size_t num_to_send_from_buf;
    size_t num_sent_from_buf;
    ssize_t num_read;

    Time time_start = clock->GetMonotonicTime();
    num_read = read(file_fd, buf, num_to_read);
    if (num_read == 0) {
      // EOF - handle this by sleeping and trying again later.
      VLOG(1) << "Got EOF so sleeping one second";
      // Don't include the time sleeping in total_time_spent_.
      total_time_spent_ += clock->GetMonotonicTime() - time_start;
      clock->Sleep(base::Seconds(1));
      time_start = clock->GetMonotonicTime();
      seconds_spent_waiting++;

      // Give up if socket is no longer connected.
      if (IsStillConnected()) {
        continue;
      } else {
        LOG(INFO) << pretty_addr_ << " - peer no longer connected; giving up";
        return false;
      }
    } else if (num_read < 0) {
      // Note that the file is expected to be on a filesystem so Linux
      // guarantees that we never get EAGAIN. In other words, we never
      // get partial reads e.g. either we get everything we ask for or
      // none of it.
      PLOG(ERROR) << "Error reading";
      return false;
    }

    num_to_send_from_buf = num_read;
    num_sent_from_buf = 0;
    while (num_to_send_from_buf > 0) {
      ssize_t num_sent =
          send(fd_, buf + num_sent_from_buf, num_to_send_from_buf, 0);
      if (num_sent == -1) {
        PLOG(ERROR) << "Error sending";
        return false;
      }
      CHECK_GT(num_sent, 0);
      num_to_send_from_buf -= num_sent;
      num_sent_from_buf += num_sent;
    }
    total_bytes_sent_ += num_sent_from_buf;
    total_time_spent_ += clock->GetMonotonicTime() - time_start;

    // Limit download speed, if requested. Right now the speed is
    // calculated by considering the entire download session - this
    // could be improved by using e.g. a sliding window over the last
    // 30 seconds or so.
    if (max_download_rate_ != 0) {
      int64_t bytes_allowed =
          max_download_rate_ * total_time_spent_.InSecondsF();
      if (static_cast<int64_t>(total_bytes_sent_) > bytes_allowed) {
        int64_t over_budget =
            static_cast<int64_t>(total_bytes_sent_) - bytes_allowed;
        int64_t usec_to_sleep =
            (over_budget / static_cast<double>(max_download_rate_)) *
            Time::kMicrosecondsPerSecond;
        TimeDelta sleep_duration = base::Microseconds(usec_to_sleep);
        clock->Sleep(sleep_duration);
        total_time_spent_ += sleep_duration;
      }
    }
  }

  // If we served a file, log the time it took us.
  double total_seconds_spent =
      total_time_spent_.InSecondsF() + seconds_spent_waiting;
  if (total_bytes_sent_ > 0 && total_seconds_spent > 0) {
    LOG(INFO) << pretty_addr_ << " - sent " << total_bytes_sent_
              << " bytes of response body in " << std::fixed
              << std::setprecision(3) << total_seconds_spent << " seconds"
              << " (" << (total_bytes_sent_ / total_seconds_spent / 1e6)
              << " MB/s) including " << seconds_spent_waiting
              << " seconds spent waiting for content in the file.";
  }

  return true;
}

void ConnectionDelegate::ReportSendFileMetrics(bool send_file_result) {
  // Report P2P.Server.DownloadSpeedKBps with the average speed at wich the
  // download was served at, every time a file was served, interrupted or not.
  int average_speed_kbps = 0;
  if (total_time_spent_.InSecondsF() > 0.) {
    average_speed_kbps =
        total_bytes_sent_ / total_time_spent_.InSecondsF() / kBytesPerKB;
  }
  server_->ReportServerMessage(p2p::util::kP2PServerDownloadSpeedKBps,
                               average_speed_kbps);

  // TODO(deymo): Compute and report the P2P.Server.PeakDownloadSpeedKBps also
  // handling better the download speed computed in this function to consider
  // only a window of time instead of the average speed for the whole file.

  // Handle the error condition.
  if (!send_file_result) {
    if (total_bytes_sent_ > 0) {
      // Report P2P.Server.ContentServedInterruptedMB every time we have served
      // part of a file but the transmission was interrupted.
      server_->ReportServerMessage(p2p::util::kP2PServerServedInterruptedMB,
                                   total_bytes_sent_ / kBytesPerMB);
    }
    return;
  }

  if (total_bytes_sent_ > 0) {
    // Report P2P.Server.ContentServedSuccessfullyMB every time we have served
    // a file to its end.
    server_->ReportServerMessage(p2p::util::kP2PServerServedSuccessfullyMB,
                                 total_bytes_sent_ / kBytesPerMB);
  }
}

P2PServerRequestResult ConnectionDelegate::ServiceHttpRequest(
    const string& method,
    const string& uri,
    const string& version,
    const map<string, string>& headers) {
  struct stat statbuf;
  size_t file_size = 0;
  map<string, string> response_headers;
  uint64_t range_first, range_last, range_len;
  uint response_code;
  const char* response_string;
  map<string, string>::const_iterator header_it;
  string file_name;
  int file_fd = -1;
  char ea_value[64] = {0};
  bool send_file_result;
  ssize_t ea_size;
  // Initialize the result in an invalid RequestResult.
  P2PServerRequestResult req_res = p2p::util::kNumP2PServerRequestResults;
  int range_begin_percentage = 0;

  // Log User-Agent, if available
  header_it = headers.find("user-agent");
  if (header_it != headers.end()) {
    LOG(INFO) << pretty_addr_ << " - user agent: " << header_it->second;
  }

  if (!(method == "GET" || method == "POST")) {
    SendSimpleResponse(501, "Method Not Implemented");
    // A peer should never request something different than GET or POST. Report
    // this as a malformed request.
    req_res = p2p::util::kP2PRequestResultMalformed;
    goto out;
  }

  // Ensure the URI contains exactly one '/'
  if (uri[0] != '/' || uri.find('/', 1) != string::npos) {
    SendSimpleResponse(400, "Bad Request");
    req_res = p2p::util::kP2PRequestResultMalformed;
    goto out;
  }

  LOG(INFO) << pretty_addr_ << " - requesting resource with URI " << uri;

  // Handle /index.html
  if (uri == "/" || uri == "/index.html") {
    SendSimpleResponse(404, "No index");
    req_res = p2p::util::kP2PRequestResultIndex;
    goto out;
  }

  file_name = uri.substr(1) + ".p2p";
  VLOG(1) << "Opening `" << file_name << "'";
  file_fd = openat(dirfd_, file_name.c_str(), O_RDONLY);
  if (file_fd == -1) {
    SendSimpleResponse(404, string("Error opening file: ") + strerror(errno));
    req_res = p2p::util::kP2PRequestResultNotFound;
    goto out;
  }

  if (fstat(file_fd, &statbuf) != 0) {
    SendSimpleResponse(404, "Error getting information about file");
    req_res = p2p::util::kP2PRequestResultNotFound;
    goto out;
  }
  file_size = statbuf.st_size;
  VLOG(1) << "File is " << file_size << " bytes";
  LOG(INFO) << "File is " << file_size << " bytes";

  ea_size =
      fgetxattr(file_fd, "user.cros-p2p-filesize", &ea_value, sizeof ea_value);
  if (ea_size > 0 && ea_value[0] != 0) {
    int64_t val;
    if (base::StringToInt64(ea_value, &val)) {
      VLOG(1) << "Read user.cros-p2p-filesize=" << val;
      if (static_cast<size_t>(val) > file_size) {
        // Simply update file_size to what the EA says - code below
        // handles that by checking for EOF and sleeping
        file_size = val;
      }
    }
  }

  if (file_size == 0) {
    range_first = 0;
    range_last = 0;
    range_len = 0;
    response_code = 200;
    response_string = "OK";
  } else {
    header_it = headers.find("range");
    if (header_it != headers.end()) {
      if (!ParseRange(header_it->second, file_size, &range_first,
                      &range_last)) {
        SendSimpleResponse(400, "Error parsing Range header");
        req_res = p2p::util::kP2PRequestResultMalformed;
        goto out;
      }
      if (range_last >= file_size) {
        SendSimpleResponse(416, "Requested Range Not Satisfiable");
        req_res = p2p::util::kP2PRequestResultMalformed;
        goto out;
      }
      response_code = 206;
      response_string = "Partial Content";
      response_headers["Content-Range"] = std::to_string(range_first) + "-" +
                                          std::to_string(range_last) + "/" +
                                          std::to_string(file_size);
    } else {
      range_first = 0;
      range_last = file_size - 1;
      response_code = 200;
      response_string = "OK";
    }
    CHECK(range_first <= range_last);
    CHECK(range_last < file_size);
    range_len = range_last - range_first + 1;
  }

  response_headers["Content-Type"] = "application/octet-stream";
  response_headers["Content-Length"] = std::to_string(range_len);
  if (!SendResponse(response_code, response_string, response_headers, "")) {
    req_res = p2p::util::kP2PRequestResultResponseInterrupted;
    goto out;
  }

  if (range_first > 0) {
    if (lseek(file_fd, static_cast<off_t>(range_first), SEEK_SET) !=
        static_cast<off_t>(range_first)) {
      PLOG(ERROR) << "Error seeking";
      req_res = p2p::util::kP2PRequestResultNotFound;
      goto out;
    }
  }

  // From now on, we don't report a result as Malformed. Report the
  // P2P.Server.RangeBeginPercentage at the begining of the file serving period,
  // since it is being reported either the transmission is interrupted or nor.
  if (file_size > 0)
    range_begin_percentage = 100.0 * range_first / file_size;
  server_->ReportServerMessage(p2p::util::kP2PServerRangeBeginPercentage,
                               range_begin_percentage);

  // Send the file and report the metrics associated with the transfer.
  send_file_result = SendFile(file_fd, range_len);
  ReportSendFileMetrics(send_file_result);

  req_res = send_file_result ? p2p::util::kP2PRequestResultResponseSent
                             : p2p::util::kP2PRequestResultResponseInterrupted;

out:
  if (file_fd != -1)
    close(file_fd);
  return req_res;
}

bool ConnectionDelegate::IsStillConnected() {
  char buf[1];
  ssize_t num_recv;

  // Sockets become readable when closed by the peer, which can be
  // used to figure out if the other end is still connected
  num_recv = recv(fd_, buf, 0, MSG_DONTWAIT | MSG_PEEK);
  if (num_recv == -1)
    return true;
  return false;
}

}  // namespace http_server

}  // namespace p2p
