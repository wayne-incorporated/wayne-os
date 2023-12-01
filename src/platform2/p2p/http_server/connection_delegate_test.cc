// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/http_server/connection_delegate.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <string>
#include <vector>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/threading/simple_thread.h>
#include <gtest/gtest.h>

#include "p2p/common/constants.h"
#include "p2p/common/fake_clock.h"
#include "p2p/common/testutil.h"
#include "p2p/common/util.h"
#include "p2p/http_server/mock_server.h"

using std::map;
using std::string;
using std::tuple;
using std::vector;

using base::FilePath;
using base::WriteFile;

using p2p::common::FakeClock;
using p2p::testutil::SetExpectedFileSize;
using p2p::testutil::SetupTestDir;
using p2p::testutil::TeardownTestDir;

using testing::_;

namespace {
// DefaultDownloadRate used for the tests in bytes per seconds (5MB/s).
static const int kDefaultDownloadRate = 5 * 1000 * 1000;
}  // namespace

namespace p2p {

namespace http_server {

class ConnectionDelegateTest : public ::testing::Test {
 public:
  ConnectionDelegateTest()
      : testdir_fd_(-1),
        server_fd_(-1),
        client_fd_(-1),
        thread_(NULL),
        delegate_(NULL) {
    ON_CALL(mock_server_, Clock()).WillByDefault(testing::Return(&clock_));
    EXPECT_CALL(mock_server_, Clock()).Times(testing::AtLeast(0));
  }

 protected:
  void SetupDelegate() {
    testdir_path_ = SetupTestDir("connection-delegate");
    testdir_fd_ = open(testdir_path_.value().c_str(), O_DIRECTORY);
    if (testdir_fd_ == -1)
      PLOG(ERROR) << "Opening delegate-test temp directory";
    ASSERT_NE(testdir_fd_, -1);

    // Create a TCP server in any port and connect to it. This provides the
    // very same kind of socket ConnectionDelegate will use in the real
    // implementation.
    int servsock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                          IPPROTO_TCP);
    if (servsock == -1)
      PLOG(ERROR) << "Creating a server socket()";
    ASSERT_NE(servsock, -1);

    client_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (client_fd_ == -1)
      PLOG(ERROR) << "Creating a client socket()";
    ASSERT_NE(client_fd_, -1);

    // Set the socket to listen to a random port.
    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    memset(reinterpret_cast<char*>(&server_addr), 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(0);  // any port
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ASSERT_NE(-1,
              bind(servsock, reinterpret_cast<struct sockaddr*>(&server_addr),
                   sizeof(server_addr)));
    // Read back the selected address and port.
    ASSERT_NE(-1, getsockname(servsock,
                              reinterpret_cast<struct sockaddr*>(&server_addr),
                              &server_len));

    ASSERT_NE(listen(servsock, 1), -1);

    // At this point, the server socked will accept the connection and we will
    // get the server side socket once we call accept().
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    ASSERT_NE(-1, connect(client_fd_,
                          reinterpret_cast<struct sockaddr*>(&server_addr),
                          sizeof(server_addr)));

    for (int i = 0; i < 3; ++i) {
      server_fd_ =
          accept(servsock, reinterpret_cast<struct sockaddr*>(&client_addr),
                 &client_len);
      if (server_fd_ == -1 && errno == EAGAIN) {
        sleep(1);
        continue;
      }
      break;
    }
    if (server_fd_ == -1)
      PLOG(ERROR) << "Accepting the client connection.";
    ASSERT_NE(server_fd_, -1);

    // Tear down the listening server (but keep the server_fd_ socket).
    ASSERT_EQ(close(servsock), 0);

    // Create the Server
    delegate_ = new ConnectionDelegate(testdir_fd_, server_fd_, "[addr]",
                                       &mock_server_, kDefaultDownloadRate);

    thread_ = new base::DelegateSimpleThread(delegate_, "delegate");
  }

  void TearDown() override {
    if (thread_)
      delete thread_;
    // The ConnectionDelegate deletes itself when Run() finishes.

    if (client_fd_ != -1)
      EXPECT_EQ(0, close(client_fd_));
    // The ConnectionDelegate should close the provided file descriptor, thus
    // this close should fail.
    if (server_fd_ != -1)
      EXPECT_EQ(-1, close(server_fd_));
    if (testdir_fd_ != -1)
      EXPECT_EQ(0, close(testdir_fd_));
    if (!testdir_path_.empty())
      TeardownTestDir(testdir_path_);
  }

  // A randomly generated temporary testing directory to put the shared files.
  FilePath testdir_path_;

  // File descriptor to the testdir_path_ directory.
  int testdir_fd_;

  // The server-side fd in the connection (passed to ConnectionDelegate).
  int server_fd_;

  // The client-side fd that a client is using to request the content from the
  // ConnectionDelegate.
  int client_fd_;

  // Thread pool needed to run the ConnectionDelegate.
  base::DelegateSimpleThread* thread_;

  testing::StrictMock<MockServer> mock_server_;
  ConnectionDelegate* delegate_;
  FakeClock clock_;
};

// A class to help building a HTTP Request.
class HTTPRequest {
 public:
  HTTPRequest()
      : method_("GET"), http_version_("1.1"), uri_("/"), host_("127.0.0.1") {
    headers_["User-Agent"] = "HTTPRequest/1.0 (unittester)";
  }

  string ToString() const {
    string res = method_ + " " + uri_ + " HTTP/" + http_version_ + "\r\n" +
                 "Host: " + host_ + "\r\n";
    for (const auto& it : headers_)
      res += it.first + ": " + it.second + "\r\n";
    res += "\r\n" + post_data_;
    return res;
  }

  bool Send(int fd) const {
    string req = ToString();
    size_t to_write = req.size();
    const char* p = req.c_str();
    int write_result;
    while (to_write > 0) {
      write_result = write(fd, p, to_write);
      if (write_result < 0 && errno == EAGAIN)
        continue;
      if (write_result <= 0) {
        PLOG(ERROR) << "Error writing to fd " << fd;
        return false;
      }
      to_write -= write_result;
      p += write_result;
    }
    return true;
  }

  string method_;
  string http_version_;  // The HTTP protocol version.
  string uri_;
  string host_;
  map<string, string> headers_;
  string post_data_;
};

class HTTPResponse {
 public:
  explicit HTTPResponse(const string& response)
      : response_(response), valid_(false) {
    const char* p = response_.c_str();
    int len = response_.size();
    if (len == 0)
      return;

    // Parse the header lines until the empty line is reached.
    const char* line = p;
    int line_len = len;
    while (line_len > 0) {
      int i;
      for (i = 0; i < line_len; ++i) {
        if (line[i] == '\n') {
          if (i > 0 && line[i - 1] == '\r') {
            // Found \r\n ending line.
            line_len = i + 1;
            break;
          }
          LOG(ERROR) << "Header line doesn't end in \\r\\n.";
          return;
        }
      }
      // Check if the end of the response was reached while parsing the headers.
      if (i == line_len)
        return;

      raw_headers_.push_back(string(line, line_len - 2));
      line += line_len;
      line_len = len - (line - p);
      // Check if the empty header line was found.
      if (line_len >= 2 && line[0] == '\r' && line[1] == '\n')
        break;
    }
    // Check if the header is \r\n
    if (!line_len) {
      LOG(ERROR) << "Missing \\r\\n after the headers.";
      return;
    }

    line += 2;
    if (line < p + len)
      content_ = string(line, len - (line - p));

    // Parse the first response line.
    string first_line = raw_headers_[0];
    if (first_line.substr(0, 5) == "HTTP/") {
      size_t sp_pos = first_line.find(' ');
      if (sp_pos != std::string::npos) {
        http_version_ = first_line.substr(5, sp_pos - 5);
        first_line = first_line.substr(sp_pos + 1);
      }
    }
    http_code_ = atoi(first_line.c_str());

    // Parse the raw_headers.
    for (size_t i = 1; i < raw_headers_.size(); ++i) {
      const string& header = raw_headers_[i];
      const char* header_p = header.c_str();
      const char* sep =
          reinterpret_cast<const char*>(memchr(header_p, ':', header.size()));
      if (!sep || sep[1] != ' ') {
        LOG(ERROR) << "Invalid header: \"" << header << "\".";
        return;
      }
      string key(header_p, sep - header_p);
      string value(sep + 2, header.size() - (sep + 2 - header_p));

      if (headers_.find(key) != headers_.end()) {
        LOG(ERROR) << "The header \"" << key << "\" appears twice in the "
                   << "response.";
        return;
      }
      // TODO(deymo): Support header continuation. See http://crbug.com/246326.
      headers_[key] = value;
    }
    valid_ = true;
  }

  // The original response string.
  string response_;

  // Tells wether the response has a valid (and supported) format.
  bool valid_;

  // The HTTP response code.
  int http_code_;

  string http_version_;

  map<string, string> headers_;

  // The content body.
  string content_;

 private:
  vector<string> raw_headers_;
};

// Read or continue reading a HTTP response from the file descriptor until the
// connection is closed or the "content" part of the HTTP response is at least
// |min_content_size|. If more than |min_content_size| bytes are available to
// read on the file descriptor those will be included in the |response| as well.
// A value of -1 in |min_content_size| will block until the connection is
// closed.
// Returns wether the response was successfully read from the file descriptor
// and the socked was properly close from the other end or the
// |min_content_size| reached.
// The bytes read from the file descriptor are appended to the |response|
// string, allowing the caller to do a partial read of a HTTP response and then
// continue it. For example:
//
//   string resp;
//   // This will at least read the headers:
//   ReadHTTPResponse(some_sock, &resp, 0);
//   // ... do some checking of the headers, read the Content-Length if present.
//   ReadHTTPResponse(some_sock, &resp, expect_content_size);
static bool ReadHTTPResponse(int fd,
                             string* response,
                             int min_content_size = -1) {
  char buf[16 * 1024];  // 16KiB is a reasonable buffer for recv().
  int res;
  do {
    if (min_content_size >= 0) {
      res = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
      if (res == -1 && errno == EWOULDBLOCK) {
        HTTPResponse ret(*response);
        if (ret.valid_ &&
            ret.content_.size() >= static_cast<size_t>(min_content_size))
          return true;
        // Re-read but block this time.
        res = recv(fd, buf, sizeof(buf), 0);
      }
    } else {
      res = recv(fd, buf, sizeof(buf), 0);
    }
    if (res == -1 && errno == EAGAIN)
      continue;
    if (res == -1) {
      PLOG(ERROR) << "Reading HTTPResponse from fd " << fd;
      return false;
    }
    if (res == 0)
      break;
    response->append(buf, res);
  } while (true);
  return true;
}

// Generates undefined but deterministic printable data.
// Printable data is considered all the ASCII-7 char excluding the first 32
// codes (control characters) and the 128. Thus, this function generates
// ASCII chars in the range 32-127 inclusive.
static void GeneratePrintableData(size_t size, string* output) {
  output->clear();
  output->resize(size);
  for (size_t i = 0; i < size; ++i)
    output->at(i) = static_cast<char>(32 + (45 + i * 131 + i * i * 17) % 95);
}

TEST_F(ConnectionDelegateTest, NoRequestAndClose) {
  SetupDelegate();

  p2p::testutil::TimeBombAbort bomb(60, "Test NoRequestAndClose timeout\n");
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultMalformed));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  EXPECT_EQ(0, close(client_fd_));
  client_fd_ = -1;
  thread_->Join();
}

TEST_F(ConnectionDelegateTest, RequestUnsupportedMode) {
  SetupDelegate();

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultMalformed));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  // Send a HEAD request.
  HTTPRequest req;
  req.method_ = "HEAD";
  req.uri_ = "/non-existent";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  EXPECT_EQ(501, resp.http_code_);  // Not Implemented.
}

TEST_F(ConnectionDelegateTest, GetExistentFile) {
  SetupDelegate();

  const string content = "Hello World!";
  WriteFile(testdir_path_.Append("hello.p2p"), content.c_str(), content.size());

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultResponseSent));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerServedSuccessfullyMB, 0));
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerDownloadSpeedKBps, _));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 0));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/hello";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  EXPECT_EQ(200, resp.http_code_);
  EXPECT_EQ(content, resp.content_);
  EXPECT_EQ("application/octet-stream", resp.headers_["Content-Type"]);
  EXPECT_EQ(base::NumberToString(content.size()),
            resp.headers_["Content-Length"]);
}

TEST_F(ConnectionDelegateTest, PostExistentFile) {
  SetupDelegate();

  string content;
  GeneratePrintableData(9 * 1000 * 1000 - 1, &content);
  WriteFile(testdir_path_.Append("a.foo.p2p"), content.c_str(), content.size());

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultResponseSent));
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerServedSuccessfullyMB,
                                  8));  // Almost 9 MB served.
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerDownloadSpeedKBps, _));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 0));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.method_ = "POST";
  req.uri_ = "/a.foo";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  ASSERT_EQ(200, resp.http_code_);
  EXPECT_EQ(content, resp.content_);
  EXPECT_EQ("application/octet-stream", resp.headers_["Content-Type"]);
  EXPECT_EQ(base::NumberToString(content.size()),
            resp.headers_["Content-Length"]);
}

TEST_F(ConnectionDelegateTest, GetEmptyFile) {
  SetupDelegate();

  WriteFile(testdir_path_.Append("empty.p2p"), "", 0);

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultResponseSent));
  // The reported download speed should be 0 in this case, and no
  // kP2PServerServedSuccessfullyMB is reported.
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerDownloadSpeedKBps, 0));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 0));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/empty";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  EXPECT_EQ(200, resp.http_code_);
  EXPECT_EQ("", resp.content_);
  EXPECT_EQ("application/octet-stream", resp.headers_["Content-Type"]);
  EXPECT_EQ("0", resp.headers_["Content-Length"]);
}

TEST_F(ConnectionDelegateTest, GetRangeOfFile) {
  SetupDelegate();

  string content;
  GeneratePrintableData(60 * 1000, &content);
  WriteFile(testdir_path_.Append("data.p2p"), content.c_str(), content.size());

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultResponseSent));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerServedSuccessfullyMB, 0));
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerDownloadSpeedKBps, _));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 25));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/data";
  req.headers_["User-Agent"] = "The Unit Tester";
  req.headers_["Range"] = "bytes=15000-17000";
  // An extra header shouldn't affect.
  req.headers_["X-Hello"] = "World";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  ASSERT_EQ(206, resp.http_code_);  // Partial content.
  EXPECT_EQ("application/octet-stream", resp.headers_["Content-Type"]);
  EXPECT_EQ("2001", resp.headers_["Content-Length"]);
  EXPECT_EQ(content.substr(15000, 2001), resp.content_);
}

TEST_F(ConnectionDelegateTest, GetInvalidRangeOfFile) {
  SetupDelegate();

  string content;
  GeneratePrintableData(64 * 1000, &content);
  WriteFile(testdir_path_.Append("data.p2p"), content.c_str(), content.size());

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultMalformed));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/data";
  // The range starts in the file but the end is after the end of the file.
  req.headers_["Range"] = "bytes=60000-70000";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  EXPECT_EQ(416, resp.http_code_);  // Requested Range Not Satisfiable.
  EXPECT_EQ("", resp.content_);
}

TEST_F(ConnectionDelegateTest, GetLastPartOfFile) {
  SetupDelegate();

  string content;
  GeneratePrintableData(5 * 1000, &content);
  WriteFile(testdir_path_.Append("data.p2p"), content.c_str(), content.size());

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultResponseSent));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerServedSuccessfullyMB, 0));
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerDownloadSpeedKBps, _));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 80));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/data";
  // HTTP headers aren't case sensitive and we should send only one. This tests
  // the parser behaviour.
  req.headers_["User-Agent"] = "The Unit Tester I";
  req.headers_["user-agent"] = "The Unit Tester II";
  req.headers_["UsEr-AgEnT"] = "The Unit Tester III";
  req.headers_["raNGE"] = "bytes=4000-";
  req.headers_["RangE"] = "bytes=4000-";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  ASSERT_EQ(206, resp.http_code_);  // Partial content.
  EXPECT_EQ("application/octet-stream", resp.headers_["Content-Type"]);
  EXPECT_EQ("1000", resp.headers_["Content-Length"]);
  EXPECT_EQ(content.substr(4000, 1000), resp.content_);
}

TEST_F(ConnectionDelegateTest, GetIncompleteFile) {
  if (!util::IsXAttrSupported(FilePath("/tmp"))) {
    LOG(WARNING) << "Skipping test because /tmp does not support xattr. "
                 << "Please update your system to support this feature.";
    return;
  }

  SetupDelegate();

  string content;
  GeneratePrintableData(50 * 1000, &content);
  WriteFile(testdir_path_.Append("data.p2p"), content.c_str(), content.size());
  ASSERT_TRUE(
      SetExpectedFileSize(testdir_path_.Append("data.p2p"), 100 * 1000));

  EXPECT_CALL(
      mock_server_,
      ReportServerMessage(p2p::util::kP2PServerRequestResult,
                          p2p::util::kP2PRequestResultResponseInterrupted));
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerServedInterruptedMB, 0));
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerDownloadSpeedKBps, _));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 0));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/data";
  req.Send(client_fd_);
  // Request the whole file (100KB), but try to read only the first 50KB.
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp, 50 * 1000));
  // Disconnect.
  close(client_fd_);
  client_fd_ = -1;
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  ASSERT_EQ(200, resp.http_code_);
  EXPECT_EQ("application/octet-stream", resp.headers_["Content-Type"]);
  EXPECT_EQ("100000", resp.headers_["Content-Length"]);
  EXPECT_EQ(content, resp.content_);
}

TEST_F(ConnectionDelegateTest, GetPartOfIncompleteFile) {
  if (!util::IsXAttrSupported(FilePath("/tmp"))) {
    LOG(WARNING) << "Skipping test because /tmp does not support xattr. "
                 << "Please update your system to support this feature.";
    return;
  }

  SetupDelegate();

  string content;
  GeneratePrintableData(5 * 1000, &content);
  WriteFile(testdir_path_.Append("data.p2p"), content.c_str(), content.size());
  ASSERT_TRUE(SetExpectedFileSize(testdir_path_.Append("data.p2p"), 10 * 1000));

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultResponseSent));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerServedSuccessfullyMB, 0));
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerDownloadSpeedKBps, _));
  // Total file size is 10KB, but actual file size is 5KB. A range starting
  // at 2KB should be reported as 20%.
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 20));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/data";
  req.headers_["Range"] = "bytes=2000-4999";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  // Disconnect.
  close(client_fd_);
  client_fd_ = -1;
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  ASSERT_EQ(206, resp.http_code_);
  EXPECT_EQ("application/octet-stream", resp.headers_["Content-Type"]);
  EXPECT_EQ("3000", resp.headers_["Content-Length"]);
  EXPECT_EQ(content.substr(2000, 3000), resp.content_);
}

TEST_F(ConnectionDelegateTest, GetNonExistentFile) {
  SetupDelegate();

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultNotFound));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/hello";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  EXPECT_EQ(404, resp.http_code_);
}

TEST_F(ConnectionDelegateTest, URIArgumentsNotParsed) {
  SetupDelegate();

  const string content = "Hello World!";
  WriteFile(testdir_path_.Append("hello.p2p"), content.c_str(), content.size());

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultNotFound));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/hello?world";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  EXPECT_EQ(404, resp.http_code_);
}

TEST_F(ConnectionDelegateTest, URIUsesRelativePath) {
  SetupDelegate();

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultMalformed));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "//etc/passwd";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  EXPECT_EQ(400, resp.http_code_);  // Bad request.
}

TEST_F(ConnectionDelegateTest, MalformedInversedRange) {
  SetupDelegate();

  const string content = "Hello World!";
  WriteFile(testdir_path_.Append("hello.p2p"), content.c_str(), content.size());

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultMalformed));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/hello";
  // Request an inverted range.
  req.headers_["Range"] = "bytes=9-5";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  EXPECT_EQ(400, resp.http_code_);  // Bad request.
}

// Tests that the ConnectionDelegate properly blocks when the end of the file
// is missing and continues serving the file when more data is available.
TEST_F(ConnectionDelegateTest, Waiting) {
  if (!util::IsXAttrSupported(FilePath("/tmp"))) {
    LOG(WARNING) << "Skipping test because /tmp does not support xattr. "
                 << "Please update your system to support this feature.";
    return;
  }

  SetupDelegate();

  // The file starts with 50kB on disk, but expected total size of 100kB. The
  // file is then extended to 75kB and finally to 100kB.
  string content;
  GeneratePrintableData(100 * 1000, &content);
  WriteFile(testdir_path_.Append("wait.p2p"), content.c_str(), 50 * 1000);
  ASSERT_TRUE(
      SetExpectedFileSize(testdir_path_.Append("wait.p2p"), 100 * 1000));

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultResponseSent));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerServedSuccessfullyMB, 0));
  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerDownloadSpeedKBps, _));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 0));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/wait";
  req.Send(client_fd_);
  string text_resp;
  // Expect to read the first 50kB with a valid HTTP response for the
  // total size of 100kB.
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp, 50 * 1000));

  HTTPResponse resp(text_resp);
  ASSERT_TRUE(resp.valid_);
  ASSERT_EQ(200, resp.http_code_);
  EXPECT_EQ("application/octet-stream", resp.headers_["Content-Type"]);
  EXPECT_EQ("100000", resp.headers_["Content-Length"]);

  // Extend the file to 75kB.
  int fd = open(testdir_path_.Append("wait.p2p").value().c_str(),
                O_WRONLY | O_APPEND);
  EXPECT_NE(fd, -1);
  EXPECT_EQ(25 * 1000, write(fd, content.c_str() + 50 * 1000, 25 * 1000));

  // Expect to reach 75kB on the reader side.
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp, 75 * 1000));

  HTTPResponse middle_resp(text_resp);
  ASSERT_TRUE(middle_resp.valid_);
  EXPECT_EQ(middle_resp.content_.size(), 75 * 1000);

  // Extend the file to its total expected size and expect the server to close
  // the connection right after serving the total size.
  EXPECT_EQ(25 * 1000, write(fd, content.c_str() + 75 * 1000, 25 * 1000));
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));

  EXPECT_EQ(0, close(fd));
  thread_->Join();

  HTTPResponse full_resp(text_resp);
  ASSERT_TRUE(full_resp.valid_);
  EXPECT_EQ(full_resp.content_.size(), 100 * 1000);
  EXPECT_EQ(full_resp.content_, content);
}

TEST_F(ConnectionDelegateTest, LimitDownloadSpeed) {
  if (!util::IsXAttrSupported(FilePath("/tmp"))) {
    LOG(WARNING) << "Skipping test because /tmp does not support xattr. "
                 << "Please update your system to support this feature.";
    return;
  }

  SetupDelegate();

  string content;
  GeneratePrintableData(50 * 1000 * 1000, &content);
  WriteFile(testdir_path_.Append("50mb.p2p"), content.c_str(), content.size());
  ASSERT_TRUE(
      SetExpectedFileSize(testdir_path_.Append("50mb.p2p"), content.size()));

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultResponseSent));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerServedSuccessfullyMB, 50));
  // The reported download speed should be the maximum default speed used in
  // this test (kDefaultDownloadRate).
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerDownloadSpeedKBps, 5000));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 0));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/50mb";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));
  thread_->Join();

  // Don't need to parse the response. Just expect it to have the 50MB plus the
  // header size.
  EXPECT_GE(text_resp.size(), 50 * 1000 * 1000);

  // Since the file was already complete at the begining of the test, the
  // sleeping time should be only 10s (50MB / 5 MB/s). A minimum tolerance is
  // added to avoid floating-point errors.
  EXPECT_GE(clock_.GetSleptTime().InSecondsF(), 9.999);
  EXPECT_LE(clock_.GetSleptTime().InSecondsF(), 10.001);
}

TEST_F(ConnectionDelegateTest, DisregardTimeWaitingFromTransferBudget) {
  if (!util::IsXAttrSupported(FilePath("/tmp"))) {
    LOG(WARNING) << "Skipping test because /tmp does not support xattr. "
                 << "Please update your system to support this feature.";
    return;
  }

  SetupDelegate();

  string content;
  GeneratePrintableData(25 * 1000 * 1000, &content);
  WriteFile(testdir_path_.Append("50mb.p2p"), content.c_str(), content.size());
  ASSERT_TRUE(
      SetExpectedFileSize(testdir_path_.Append("50mb.p2p"), 50 * 1000 * 1000));

  EXPECT_CALL(mock_server_,
              ReportServerMessage(p2p::util::kP2PServerRequestResult,
                                  p2p::util::kP2PRequestResultResponseSent));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerServedSuccessfullyMB, 50));
  // The reported download speed should be the maximum default speed used in
  // this test (kDefaultDownloadRate).
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerDownloadSpeedKBps, 5000));
  EXPECT_CALL(mock_server_, ReportServerMessage(
                                p2p::util::kP2PServerRangeBeginPercentage, 0));
  EXPECT_CALL(mock_server_, ConnectionTerminated(delegate_));

  thread_->Start();
  HTTPRequest req;
  req.uri_ = "/50mb";
  req.Send(client_fd_);
  string text_resp;
  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp, 25 * 1000 * 1000));

  // At this point, the ConnectionDelegate is waiting on data to be read from
  // the file, but EOF is reached so it will try to call clock->Sleep() to
  // sleep for a second waiting for data to be ready. After the last byte is
  // sent to the socket, the ConnectionDelegate waits to reach the right
  // speed and once EOF on the input is reached it will wait again until some
  // data is ready to read from there. To ensure we saw at least one Sleep()
  // call because of the later condition, block twice until Sleep() is called.
  clock_.BlockUntilSleepIsCalled();
  clock_.BlockUntilSleepIsCalled();

  // Extend the file to its total expected size and expect the server to close
  // the connection right after serving the total size.
  int fd = open(testdir_path_.Append("50mb.p2p").value().c_str(),
                O_WRONLY | O_APPEND);
  EXPECT_NE(fd, -1);
  EXPECT_EQ(content.size(), write(fd, content.c_str(), content.size()));
  EXPECT_EQ(0, close(fd));

  EXPECT_TRUE(ReadHTTPResponse(client_fd_, &text_resp));

  thread_->Join();

  // Don't need to parse the response. Just expect it to have the 50MB plus the
  // header size.
  EXPECT_GE(text_resp.size(), 50 * 1000 * 1000);
}

}  // namespace http_server

}  // namespace p2p
