// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/container/appfuse/data_filter.h"

#include <linux/fuse.h>
#include <sys/socket.h>

#include <base/functional/bind.h>
#include <base/posix/eintr_wrapper.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

namespace arc {
namespace appfuse {

class DataFilterTest : public testing::Test {
 public:
  DataFilterTest() = default;
  DataFilterTest(const DataFilterTest&) = delete;
  DataFilterTest& operator=(const DataFilterTest&) = delete;

  ~DataFilterTest() override = default;

  void SetUp() override {
    data_filter_.set_on_stopped_callback(
        base::BindOnce(&DataFilterTest::OnStopped, base::Unretained(this)));
    int raw_socks[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, raw_socks));
    fd_dev_ = base::ScopedFD(raw_socks[0]);
    fd_app_ = data_filter_.Start(base::ScopedFD(raw_socks[1]));
    ASSERT_TRUE(fd_app_.is_valid());
  }

  void TearDown() override {
    if (stop_expected_) {
      run_loop_.Run();
      EXPECT_TRUE(was_stopped_);
    }
  }

  // Reads filtered data which /dev/fuse sent to app.
  bool ReadInData(fuse_in_header* header, void* body, size_t body_size) {
    std::vector<char> buf(sizeof(*header) + body_size);
    if (HANDLE_EINTR(read(fd_app_.get(), buf.data(), buf.size())) != buf.size())
      return false;
    memcpy(header, buf.data(), sizeof(*header));
    memcpy(body, buf.data() + sizeof(*header), body_size);
    return true;
  }

  // Reads filtered data which app sent to /dev/fuse.
  bool ReadOutData(fuse_out_header* header, void* body, size_t body_size) {
    std::vector<char> buf(sizeof(*header) + body_size);
    if (HANDLE_EINTR(read(fd_dev_.get(), buf.data(), buf.size())) != buf.size())
      return false;
    memcpy(header, buf.data(), sizeof(*header));
    memcpy(body, buf.data() + sizeof(*header), body_size);
    return true;
  }

  // Writes data to the filter which will be sent to app.
  bool WriteInData(const fuse_in_header& header,
                   const void* body,
                   size_t body_size) {
    std::vector<char> buf(sizeof(header) + body_size);
    memcpy(buf.data(), &header, sizeof(header));
    memcpy(buf.data() + sizeof(header), body, body_size);
    return HANDLE_EINTR(write(fd_dev_.get(), buf.data(), buf.size())) ==
           buf.size();
  }

  // Writes data to the filter which will be sent to /dev/fuse.
  bool WriteOutData(const fuse_out_header& header,
                    const void* body,
                    size_t body_size) {
    std::vector<char> buf(sizeof(header) + body_size);
    memcpy(buf.data(), &header, sizeof(header));
    memcpy(buf.data() + sizeof(header), body, body_size);
    return HANDLE_EINTR(write(fd_app_.get(), buf.data(), buf.size())) ==
           buf.size();
  }

  void ExpectStop() { stop_expected_ = true; }

 private:
  void OnStopped() {
    EXPECT_FALSE(was_stopped_);
    was_stopped_ = true;
    run_loop_.Quit();
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  base::RunLoop run_loop_;
  DataFilter data_filter_;
  base::ScopedFD fd_app_;  // App-side FD connected to the filter.
  base::ScopedFD fd_dev_;  // /dev/fuse-side FD connected to the filter.
  bool was_stopped_ = false;
  bool stop_expected_ = false;
};

TEST_F(DataFilterTest, ValidRequestAndResponse) {
  constexpr int kUnique = 123;
  constexpr mode_t kMode = S_IFREG | 0777;
  {  // GETATTR request from /dev/fuse to DataFitler.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    header.len = sizeof(header) + sizeof(body);
    header.opcode = FUSE_GETATTR;
    header.unique = kUnique;
    ASSERT_TRUE(WriteInData(header, &body, sizeof(body)));
  }
  {  // DataFilter passes GETATTR to the app.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    ASSERT_TRUE(ReadInData(&header, &body, sizeof(body)));
    EXPECT_EQ(FUSE_GETATTR, header.opcode);
    EXPECT_EQ(kUnique, header.unique);
  }
  {  // GETATTR response from app to DataFilter.
    fuse_out_header header = {};
    fuse_attr_out body = {};
    header.len = sizeof(header) + sizeof(body);
    header.unique = kUnique;
    body.attr.mode = kMode;
    ASSERT_TRUE(WriteOutData(header, &body, sizeof(body)));
  }
  {  // DataFilter passes the response to /dev/fuse.
    fuse_out_header header = {};
    fuse_attr_out body = {};
    ASSERT_TRUE(ReadOutData(&header, &body, sizeof(body)));
    EXPECT_EQ(kUnique, header.unique);
    EXPECT_EQ(kMode, body.attr.mode);
  }
}

TEST_F(DataFilterTest, ValidRequestAndErrorResponse) {
  constexpr int kUnique = 123;
  {  // GETATTR request from /dev/fuse to DataFitler.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    header.len = sizeof(header) + sizeof(body);
    header.opcode = FUSE_GETATTR;
    header.unique = kUnique;
    ASSERT_TRUE(WriteInData(header, &body, sizeof(body)));
  }
  {  // DataFilter passes GETATTR to the app.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    ASSERT_TRUE(ReadInData(&header, &body, sizeof(body)));
    EXPECT_EQ(FUSE_GETATTR, header.opcode);
    EXPECT_EQ(kUnique, header.unique);
  }
  {  // ENOENT response from app to DataFilter.
    fuse_out_header header = {};
    header.len = sizeof(header);
    header.unique = kUnique;
    header.error = -ENOENT;
    ASSERT_TRUE(WriteOutData(header, nullptr, 0));
  }
  {  // DataFilter passes the response to /dev/fuse.
    fuse_out_header header = {};
    ASSERT_TRUE(ReadOutData(&header, nullptr, 0));
    EXPECT_EQ(kUnique, header.unique);
    EXPECT_EQ(-ENOENT, header.error);
  }
}

TEST_F(DataFilterTest, InvalidFileMode) {
  constexpr int kUnique = 123;
  constexpr mode_t kMode = S_IFBLK | 0777;  // S_IFBLK is not allowed.
  ExpectStop();
  {  // GETATTR request from /dev/fuse to DataFitler.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    header.len = sizeof(header) + sizeof(body);
    header.opcode = FUSE_GETATTR;
    header.unique = kUnique;
    ASSERT_TRUE(WriteInData(header, &body, sizeof(body)));
  }
  {  // DataFilter passes GETATTR to the app.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    ASSERT_TRUE(ReadInData(&header, &body, sizeof(body)));
    EXPECT_EQ(FUSE_GETATTR, header.opcode);
    EXPECT_EQ(kUnique, header.unique);
  }
  {  // GETATTR response from app to DataFilter.
    fuse_out_header header = {};
    fuse_attr_out body = {};
    header.len = sizeof(header) + sizeof(body);
    header.unique = kUnique;
    body.attr.mode = kMode;
    ASSERT_TRUE(WriteOutData(header, &body, sizeof(body)));
  }
  {  // DataFilter rejects response because of the invalid mode value.
    fuse_out_header header = {};
    fuse_attr_out body = {};
    EXPECT_FALSE(ReadOutData(&header, &body, sizeof(body)));
  }
}

TEST_F(DataFilterTest, InvalidInHeader) {
  constexpr int kUnique = 123;
  ExpectStop();
  {  // GETATTR request from /dev/fuse to DataFitler.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    header.len = sizeof(header) - 1;  // Invalid len.
    header.opcode = FUSE_GETATTR;
    header.unique = kUnique;
    ASSERT_TRUE(WriteInData(header, &body, sizeof(body)));
  }
  {  // DataFilter rejects it because the header is invalid.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    ASSERT_FALSE(ReadInData(&header, &body, sizeof(body)));
  }
}

TEST_F(DataFilterTest, InvalidOutHeader) {
  constexpr int kUnique = 123;
  constexpr mode_t kMode = S_IFREG | 0777;
  ExpectStop();
  {  // GETATTR request from /dev/fuse to DataFitler.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    header.len = sizeof(header) + sizeof(body);
    header.opcode = FUSE_GETATTR;
    header.unique = kUnique;
    ASSERT_TRUE(WriteInData(header, &body, sizeof(body)));
  }
  {  // DataFilter passes GETATTR to the app.
    fuse_in_header header = {};
    fuse_getattr_in body = {};
    ASSERT_TRUE(ReadInData(&header, &body, sizeof(body)));
    EXPECT_EQ(FUSE_GETATTR, header.opcode);
    EXPECT_EQ(kUnique, header.unique);
  }
  {  // GETATTR response from app to DataFilter.
    fuse_out_header header = {};
    fuse_attr_out body = {};
    header.len = sizeof(header) - 1;  // Invalid len.
    header.unique = kUnique;
    body.attr.mode = kMode;
    ASSERT_TRUE(WriteOutData(header, &body, sizeof(body)));
  }
  {  // DataFilter rejects response because of the invalid header.
    fuse_out_header header = {};
    fuse_attr_out body = {};
    EXPECT_FALSE(ReadOutData(&header, &body, sizeof(body)));
  }
}

TEST_F(DataFilterTest, NotSupported) {
  constexpr int kUnique = 123;
  {  // MKNOD should not be supported.
    fuse_in_header header = {};
    fuse_mknod_in body = {};
    header.len = sizeof(header) + sizeof(body);
    header.opcode = FUSE_MKNOD;
    header.unique = kUnique;
    ASSERT_TRUE(WriteInData(header, &body, sizeof(body)));
  }
  {  // ENOSYS is written to /dev/fuse.
    fuse_out_header header = {};
    ASSERT_TRUE(ReadOutData(&header, nullptr, 0));
    EXPECT_EQ(-ENOSYS, header.error);
    EXPECT_EQ(kUnique, header.unique);
  }
}

}  // namespace appfuse
}  // namespace arc
