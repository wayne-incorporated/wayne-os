// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/local_file.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/posix/eintr_wrapper.h>
#include <base/run_loop.h>
#include <base/strings/string_piece.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "arc/vm/mojo_proxy/file_descriptor_util.h"

namespace arc {
namespace {

template <typename T>
void StoreArgument(T* out, T in) {
  *out = std::move(in);
}

class LocalFileTest : public testing::Test {
 public:
  LocalFileTest() = default;
  ~LocalFileTest() override = default;
  LocalFileTest(const LocalFileTest&) = delete;
  LocalFileTest& operator=(const LocalFileTest&) = delete;

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
};

TEST_F(LocalFileTest, ReadErrorIoctl) {
  // Pass a /dev/null FD which doesn't support iotctl(FIONREAD).
  base::ScopedFD fd(HANDLE_EINTR(open("/dev/null", O_RDONLY)));
  auto read_result =
      LocalFile(std::move(fd), true, base::DoNothing(), nullptr).Read();
  EXPECT_EQ(ENOTTY, read_result.error_code);
}

TEST_F(LocalFileTest, ReadErrorRecvmsg) {
  auto pipes = CreatePipe();
  ASSERT_TRUE(pipes.has_value());
  // Put some data.
  ASSERT_TRUE(base::WriteFileDescriptor(pipes->second.get(), "a"));
  // Pipe doesn't support recvmsg, but can_send_fds==true is specified.
  auto read_result =
      LocalFile(std::move(pipes->first), true, base::DoNothing(), nullptr)
          .Read();
  EXPECT_EQ(ENOTSOCK, read_result.error_code);
}

TEST_F(LocalFileTest, Pread) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const base::FilePath file_path = temp_dir.GetPath().Append("test_file.txt");
  constexpr char kFileContent[] = "abcdefghijklmnopqrstuvwxyz";
  // Trim trailing '\0'.
  ASSERT_EQ(sizeof(kFileContent) - 1,
            base::WriteFile(file_path, kFileContent, sizeof(kFileContent) - 1));

  base::ScopedFD fd(HANDLE_EINTR(open(file_path.value().c_str(), O_RDONLY)));
  ASSERT_TRUE(fd.is_valid());

  LocalFile stream(std::move(fd), false,
                   base::BindOnce([]() { ADD_FAILURE(); }),
                   task_environment_.GetMainThreadTaskRunner());
  arc_proxy::PreadResponse response;
  stream.Pread(
      10, 10,
      base::BindOnce(&StoreArgument<arc_proxy::PreadResponse>, &response));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, response.error_code());
  EXPECT_EQ("klmnopqrst", response.blob());

  // Test for EOF. Result |blob| should contain only the available bytes.
  stream.Pread(
      10, 20,
      base::BindOnce(&StoreArgument<arc_proxy::PreadResponse>, &response));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, response.error_code());
  EXPECT_EQ("uvwxyz", response.blob());
}

TEST_F(LocalFileTest, PreadError) {
  // Use -1 (invalid file descriptor) to let pread(2) return error in Pread().
  LocalFile stream{base::ScopedFD(), false,
                   base::BindOnce([]() { ADD_FAILURE(); }),
                   task_environment_.GetMainThreadTaskRunner()};
  arc_proxy::PreadResponse response;
  stream.Pread(
      10, 10,
      base::BindOnce(&StoreArgument<arc_proxy::PreadResponse>, &response));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(EBADF, response.error_code());
}

TEST_F(LocalFileTest, Fstat) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const base::FilePath file_path = temp_dir.GetPath().Append("test_file.txt");
  constexpr char kFileContent[] = "abcdefghijklmnopqrstuvwxyz";
  // Trim trailing '\0'.
  ASSERT_EQ(sizeof(kFileContent) - 1,
            base::WriteFile(file_path, kFileContent, sizeof(kFileContent) - 1));

  base::ScopedFD fd(HANDLE_EINTR(open(file_path.value().c_str(), O_RDONLY)));
  ASSERT_TRUE(fd.is_valid());

  LocalFile stream(std::move(fd), false,
                   base::BindOnce([]() { ADD_FAILURE(); }),
                   task_environment_.GetMainThreadTaskRunner());
  arc_proxy::FstatResponse response;
  stream.Fstat(
      base::BindOnce(&StoreArgument<arc_proxy::FstatResponse>, &response));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, response.error_code());
  EXPECT_EQ(26, response.size());
}

TEST_F(LocalFileTest, FstatError) {
  // Use -1 (invalid file descriptor) to let pread(2) return error in Pread().
  LocalFile stream{base::ScopedFD(), false,
                   base::BindOnce([]() { ADD_FAILURE(); }),
                   task_environment_.GetMainThreadTaskRunner()};
  arc_proxy::FstatResponse response;
  stream.Fstat(
      base::BindOnce(&StoreArgument<arc_proxy::FstatResponse>, &response));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(EBADF, response.error_code());
}

TEST_F(LocalFileTest, Ftruncate) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const base::FilePath file_path = temp_dir.GetPath().Append("test_file.txt");
  ASSERT_EQ(0, base::WriteFile(file_path, nullptr, 0));

  base::ScopedFD fd(HANDLE_EINTR(open(file_path.value().c_str(), O_WRONLY)));
  ASSERT_TRUE(fd.is_valid());

  LocalFile file(std::move(fd), false, base::BindOnce([]() { ADD_FAILURE(); }),
                 task_environment_.GetMainThreadTaskRunner());
  arc_proxy::FtruncateResponse response;
  constexpr int64_t kLength = 5;
  file.Ftruncate(
      kLength,
      base::BindOnce(&StoreArgument<arc_proxy::FtruncateResponse>, &response));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, response.error_code());

  std::string contents;
  ASSERT_TRUE(ReadFileToString(file_path, &contents));
  EXPECT_EQ(contents.size(), kLength);
}

TEST_F(LocalFileTest, FtruncateError) {
  // Use -1 (invalid file descriptor) to let ftruncate(2) return error.
  LocalFile file{base::ScopedFD(), false,
                 base::BindOnce([]() { ADD_FAILURE(); }),
                 task_environment_.GetMainThreadTaskRunner()};
  arc_proxy::FtruncateResponse response;
  constexpr int64_t kLength = 5;
  file.Ftruncate(
      kLength,
      base::BindOnce(&StoreArgument<arc_proxy::FtruncateResponse>, &response));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(EBADF, response.error_code());
}

// Tests LocalFile with a stream socket.
class SocketStreamTest : public testing::Test {
 public:
  SocketStreamTest() = default;
  SocketStreamTest(const SocketStreamTest&) = delete;
  SocketStreamTest& operator=(const SocketStreamTest&) = delete;

  ~SocketStreamTest() override = default;

  void SetUp() override {
    auto sockets = CreateSocketPair(SOCK_STREAM | SOCK_NONBLOCK);
    ASSERT_TRUE(sockets.has_value());
    stream_ = std::make_unique<LocalFile>(
        std::move(sockets.value().first), true,
        base::BindOnce([]() { ADD_FAILURE(); }), nullptr);
    socket_ = std::move(sockets.value().second);
  }

 protected:
  std::unique_ptr<LocalFile> stream_;  // Paired with socket_.
  base::ScopedFD socket_;              // Paired with stream_.

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::MainThreadType::IO};
};

TEST_F(SocketStreamTest, Read) {
  base::ScopedFD attached_fd(HANDLE_EINTR(open("/dev/null", O_RDONLY)));
  ASSERT_TRUE(attached_fd.is_valid());

  constexpr char kData[] = "abcdefghijklmnopqrstuvwxyz";
  std::vector<base::ScopedFD> fds;
  fds.push_back(std::move(attached_fd));
  ASSERT_EQ(Sendmsg(socket_.get(), kData, sizeof(kData), fds), sizeof(kData));

  auto read_result = stream_->Read();
  EXPECT_EQ(0, read_result.error_code);
  EXPECT_EQ(base::StringPiece(kData, sizeof(kData)), read_result.blob);
  EXPECT_EQ(1, read_result.fds.size());
}

TEST_F(SocketStreamTest, ReadEOF) {
  // Close the other side immediately.
  socket_.reset();

  auto read_result = stream_->Read();
  EXPECT_EQ(0, read_result.error_code);
  EXPECT_TRUE(read_result.blob.empty());
  EXPECT_TRUE(read_result.fds.empty());
}

TEST_F(SocketStreamTest, Write) {
  base::ScopedFD attached_fd(HANDLE_EINTR(open("/dev/null", O_RDONLY)));
  ASSERT_TRUE(attached_fd.is_valid());

  constexpr char kData[] = "abcdefghijklmnopqrstuvwxyz";
  {
    std::vector<base::ScopedFD> fds;
    fds.emplace_back(std::move(attached_fd));
    ASSERT_TRUE(
        stream_->Write(std::string(kData, sizeof(kData)), std::move(fds)));
  }
  std::string read_data;
  read_data.resize(sizeof(kData));
  std::vector<base::ScopedFD> fds;
  ASSERT_EQ(sizeof(kData),
            Recvmsg(socket_.get(), &read_data[0], sizeof(kData), &fds));
  EXPECT_EQ(1, fds.size());
}

TEST_F(SocketStreamTest, PendingWrite) {
  int sndbuf_value = 0;
  socklen_t len = sizeof(sndbuf_value);
  ASSERT_EQ(
      0, getsockopt(socket_.get(), SOL_SOCKET, SO_SNDBUF, &sndbuf_value, &len));

  // To verify that LocalFile can handle partial write.
  const size_t kDataSize = sndbuf_value * 2 / 3;
  constexpr int kNumData = 4;

  // Write data to the stream.
  std::string sent_data;
  for (int i = 0; i < kNumData; ++i) {
    const std::string data(kDataSize, 'a' + i);
    std::vector<base::ScopedFD> attached_fds;
    attached_fds.emplace_back(HANDLE_EINTR(open("/dev/null", O_RDONLY)));
    ASSERT_TRUE(attached_fds.back().is_valid());
    ASSERT_TRUE(stream_->Write(data, std::move(attached_fds)));
    sent_data += data;
  }

  // Read data from the stream.
  std::string read_data;
  std::vector<base::ScopedFD> read_fds;
  while (read_data.size() < sent_data.size()) {
    base::RunLoop().RunUntilIdle();  // To perform pending write.

    constexpr size_t kBufSize = 4096;
    std::string buf;
    std::vector<base::ScopedFD> fds;
    buf.resize(kBufSize);
    const ssize_t result = Recvmsg(socket_.get(), &buf[0], buf.size(), &fds);
    ASSERT_GT(result, 0);
    buf.resize(result);
    read_data += buf;
    for (auto& fd : fds)
      read_fds.push_back(std::move(fd));
  }

  EXPECT_EQ(sent_data, read_data);
  EXPECT_EQ(kNumData, read_fds.size());
}

TEST_F(SocketStreamTest, WriteError) {
  constexpr char kData[] = "abcdefghijklmnopqrstuvwxyz";
  bool error_handler_was_run = false;
  base::OnceClosure error_handler =
      base::BindOnce([](bool* run) { *run = true; }, &error_handler_was_run);
  // Write to a non-socket FD.
  base::ScopedFD fd(HANDLE_EINTR(open("/dev/null", O_RDONLY)));
  LocalFile(std::move(fd), true, std::move(error_handler), nullptr)
      .Write(kData, {});
  EXPECT_TRUE(error_handler_was_run);
}

// Tests LocalFile with a seqpacket socket.
class SocketSeqpacketTest : public testing::Test {
 public:
  SocketSeqpacketTest() = default;
  SocketSeqpacketTest(const SocketSeqpacketTest&) = delete;
  SocketSeqpacketTest& operator=(const SocketSeqpacketTest&) = delete;

  ~SocketSeqpacketTest() override = default;

  void SetUp() override {
    auto sockets = CreateSocketPair(SOCK_SEQPACKET | SOCK_NONBLOCK);
    ASSERT_TRUE(sockets.has_value());
    seqpacket_ = std::make_unique<LocalFile>(
        std::move(sockets.value().first), true,
        base::BindOnce([]() { ADD_FAILURE(); }), nullptr);
    socket_ = std::move(sockets.value().second);
  }

 protected:
  std::unique_ptr<LocalFile> seqpacket_;  // Paired with socket_.
  base::ScopedFD socket_;                 // Paired with seqpacket_.

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::MainThreadType::IO};
};

TEST_F(SocketSeqpacketTest, PendingWrite) {
  int sndbuf_value = 0;
  socklen_t len = sizeof(sndbuf_value);
  ASSERT_EQ(
      0, getsockopt(socket_.get(), SOL_SOCKET, SO_SNDBUF, &sndbuf_value, &len));

  // To verify that SOCK_SEQPACKET never performs partial write.
  const size_t kDataSize = sndbuf_value * 2 / 3;
  constexpr int kNumData = 4;

  // Write data to the socket.
  std::string sent_data;
  for (int i = 0; i < kNumData; ++i) {
    const std::string data(kDataSize, 'a' + i);
    std::vector<base::ScopedFD> attached_fds;
    attached_fds.emplace_back(HANDLE_EINTR(open("/dev/null", O_RDONLY)));
    ASSERT_TRUE(attached_fds.back().is_valid());
    ASSERT_TRUE(seqpacket_->Write(data, std::move(attached_fds)));
    sent_data += data;
  }

  // Read data from the socket.
  std::string read_data;
  for (int i = 0; i < kNumData; ++i) {
    base::RunLoop().RunUntilIdle();  // To perform pending write.

    std::string buf;
    std::vector<base::ScopedFD> fds;
    buf.resize(sndbuf_value);
    const ssize_t result = Recvmsg(socket_.get(), &buf[0], buf.size(), &fds);
    EXPECT_EQ(kDataSize, result);  // SOCK_SEQPACKET keeps the packet size.
    buf.resize(result);
    EXPECT_EQ(1, fds.size());
    read_data += buf;
  }
  EXPECT_EQ(sent_data, read_data);
}

// Tests LocalFile with a pipe.
class PipeStreamTest : public testing::Test {
 public:
  PipeStreamTest() = default;
  PipeStreamTest(const PipeStreamTest&) = delete;
  PipeStreamTest& operator=(const PipeStreamTest&) = delete;

  ~PipeStreamTest() override = default;

  void SetUp() override {
    auto pipes = CreatePipe();
    ASSERT_TRUE(pipes.has_value());
    std::tie(read_fd_, write_fd_) = std::move(pipes.value());
  }

 protected:
  base::ScopedFD read_fd_;
  base::ScopedFD write_fd_;

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::MainThreadType::IO};
};

TEST_F(PipeStreamTest, Read) {
  constexpr char kData[] = "abcdefghijklmnopqrstuvwxyz";
  ASSERT_TRUE(base::WriteFileDescriptor(
      write_fd_.get(), base::StringPiece(kData, sizeof(kData))));

  auto read_result = LocalFile(std::move(read_fd_), false,
                               base::BindOnce([]() { ADD_FAILURE(); }), nullptr)
                         .Read();
  EXPECT_EQ(0, read_result.error_code);
  EXPECT_EQ(base::StringPiece(kData, sizeof(kData)), read_result.blob);
  EXPECT_TRUE(read_result.fds.empty());
}

TEST_F(PipeStreamTest, ReadEOF) {
  // Close the write end immediately.
  write_fd_.reset();

  auto read_result = LocalFile(std::move(read_fd_), false,
                               base::BindOnce([]() { ADD_FAILURE(); }), nullptr)
                         .Read();
  EXPECT_EQ(0, read_result.error_code);
  EXPECT_TRUE(read_result.blob.empty());
  EXPECT_TRUE(read_result.fds.empty());
}

TEST_F(PipeStreamTest, Write) {
  constexpr char kData[] = "abcdefghijklmnopqrstuvwxyz";
  ASSERT_TRUE(LocalFile(std::move(write_fd_), false,
                        base::BindOnce([]() { ADD_FAILURE(); }), nullptr)
                  .Write(std::string(kData, sizeof(kData)), {}));

  std::string read_data;
  read_data.resize(sizeof(kData));
  ASSERT_TRUE(base::ReadFromFD(read_fd_.get(), &read_data[0], sizeof(kData)));
  EXPECT_EQ(std::string(kData, sizeof(kData)), read_data);
}

TEST_F(PipeStreamTest, WriteFD) {
  base::ScopedFD attached_fd(HANDLE_EINTR(open("/dev/null", O_RDONLY)));
  ASSERT_TRUE(attached_fd.is_valid());

  constexpr char kData[] = "abcdefghijklmnopqrstuvwxyz";
  std::vector<base::ScopedFD> fds;
  fds.emplace_back(std::move(attached_fd));
  // Not supported.
  bool error_handler_was_run = false;
  base::OnceClosure error_handler =
      base::BindOnce([](bool* run) { *run = true; }, &error_handler_was_run);
  EXPECT_TRUE(
      LocalFile(std::move(write_fd_), false, std::move(error_handler), nullptr)
          .Write(std::string(kData, sizeof(kData)), std::move(fds)));
  EXPECT_TRUE(error_handler_was_run);
}

TEST_F(PipeStreamTest, PendingWrite) {
  const int pipe_size = HANDLE_EINTR(fcntl(write_fd_.get(), F_GETPIPE_SZ));
  ASSERT_NE(-1, pipe_size);

  LocalFile stream(std::move(write_fd_), false,
                   base::BindOnce([]() { ADD_FAILURE(); }), nullptr);

  const std::string data1(pipe_size, 'a');
  const std::string data2(pipe_size, 'b');
  const std::string data3(pipe_size, 'c');

  // Write data1, data2, and data3 to the stream.
  ASSERT_TRUE(stream.Write(data1, {}));
  ASSERT_TRUE(stream.Write(data2, {}));
  ASSERT_TRUE(stream.Write(data3, {}));

  // Read data1 from the pipe.
  std::string read_data;
  read_data.resize(pipe_size);
  ASSERT_EQ(data1.size(), HANDLE_EINTR(read(read_fd_.get(), &read_data[0],
                                            read_data.size())));
  read_data.resize(data1.size());
  EXPECT_EQ(data1, read_data);

  // data2 is still pending.
  ASSERT_EQ(
      -1, HANDLE_EINTR(read(read_fd_.get(), &read_data[0], read_data.size())));
  ASSERT_EQ(EAGAIN, errno);

  // Now the pipe's buffer is empty. Let the stream write data2 to the pipe.
  base::RunLoop().RunUntilIdle();

  // Read data2 from the pipe.
  read_data.resize(pipe_size);
  ASSERT_EQ(data2.size(), HANDLE_EINTR(read(read_fd_.get(), &read_data[0],
                                            read_data.size())));
  read_data.resize(data2.size());
  EXPECT_EQ(data2, read_data);

  // data3 is still pending.
  ASSERT_EQ(
      -1, HANDLE_EINTR(read(read_fd_.get(), &read_data[0], read_data.size())));
  ASSERT_EQ(EAGAIN, errno);

  // Let the stream write data3 to the pipe.
  base::RunLoop().RunUntilIdle();

  // Read data3 from the pipe.
  read_data.resize(pipe_size);
  ASSERT_EQ(data3.size(), HANDLE_EINTR(read(read_fd_.get(), &read_data[0],
                                            read_data.size())));
  read_data.resize(data3.size());
  EXPECT_EQ(data3, read_data);
}

}  // namespace
}  // namespace arc
