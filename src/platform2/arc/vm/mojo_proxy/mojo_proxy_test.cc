// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/mojo_proxy.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/posix/unix_domain_socket.h>
#include <base/run_loop.h>
#include <base/task/thread_pool.h>
#include <base/task/thread_pool/thread_pool_instance.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <base/threading/thread_restrictions.h>
#include <gtest/gtest.h>

#include "arc/vm/mojo_proxy/file_descriptor_util.h"
#include "arc/vm/mojo_proxy/message.pb.h"
#include "arc/vm/mojo_proxy/message_stream.h"

namespace arc {
namespace {

class TestDelegate : public MojoProxy::Delegate {
 public:
  TestDelegate(MojoProxy::Type type, base::ScopedFD fd)
      : type_(type), stream_(std::make_unique<MessageStream>(std::move(fd))) {}
  ~TestDelegate() override = default;

  bool is_stopped() const { return is_stopped_; }

  void ResetStream() { stream_.reset(); }

  MojoProxy::Type GetType() const override { return type_; }
  int GetPollFd() override { return stream_->Get(); }
  base::ScopedFD CreateProxiedRegularFile(int64_t handle,
                                          int32_t flags) override {
    return {};
  }
  bool SendMessage(const arc_proxy::MojoMessage& message,
                   const std::vector<base::ScopedFD>& fds) override {
    return stream_->Write(message, fds);
  }
  bool ReceiveMessage(arc_proxy::MojoMessage* message,
                      std::vector<base::ScopedFD>* fds) override {
    if (!virtwl_mode_) {
      return stream_->Read(message, fds);
    }

    if (virtwl_tmp_message_) {
      *message = std::move(*virtwl_tmp_message_);
      virtwl_tmp_message_.reset();
      return true;
    }

    std::vector<base::ScopedFD> extra_fds;
    arc_proxy::MojoMessage tmp_msg;
    if (!stream_->Read(message, fds) || !stream_->Read(&tmp_msg, &extra_fds)) {
      return false;
    }
    for (auto& fd : extra_fds) {
      fds->push_back(std::move(fd));
    }
    virtwl_tmp_message_ = std::move(tmp_msg);
    return true;
  }
  void OnStopped() override { is_stopped_ = true; }

  void SetVirtWlMode() { virtwl_mode_ = true; }

 private:
  const MojoProxy::Type type_;
  std::unique_ptr<MessageStream> stream_;
  bool is_stopped_ = false;

  // When virtwl mode is enabled, some behavior of virtwl is emulated. In
  // particular, receiving data on the 'guest' side does not respect message
  // boundaries.
  bool virtwl_mode_ = false;

  std::optional<arc_proxy::MojoMessage> virtwl_tmp_message_;
};

class MojoProxyTest : public testing::Test {
 public:
  MojoProxyTest()
      : MojoProxyTest(
            base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
            base::test::TaskEnvironment::MainThreadType::IO) {}
  MojoProxyTest(const MojoProxyTest&) = delete;
  MojoProxyTest& operator=(const MojoProxyTest&) = delete;
  MojoProxyTest(base::test::TaskEnvironment::ThreadingMode threading_mode,
                base::test::TaskEnvironment::MainThreadType main_thread_type)
      : task_environment_(threading_mode, main_thread_type) {}

  ~MojoProxyTest() override = default;

  void SetUp() override {
    // Use a blocking socket pair instead of virtio-wl for testing.
    auto socket_pair = CreateSocketPair(SOCK_STREAM);
    ASSERT_TRUE(socket_pair.has_value());

    server_delegate_ = std::make_unique<TestDelegate>(
        MojoProxy::Type::SERVER, std::move(socket_pair->first));
    client_delegate_ = std::make_unique<TestDelegate>(
        MojoProxy::Type::CLIENT, std::move(socket_pair->second));

    // Register initial socket pairs.
    auto server_socket_pair = CreateSocketPair(SOCK_STREAM | SOCK_NONBLOCK);
    ASSERT_TRUE(server_socket_pair.has_value());
    auto client_socket_pair = CreateSocketPair(SOCK_STREAM | SOCK_NONBLOCK);
    ASSERT_TRUE(client_socket_pair.has_value());

    server_ = std::make_unique<MojoProxy>(server_delegate_.get());
    int64_t handle = server_->RegisterFileDescriptor(
        std::move(std::move(server_socket_pair->first)),
        arc_proxy::FileDescriptor::SOCKET_STREAM, 0 /* handle */);

    StartClient(handle, std::move(client_socket_pair->first));
    server_fd_ = std::move(server_socket_pair->second);
    client_fd_ = std::move(client_socket_pair->second);
  }

  void TearDown() override {
    client_fd_.reset();
    server_fd_.reset();
    ResetServer();
    ResetClient();
  }

  MojoProxy* server() { return server_.get(); }
  MojoProxy* client() { return client_.get(); }

  TestDelegate& server_delegate() { return *server_delegate_; }
  TestDelegate& client_delegate() { return *client_delegate_; }

  int server_fd() const { return server_fd_.get(); }
  int client_fd() const { return client_fd_.get(); }

  void ResetServerFD() { server_fd_.reset(); }
  void ResetClientFD() { client_fd_.reset(); }

  void ResetServer() {
    base::ScopedAllowBaseSyncPrimitivesForTesting allow_sync;
    server_.reset();
    server_delegate_->ResetStream();
  }
  virtual void ResetClient() { DoResetClient(); }

  void DoResetClient() {
    base::ScopedAllowBaseSyncPrimitivesForTesting allow_sync;
    client_.reset();
    client_delegate_->ResetStream();
  }

 protected:
  virtual void StartClient(int64_t handle, base::ScopedFD client) {
    client_ = std::make_unique<MojoProxy>(client_delegate_.get());
    client_->RegisterFileDescriptor(
        std::move(client), arc_proxy::FileDescriptor::SOCKET_STREAM, handle);
  }

  std::unique_ptr<TestDelegate> server_delegate_;
  std::unique_ptr<TestDelegate> client_delegate_;

  std::unique_ptr<MojoProxy> server_;
  std::unique_ptr<MojoProxy> client_;

 private:
  base::test::TaskEnvironment task_environment_;

  base::ScopedFD server_fd_;
  base::ScopedFD client_fd_;
};

// A fixture class that emulates behavior of virtwl by not respecting
// message boundaries.
class VirtwlMojoProxyTest : public MojoProxyTest {
 public:
  VirtwlMojoProxyTest()
      : MojoProxyTest(
            // Virtwl mode doesn't have a 1-to-1 mapping between send and
            // recv, so running everything on one thread can result in
            // deadlocks depending on the task order. Run the client on a
            // dedicated thread to avoid this.
            base::test::TaskEnvironment::ThreadingMode::MULTIPLE_THREADS,
            base::test::TaskEnvironment::MainThreadType::IO) {}

 private:
  void StartClient(int64_t handle, base::ScopedFD client) override {
    client_task_runner_ = base::ThreadPool::CreateSequencedTaskRunner(
        {base::MayBlock(), base::TaskPriority::BEST_EFFORT});

    client_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&VirtwlMojoProxyTest::StartClientOnHandler,
                       base::Unretained(this), handle, std::move(client)));
    base::ThreadPoolInstance::Get()->FlushForTesting();
  }

  void StartClientOnHandler(int64_t handle, base::ScopedFD client) {
    client_delegate_->SetVirtWlMode();

    client_ = std::make_unique<MojoProxy>(client_delegate_.get());

    client_->RegisterFileDescriptor(
        std::move(client), arc_proxy::FileDescriptor::SOCKET_STREAM, handle);
  }

  void ResetClient() override {
    client_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&MojoProxyTest::DoResetClient, base::Unretained(this)));
    base::ThreadPoolInstance::Get()->FlushForTesting();
  }

  scoped_refptr<base::SequencedTaskRunner> client_task_runner_;
};

// Runs the message loop until the given |fd| gets read ready.
void WaitUntilReadable(int fd) {
  base::RunLoop run_loop;
  auto controller =
      base::FileDescriptorWatcher::WatchReadable(fd, run_loop.QuitClosure());
  run_loop.Run();
}

// Exercises if simple data tranferring from |write_fd| to |read_fd| works.
void TestDataTransfer(int write_fd, int read_fd) {
  constexpr char kData[] = "abcdefg";
  if (Sendmsg(write_fd, kData, sizeof(kData), {}) != sizeof(kData)) {
    ADD_FAILURE() << "Failed to send message.";
    return;
  }

  WaitUntilReadable(read_fd);
  char buf[256];
  std::vector<base::ScopedFD> fds;
  ssize_t size = Recvmsg(read_fd, buf, sizeof(buf), &fds);
  EXPECT_EQ(size, sizeof(kData));
  EXPECT_STREQ(buf, kData);
  EXPECT_TRUE(fds.empty());
}

// Checks if EOF is read from the give socket |fd|.
void ExpectSocketEof(int fd) {
  char buf[256];
  std::vector<base::ScopedFD> fds;
  ssize_t size = Recvmsg(fd, buf, sizeof(buf), &fds);
  EXPECT_EQ(size, 0);
  EXPECT_TRUE(fds.empty());
}

// Gets the inode number from |fd|.
ino_t GetInodeNumber(const base::ScopedFD& fd) {
  struct stat st = {};
  EXPECT_NE(-1, fstat(fd.get(), &st));
  return st.st_ino;
}

TEST_F(MojoProxyTest, ServerToClient) {
  TestDataTransfer(server_fd(), client_fd());
}

TEST_F(MojoProxyTest, ClientToServer) {
  TestDataTransfer(client_fd(), server_fd());
}

TEST_F(MojoProxyTest, CloseServer) {
  ResetServerFD();
  WaitUntilReadable(client_fd());
  ExpectSocketEof(client_fd());
}

TEST_F(MojoProxyTest, CloseClient) {
  ResetClientFD();
  WaitUntilReadable(server_fd());
  ExpectSocketEof(server_fd());
}

TEST_F(MojoProxyTest, ResetServer) {
  ResetServer();
  EXPECT_TRUE(server_delegate().is_stopped());
  WaitUntilReadable(client_fd());
  ExpectSocketEof(client_fd());
  EXPECT_TRUE(client_delegate().is_stopped());
}

TEST_F(MojoProxyTest, ResetClient) {
  ResetClient();
  EXPECT_TRUE(client_delegate().is_stopped());
  WaitUntilReadable(server_fd());
  ExpectSocketEof(server_fd());
  EXPECT_TRUE(server_delegate().is_stopped());
}

TEST_F(MojoProxyTest, FileWriteError) {
  // Register a socket pair to the server.
  auto server_socket_pair = CreateSocketPair(SOCK_STREAM | SOCK_NONBLOCK);
  ASSERT_TRUE(server_socket_pair.has_value());
  int64_t handle = server()->RegisterFileDescriptor(
      std::move(server_socket_pair->first),
      arc_proxy::FileDescriptor::SOCKET_STREAM, 0 /* handle */);
  auto server_fd = std::move(server_socket_pair->second);

  // Register a read only FD to the client. This will cause a write error.
  base::ScopedFD client_fd_read, client_fd_write;
  base::CreatePipe(&client_fd_read, &client_fd_write, true);
  ASSERT_TRUE(client_fd_read.is_valid());
  client()->RegisterFileDescriptor(
      std::move(client_fd_read), arc_proxy::FileDescriptor::FIFO_READ, handle);

  // Try to send data from the server to the client, but it fails because of a
  // write error in the client.
  constexpr char kData[] = "abcdefg";
  ASSERT_TRUE(base::WriteFileDescriptor(server_fd.get(), kData));
  // Write error on the client results in closing the server socket.
  WaitUntilReadable(server_fd.get());
  ExpectSocketEof(server_fd.get());
}

TEST_F(MojoProxyTest, PassStreamSocketFromServer) {
  auto sockpair = CreateSocketPair(SOCK_STREAM | SOCK_NONBLOCK);
  ASSERT_TRUE(sockpair.has_value());
  constexpr char kData[] = "testdata";
  {
    std::vector<base::ScopedFD> fds;
    fds.push_back(std::move(sockpair->second));
    ASSERT_EQ(Sendmsg(server_fd(), kData, sizeof(kData), fds), sizeof(kData));
  }

  base::ScopedFD received_fd;
  {
    WaitUntilReadable(client_fd());
    char buf[256];
    std::vector<base::ScopedFD> fds;
    ssize_t size = Recvmsg(client_fd(), buf, sizeof(buf), &fds);
    EXPECT_EQ(sizeof(kData), size);
    EXPECT_STREQ(kData, buf);
    EXPECT_EQ(1, fds.size());
    received_fd = std::move(fds[0]);
  }
  EXPECT_EQ(SOCK_STREAM, GetSocketType(received_fd.get()));
  TestDataTransfer(sockpair->first.get(), received_fd.get());
  TestDataTransfer(received_fd.get(), sockpair->first.get());
}

TEST_F(VirtwlMojoProxyTest, PassTwoTransportablesFromServerVirtwl) {
  // Directories are an easy non-regular/fifo/socket type of fd.
  base::ScopedTempDir tmp_dir_a;
  ASSERT_TRUE(tmp_dir_a.CreateUniqueTempDir());
  base::ScopedFD fd1(HANDLE_EINTR(
      open(tmp_dir_a.GetPath().value().c_str(), O_DIRECTORY | O_RDONLY)));
  ino_t fd1_ino = GetInodeNumber(fd1);

  base::ScopedTempDir tmp_dir_b;
  ASSERT_TRUE(tmp_dir_b.CreateUniqueTempDir());
  base::ScopedFD fd2(HANDLE_EINTR(
      open(tmp_dir_b.GetPath().value().c_str(), O_DIRECTORY | O_RDONLY)));
  ino_t fd2_ino = GetInodeNumber(fd2);

  EXPECT_NE(fd1_ino, fd2_ino);

  constexpr char kData[] = "testdata";
  {
    std::vector<base::ScopedFD> fds;
    fds.push_back(std::move(fd1));
    ASSERT_EQ(Sendmsg(server_fd(), kData, sizeof(kData), fds), sizeof(kData));

    fds.clear();
    fds.push_back(std::move(fd2));
    ASSERT_EQ(Sendmsg(server_fd(), kData, sizeof(kData), fds), sizeof(kData));

    // The virtwl mode of TestDelegate.ReceiveMessage eats a readable signal
    // on the client fd, so reset the server to unstick things.
    ResetServerFD();
  }

  base::ScopedFD received_fd1;
  base::ScopedFD received_fd2;
  {
    WaitUntilReadable(client_fd());
    char buf[256] = {};
    std::vector<base::ScopedFD> fds;
    ssize_t size = Recvmsg(client_fd(), buf, sizeof(buf), &fds);
    EXPECT_EQ(sizeof(kData), size);
    EXPECT_STREQ(kData, buf);
    ASSERT_EQ(1, fds.size());
    received_fd1 = std::move(fds[0]);

    WaitUntilReadable(client_fd());
    char buf2[256] = {};
    fds.clear();
    size = Recvmsg(client_fd(), buf2, sizeof(buf2), &fds);
    EXPECT_EQ(sizeof(kData), size);
    EXPECT_STREQ(kData, buf2);
    ASSERT_EQ(1, fds.size());
    received_fd2 = std::move(fds[0]);
  }
  EXPECT_EQ(fd1_ino, GetInodeNumber(received_fd1));
  EXPECT_EQ(fd2_ino, GetInodeNumber(received_fd2));
}

TEST_F(MojoProxyTest, PassStreamSocketSocketFromClient) {
  auto sockpair = CreateSocketPair(SOCK_STREAM | SOCK_NONBLOCK);
  ASSERT_TRUE(sockpair.has_value());
  constexpr char kData[] = "testdata";
  {
    std::vector<base::ScopedFD> fds;
    fds.push_back(std::move(sockpair->second));
    ASSERT_EQ(Sendmsg(client_fd(), kData, sizeof(kData), fds), sizeof(kData));
  }

  base::ScopedFD received_fd;
  {
    WaitUntilReadable(server_fd());
    char buf[256];
    std::vector<base::ScopedFD> fds;
    ssize_t size = Recvmsg(server_fd(), buf, sizeof(buf), &fds);
    EXPECT_EQ(sizeof(kData), size);
    EXPECT_STREQ(kData, buf);
    EXPECT_EQ(1, fds.size());
    received_fd = std::move(fds[0]);
  }
  EXPECT_EQ(SOCK_STREAM, GetSocketType(received_fd.get()));
  TestDataTransfer(sockpair->first.get(), received_fd.get());
  TestDataTransfer(received_fd.get(), sockpair->first.get());
}

TEST_F(MojoProxyTest, PassDgramSocketFromServer) {
  auto sockpair = CreateSocketPair(SOCK_DGRAM | SOCK_NONBLOCK);
  ASSERT_TRUE(sockpair.has_value());
  constexpr char kData[] = "testdata";
  {
    std::vector<base::ScopedFD> fds;
    fds.push_back(std::move(sockpair->second));
    ASSERT_EQ(Sendmsg(server_fd(), kData, sizeof(kData), fds), sizeof(kData));
  }

  base::ScopedFD received_fd;
  {
    WaitUntilReadable(client_fd());
    char buf[256];
    std::vector<base::ScopedFD> fds;
    ssize_t size = Recvmsg(client_fd(), buf, sizeof(buf), &fds);
    EXPECT_EQ(sizeof(kData), size);
    EXPECT_STREQ(kData, buf);
    EXPECT_EQ(1, fds.size());
    received_fd = std::move(fds[0]);
  }
  EXPECT_EQ(SOCK_DGRAM, GetSocketType(received_fd.get()));
  TestDataTransfer(sockpair->first.get(), received_fd.get());
  TestDataTransfer(received_fd.get(), sockpair->first.get());
}

TEST_F(MojoProxyTest, PassSeqpacketSocketFromServer) {
  auto sockpair = CreateSocketPair(SOCK_SEQPACKET | SOCK_NONBLOCK);
  ASSERT_TRUE(sockpair.has_value());
  constexpr char kData[] = "testdata";
  {
    std::vector<base::ScopedFD> fds;
    fds.push_back(std::move(sockpair->second));
    ASSERT_EQ(Sendmsg(server_fd(), kData, sizeof(kData), fds), sizeof(kData));
  }

  base::ScopedFD received_fd;
  {
    WaitUntilReadable(client_fd());
    char buf[256];
    std::vector<base::ScopedFD> fds;
    ssize_t size = Recvmsg(client_fd(), buf, sizeof(buf), &fds);
    EXPECT_EQ(sizeof(kData), size);
    EXPECT_STREQ(kData, buf);
    EXPECT_EQ(1, fds.size());
    received_fd = std::move(fds[0]);
  }
  EXPECT_EQ(SOCK_SEQPACKET, GetSocketType(received_fd.get()));
  TestDataTransfer(sockpair->first.get(), received_fd.get());
  TestDataTransfer(received_fd.get(), sockpair->first.get());
}

TEST_F(MojoProxyTest, Connect) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath socket_path = temp_dir.GetPath().Append("test.sock");

  // Create unix domain socket for testing, which is connected by the following
  // Connect() invocation from client side.
  auto server_sock = CreateUnixDomainSocket(socket_path);
  server()->AddExpectedSocketPathForTesting(socket_path);

  // Try to follow the actual initial connection procedure.
  base::test::TestFuture<int, int64_t> future;
  client()->Connect(socket_path, future.GetCallback());
  const int error_code = future.Get<0>();
  const int64_t handle = future.Get<1>();
  ASSERT_EQ(0, error_code);
  // TODO(hidehiko): Remove the cast on next libchrome uprev.
  ASSERT_TRUE(handle != static_cast<int64_t>(0));

  // Register client side socket.
  auto client_sock_pair = CreateSocketPair(SOCK_STREAM | SOCK_NONBLOCK);
  ASSERT_TRUE(client_sock_pair.has_value());
  client()->RegisterFileDescriptor(std::move(client_sock_pair->first),
                                   arc_proxy::FileDescriptor::SOCKET_STREAM,
                                   handle);

  auto client_fd = std::move(client_sock_pair->second);
  auto server_fd = AcceptSocket(server_sock.get());
  ASSERT_TRUE(server_fd.is_valid());

  TestDataTransfer(client_fd.get(), server_fd.get());
  TestDataTransfer(server_fd.get(), client_fd.get());
}

TEST_F(MojoProxyTest, Pread) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const base::FilePath file_path = temp_dir.GetPath().Append("test.txt");
  constexpr char kFileContent[] = "abcdefghijklmnopqrstuvwxyz";
  // Trim trailing '\0'.
  ASSERT_EQ(sizeof(kFileContent) - 1,
            base::WriteFile(file_path, kFileContent, sizeof(kFileContent) - 1));

  base::ScopedFD fd(HANDLE_EINTR(open(file_path.value().c_str(), O_RDONLY)));
  ASSERT_TRUE(fd.is_valid());
  const int64_t handle = client()->RegisterFileDescriptor(
      std::move(fd), arc_proxy::FileDescriptor::REGULAR_FILE, 0);

  base::test::TestFuture<int, const std::string&> future;
  server()->Pread(handle, 10, 10, future.GetCallback());
  const int error_code = future.Get<0>();
  const std::string& blob = future.Get<1>();
  EXPECT_EQ(0, error_code);
  EXPECT_EQ("klmnopqrst", blob);
}

TEST_F(MojoProxyTest, Pread_UnknownHandle) {
  constexpr int64_t kUnknownHandle = 100;
  base::test::TestFuture<int, const std::string&> future;
  server()->Pread(kUnknownHandle, 10, 10, future.GetCallback());
  const int error_code = future.Get<0>();
  EXPECT_EQ(EBADF, error_code);
}

TEST_F(MojoProxyTest, Fstat) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const base::FilePath file_path = temp_dir.GetPath().Append("test.txt");
  constexpr char kFileContent[] = "abcdefghijklmnopqrstuvwxyz";
  // Trim trailing '\0'.
  constexpr size_t kContentSize = sizeof(kFileContent) - 1;
  ASSERT_EQ(kContentSize,
            base::WriteFile(file_path, kFileContent, kContentSize));

  base::ScopedFD fd(HANDLE_EINTR(open(file_path.value().c_str(), O_RDONLY)));
  ASSERT_TRUE(fd.is_valid());
  const int64_t handle = client()->RegisterFileDescriptor(
      std::move(fd), arc_proxy::FileDescriptor::REGULAR_FILE, 0);

  base::test::TestFuture<int, int64_t> future;
  server()->Fstat(handle, future.GetCallback());
  const int error_code = future.Get<0>();
  const int64_t size = future.Get<1>();
  EXPECT_EQ(0, error_code);
  EXPECT_EQ(26, size);
}

TEST_F(MojoProxyTest, Fstat_UnknownHandle) {
  constexpr int64_t kUnknownHandle = 100;
  base::test::TestFuture<int, int64_t> future;
  server()->Fstat(kUnknownHandle, future.GetCallback());
  const int error_code = future.Get<0>();
  EXPECT_EQ(EBADF, error_code);
}

TEST_F(MojoProxyTest, Ftruncate) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const base::FilePath file_path = temp_dir.GetPath().Append("test.txt");
  ASSERT_EQ(0, base::WriteFile(file_path, nullptr, 0));

  base::ScopedFD fd(HANDLE_EINTR(open(file_path.value().c_str(), O_WRONLY)));
  ASSERT_TRUE(fd.is_valid());
  const int64_t handle = client()->RegisterFileDescriptor(
      std::move(fd), arc_proxy::FileDescriptor::REGULAR_FILE, 0);

  constexpr int64_t kLength = 5;
  base::test::TestFuture<int> future;
  server()->Ftruncate(handle, kLength, future.GetCallback());
  const int error_code = future.Get();
  EXPECT_EQ(0, error_code);

  std::string contents;
  ASSERT_TRUE(ReadFileToString(file_path, &contents));
  EXPECT_EQ(contents.size(), kLength);
}

TEST_F(MojoProxyTest, Ftruncate_UnknownHandle) {
  constexpr int64_t kUnknownHandle = 100;
  constexpr int64_t kLength = 5;
  base::test::TestFuture<int> future;
  server()->Ftruncate(kUnknownHandle, kLength, future.GetCallback());
  const int error_code = future.Get();
  EXPECT_EQ(EBADF, error_code);
}

}  // namespace
}  // namespace arc
