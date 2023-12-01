// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/socket.h>
#include <time.h>

#include <list>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/task_environment.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/message_differencer.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>
#include <vm_protos/proto_bindings/vm_host.pb.h>

#include "vm_tools/syslog/guest_collector.h"

using std::string;

namespace pb = google::protobuf;

namespace vm_tools {
namespace syslog {
namespace {

using HandleLogsCallback =
    base::RepeatingCallback<void(std::unique_ptr<LogRequest>)>;

// Test server that just forwards the protobufs it receives to the main thread.
class FakeLogCollectorService final : public vm_tools::LogCollector::Service {
 public:
  FakeLogCollectorService(
      scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
      HandleLogsCallback handle_user_logs_cb);
  FakeLogCollectorService(const FakeLogCollectorService&) = delete;
  FakeLogCollectorService& operator=(const FakeLogCollectorService&) = delete;

  ~FakeLogCollectorService() override = default;

  // LogCollector::Service overrides.
  grpc::Status CollectUserLogs(grpc::ServerContext* ctx,
                               const vm_tools::LogRequest* request,
                               vm_tools::EmptyMessage* response) override;

 private:
  // Task runner for the main thread where tasks will get posted.
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;

  // Task which will get posted to main_task_runner_ whenever this service
  // receives user logs.
  HandleLogsCallback handle_user_logs_cb_;
};

FakeLogCollectorService::FakeLogCollectorService(
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    HandleLogsCallback handle_user_logs_cb)
    : main_task_runner_(main_task_runner),
      handle_user_logs_cb_(handle_user_logs_cb) {}

grpc::Status FakeLogCollectorService::CollectUserLogs(
    grpc::ServerContext* ctx,
    const vm_tools::LogRequest* request,
    vm_tools::EmptyMessage* response) {
  // Make a copy of the request and pass it on.
  auto request_copy = std::make_unique<vm_tools::LogRequest>(*request);
  main_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(handle_user_logs_cb_, std::move(std::move(request_copy))));

  return grpc::Status::OK;
}

void StartFakeLogCollectorService(
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    base::FilePath listen_path,
    base::OnceCallback<void(std::shared_ptr<grpc::Server>)> server_cb,
    HandleLogsCallback handle_user_logs_cb) {
  FakeLogCollectorService log_collector(main_task_runner, handle_user_logs_cb);

  grpc::ServerBuilder builder;
  builder.AddListeningPort("unix:" + listen_path.value(),
                           grpc::InsecureServerCredentials());
  builder.RegisterService(&log_collector);

  std::shared_ptr<grpc::Server> server(builder.BuildAndStart().release());
  main_task_runner->PostTask(FROM_HERE,
                             base::BindOnce(std::move(server_cb), server));

  if (server) {
    // This will not race with shutdown because the grpc server code includes a
    // check to see if the server has already been shut down (or is shutting
    // down) when Wait is called.
    server->Wait();
  }
}

constexpr char kServerSocket[] = "server";

// Test fixture for actually testing the Collector functionality.
class CollectorTest : public ::testing::Test {
 public:
  CollectorTest();
  CollectorTest(const CollectorTest&) = delete;
  CollectorTest& operator=(const CollectorTest&) = delete;

  ~CollectorTest() override = default;

 protected:
  // ::testing::Test overrides.
  void SetUp() override;
  void TearDown() override;

 private:
  // Posted back to the main thread by the grpc thread after starting the
  // server.
  void ServerStartCallback(base::OnceClosure quit,
                           std::shared_ptr<grpc::Server> server);

  // Posted back to the main thread by the grpc thread when it receives user
  // logs from the Collector.
  void HandleUserLogs(std::unique_ptr<vm_tools::LogRequest> request);

  // The message loop for the current thread.  Declared here because it must be
  // the last thing to be cleaned up.
  // TODO(crbug/1094927): Use SingleThreadTaskEnvironment
  base::test::TaskEnvironment task_environment_;

 protected:
  // Actual Collector being tested.
  std::unique_ptr<Collector> collector_;

  // Socket that tests will use to send the server syslog records.
  base::ScopedFD syslog_socket_;

  // LogRequest that is expected from the server for user logs.
  std::list<std::unique_ptr<vm_tools::LogRequest>> expected_user_requests_;

  // MessageDifferencer used to compare LogRequests.
  std::unique_ptr<pb::util::MessageDifferencer> message_differencer_;

  // Closure that should be called once all expected LogRequests have been
  // received or on failure.
  base::OnceClosure quit_;

  // Set to true to indicate failure.
  bool failed_;
  string failure_reason_;

 private:
  // Temporary directory where we will store our sockets.
  base::ScopedTempDir temp_dir_;

  // The thread on which the server will run.
  base::Thread server_thread_;

  // grpc::Server that will handle the requests.
  std::shared_ptr<grpc::Server> server_;

  base::WeakPtrFactory<CollectorTest> weak_factory_;
};

CollectorTest::CollectorTest()
    : task_environment_(
          base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
          base::test::TaskEnvironment::MainThreadType::IO),
      failed_(false),
      server_thread_("gRPC LogCollector Thread"),
      weak_factory_(this) {}

void CollectorTest::SetUp() {
  // Create the temporary directory.
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

  // Start the FakeLogCollectorService on a different thread.
  base::RunLoop run_loop;

  ASSERT_TRUE(server_thread_.Start());
  server_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &StartFakeLogCollectorService,
          base::SingleThreadTaskRunner::GetCurrentDefault(),
          temp_dir_.GetPath().Append(kServerSocket),
          base::BindOnce(&CollectorTest::ServerStartCallback,
                         weak_factory_.GetWeakPtr(), run_loop.QuitClosure()),
          base::BindRepeating(&CollectorTest::HandleUserLogs,
                              weak_factory_.GetWeakPtr())));

  run_loop.Run();

  ASSERT_TRUE(server_);

  // Create the sockets.
  int syslog_fds[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, syslog_fds), 0);

  // Create the stub to the FakeLogCollectorService.
  std::unique_ptr<vm_tools::LogCollector::Stub> stub =
      vm_tools::LogCollector::NewStub(grpc::CreateChannel(
          "unix:" + temp_dir_.GetPath().Append(kServerSocket).value(),
          grpc::InsecureChannelCredentials()));
  ASSERT_TRUE(stub);

  // Create the syslog server.
  collector_ = GuestCollector::CreateForTesting(base::ScopedFD(syslog_fds[0]),
                                                std::move(stub));
  ASSERT_TRUE(collector_);

  // Store the other end of the socket.
  syslog_socket_.reset(syslog_fds[1]);
}

void CollectorTest::TearDown() {
  // Do the opposite of SetUp to make sure things get cleaned up in the right
  // order.
  syslog_socket_.reset();
  collector_.reset();
  server_->Shutdown();
  server_.reset();
  server_thread_.Stop();
}

void CollectorTest::ServerStartCallback(base::OnceClosure quit,
                                        std::shared_ptr<grpc::Server> server) {
  server_.swap(server);
  std::move(quit).Run();
}

void CollectorTest::HandleUserLogs(
    std::unique_ptr<vm_tools::LogRequest> request) {
  CHECK(request);
  if (expected_user_requests_.size() == 0) {
    failed_ = true;
    failure_reason_ = "unexpected user logs";
    std::move(quit_).Run();
    return;
  }

  auto expected_request = std::move(expected_user_requests_.front());
  expected_user_requests_.pop_front();

  if (!message_differencer_->Compare(*expected_request, *request)) {
    failed_ = true;
    failure_reason_ = "mismatched user logs";
    std::move(quit_).Run();
    return;
  }

  if (expected_user_requests_.size() == 0) {
    std::move(quit_).Run();
  }
}

struct TestUserRecord {
  const char* buf;
  struct tm tm;
  vm_tools::LogSeverity severity;
  size_t content_offset;
};

}  // namespace

// Tests that the end-to-end flow works correctly.  We are not testing for
// poorly-formatted log recrods here because those are tested in the parser
// unittests.
TEST_F(CollectorTest, EndToEnd) {
  // Basic examples from RFC3164.
  const TestUserRecord user_tests[] = {
      {
          .buf = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for "
                 "lonvick on /dev/pts/8",
          // clang-format off
          .tm = {
              .tm_sec = 15,
              .tm_min = 14,
              .tm_hour = 22,
              .tm_mday = 11,
              .tm_mon = 9,
          },
          // clang-format on
          .severity = vm_tools::CRITICAL,
          .content_offset = 19,
      },
      {
          .buf = "<165>Aug 24 05:34:00 CST 1987 mymachine myproc[10]: %% It's "
                 "time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK "
                 "# Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # "
                 "Transport: Conveyer1=OK, Conveyer2=OK # %%",
          // clang-format off
          .tm = {
              .tm_sec = 00,
              .tm_min = 34,
              .tm_hour = 5,
              .tm_mday = 24,
              .tm_mon = 7,
          },
          // clang-format on
          .severity = vm_tools::NOTICE,
          .content_offset = 20,
      },
  };

  // Get the current local time so that we can set the year correctly.
  struct timespec ts;
  ASSERT_EQ(clock_gettime(CLOCK_REALTIME, &ts), 0);
  struct tm current_tm;
  ASSERT_TRUE(localtime_r(&ts.tv_sec, &current_tm));

  // Construct the expected user log protobuf.
  auto user_request = std::make_unique<vm_tools::LogRequest>();
  for (TestUserRecord test : user_tests) {
    vm_tools::LogRecord* record = user_request->add_records();
    record->set_severity(test.severity);
    test.tm.tm_year = current_tm.tm_year;
    test.tm.tm_isdst = current_tm.tm_isdst;
    record->mutable_timestamp()->set_seconds(timelocal(&test.tm));
    record->mutable_timestamp()->set_nanos(0);
    record->set_content(string(&test.buf[test.content_offset]));

    size_t buf_len = strlen(test.buf);
    ASSERT_EQ(send(syslog_socket_.get(), test.buf, buf_len, MSG_NOSIGNAL),
              buf_len);
  }
  expected_user_requests_.push_back(std::move(user_request));

  // Construct the MessageDifferencer.
  string differences;
  message_differencer_ = std::make_unique<pb::util::MessageDifferencer>();
  message_differencer_->ReportDifferencesToString(&differences);

  failed_ = false;

  // Now wait for things to go through.
  base::RunLoop run_loop;
  quit_ = run_loop.QuitClosure();

  run_loop.Run();

  EXPECT_FALSE(failed_) << "Failure reason: " << failure_reason_ << "\n"
                        << differences;
}

}  // namespace syslog
}  // namespace vm_tools
