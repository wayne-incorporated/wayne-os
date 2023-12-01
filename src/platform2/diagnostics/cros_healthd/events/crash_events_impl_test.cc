// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/crash_events.h"

#include <optional>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/strings/strcat.h>
#include <base/strings/string_piece.h>
#include <base/test/gmock_callback_support.h>
#include <base/test/repeating_test_future.h>
#include <base/test/task_environment.h>
#include <brillo/syslog_logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/events/mock_event_observer.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/system/mock_context.h"

namespace diagnostics {
namespace {

namespace mojom = ash::cros_healthd::mojom;
using ::testing::_;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::NiceMock;

constexpr uint64_t kInitOffset = 100u;

constexpr char kValidLogLine[] =
    R"TEXT({"path_hash":"a_local_id","capture_time":"9876543",)TEXT"
    R"TEXT("fatal_crash_type":"kernel","upload_id":"a_crash_report_id"})TEXT";

const auto kExpectedUnuploadedResultForValidLogLine =
    mojom::CrashEventInfo::New(
        /*crash_type=*/mojom::CrashEventInfo::CrashType::kKernel,
        /*local_id=*/"a_local_id",
        /*capture_time=*/base::Time::FromDoubleT(9876543.0),
        /*upload_info=*/nullptr);

const auto kExpectedUploadedResultForValidLogLine = mojom::CrashEventInfo::New(
    /*crash_type=*/mojom::CrashEventInfo::CrashType::kKernel,
    /*local_id=*/"a_local_id",
    /*capture_time=*/base::Time::FromDoubleT(9876543.0),
    /*upload_info=*/
    mojom::CrashUploadInfo::New(
        /*crash_report_id=*/"a_crash_report_id",
        /*creation_time=*/base::Time(),
        /*offset=*/0u));

constexpr char kUninterestingValidLogLine[] =
    R"TEXT({"path_hash":"other_local_id","capture_time":"2",)TEXT"
    R"TEXT("upload_id":"other_crash_report_id"})TEXT";

constexpr char kInvalidLogLine[] = "{{{{";

// Tests parsing each valid field outside upload_info.
class UploadsLogParserValidFieldTest : public ::testing::TestWithParam<bool> {
 protected:
  bool is_uploaded() { return GetParam(); }
};

TEST_P(UploadsLogParserValidFieldTest, ParseLocalID) {
  const auto result = ParseUploadsLog(
      R"TEXT({"path_hash":"some_hash0","capture_time":"2",)TEXT"
      R"TEXT("fatal_crash_type":"kernel","upload_id":"abc"})TEXT"
      "\n"
      R"TEXT({"path_hash":"some_hash1","capture_time":"2",)TEXT"
      R"TEXT("fatal_crash_type":"kernel","upload_id":"abc"})TEXT",
      /*is_uploaded=*/is_uploaded(),
      /*creation_time=*/base::Time(),
      /*init_offset=*/0u);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_EQ(result[0]->local_id, "some_hash0");
  EXPECT_EQ(result[1]->local_id, "some_hash1");
}

TEST_P(UploadsLogParserValidFieldTest, ParseCaptureTime) {
  const auto result = ParseUploadsLog(
      R"TEXT({"path_hash":"some_hash","capture_time":"10",)TEXT"
      R"TEXT("fatal_crash_type":"kernel","upload_id":"abc"})TEXT"
      "\n"
      R"TEXT({"path_hash":"some_hash","capture_time":"100",)TEXT"
      R"TEXT("fatal_crash_type":"kernel","upload_id":"abc"})TEXT",
      /*is_uploaded=*/is_uploaded(),
      /*creation_time=*/base::Time(),
      /*init_offset=*/0u);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_EQ(result[0]->capture_time, base::Time::FromDoubleT(10.0));
  EXPECT_EQ(result[1]->capture_time, base::Time::FromDoubleT(100.0));
}

TEST_P(UploadsLogParserValidFieldTest, ParseCrashType) {
  const auto result = ParseUploadsLog(
      R"TEXT({"path_hash":"some_hash","capture_time":"2",)TEXT"
      R"TEXT("fatal_crash_type":"kernel","upload_id":"abc"})TEXT"
      "\n"
      R"TEXT({"path_hash":"some_hash","capture_time":"2",)TEXT"
      R"TEXT("fatal_crash_type":"ec","upload_id":"abc"})TEXT"
      "\n"
      R"TEXT({"path_hash":"some_hash","capture_time":"2",)TEXT"
      R"TEXT("fatal_crash_type":"some_unknown_value","upload_id":"abc"})TEXT"
      "\n"
      // fatal_crash_type is missing
      R"TEXT({"path_hash":"some_hash","capture_time":"2",)TEXT"
      R"TEXT("upload_id":"abc"})TEXT",
      /*is_uploaded=*/is_uploaded(),
      /*creation_time=*/base::Time(),
      /*init_offset=*/0u);
  ASSERT_EQ(result.size(), 4u);
  EXPECT_EQ(result[0]->crash_type, mojom::CrashEventInfo::CrashType::kKernel);
  EXPECT_EQ(result[1]->crash_type,
            mojom::CrashEventInfo::CrashType::kEmbeddedController);
  EXPECT_EQ(result[2]->crash_type, mojom::CrashEventInfo::CrashType::kUnknown);
  EXPECT_EQ(result[3]->crash_type, mojom::CrashEventInfo::CrashType::kUnknown);
}

INSTANTIATE_TEST_SUITE_P(VaryingIsUploaded,
                         UploadsLogParserValidFieldTest,
                         testing::Bool(),
                         [](const ::testing::TestParamInfo<
                             UploadsLogParserValidFieldTest::ParamType>& info) {
                           return info.param ? "uploaded" : "unuploaded";
                         });

// Tests fields inside upload_info

TEST(UploadsLogParserTest, ParseValidUnuploaded) {
  const auto result = ParseUploadsLog(
      // With upload_id
      R"TEXT({"path_hash":"some_hash","capture_time":"2",)TEXT"
      R"TEXT("fatal_crash_type":"kernel","upload_id":"abc"})TEXT"
      "\n"
      // Missing upload_id
      R"TEXT({"path_hash":"some_hash","capture_time":"2",)TEXT"
      R"TEXT("fatal_crash_type":"kernel"})TEXT",
      /*is_uploaded=*/false,
      /*creation_time=*/base::Time(),
      /*init_offset=*/0u);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_TRUE(result[0]->upload_info.is_null());
  EXPECT_TRUE(result[1]->upload_info.is_null());
}

TEST(UploadsLogParserTest, ParseUploadedValidCrashReportID) {
  const auto result = ParseUploadsLog(
      R"TEXT({"path_hash":"some_hash","capture_time":"2",)TEXT"
      R"TEXT("fatal_crash_type":"kernel","upload_id":"abc"})TEXT"
      "\n"
      R"TEXT({"path_hash":"some_hash","capture_time":"2",)TEXT"
      R"TEXT("fatal_crash_type":"kernel","upload_id":"de"})TEXT",
      /*is_uploaded=*/true,
      /*creation_time=*/base::Time(),
      /*init_offset=*/0u);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_EQ(result[0]->upload_info->crash_report_id, "abc");
  EXPECT_EQ(result[1]->upload_info->crash_report_id, "de");
}

TEST(UploadsLogParserTest, ParseOffsetWithValidLinesOnly) {
  std::ostringstream stream;
  stream << kValidLogLine << "\n";
  stream << kValidLogLine << "\n";
  const auto result = ParseUploadsLog(stream.str(), /*is_uploaded=*/true,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/kInitOffset);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_EQ(result[0]->upload_info->offset, kInitOffset + 0u);
  EXPECT_EQ(result[1]->upload_info->offset, kInitOffset + 1u);
}

TEST(UploadsLogParserTest, ParseOffsetWithInvalidLine) {
  std::ostringstream stream;
  stream << kValidLogLine << "\n";
  stream << kInvalidLogLine << "\n";
  stream << kValidLogLine << "\n";
  const auto result = ParseUploadsLog(stream.str(), /*is_uploaded=*/true,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/kInitOffset);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_EQ(result[0]->upload_info->offset, kInitOffset + 0u);
  EXPECT_EQ(result[1]->upload_info->offset, kInitOffset + 1u);
}

TEST(UploadsLogParserTest, ParseOffsetWithBlankLine) {
  std::ostringstream stream;
  stream << kValidLogLine << "\n";
  stream << "\n";  // blank line
  stream << kValidLogLine << "\n";
  const auto result = ParseUploadsLog(stream.str(), /*is_uploaded=*/true,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/kInitOffset);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_EQ(result[0]->upload_info->offset, kInitOffset + 0u);
  EXPECT_EQ(result[1]->upload_info->offset, kInitOffset + 1u);
}

TEST(UploadsLogParserTest, PassThroughCreationTime) {
  static constexpr base::Time kCreationTime = base::Time::FromTimeT(300);
  std::ostringstream stream;
  stream << kValidLogLine << "\n";
  stream << kValidLogLine << "\n";
  const auto result = ParseUploadsLog(stream.str(), /*is_uploaded=*/true,
                                      /*creation_time=*/kCreationTime,
                                      /*init_offset=*/kInitOffset);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_EQ(result[0]->upload_info->creation_time, kCreationTime);
  EXPECT_EQ(result[1]->upload_info->creation_time, kCreationTime);
}

TEST(UploadsLogParserTest, CalcParsedBytesWithValidLineEnding) {
  uint64_t parsed_bytes;
  std::ostringstream stream;
  stream << kValidLogLine << "\n";
  stream << kValidLogLine;
  const auto input = stream.str();
  const auto result = ParseUploadsLog(input, /*is_uploaded=*/true,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/kInitOffset,
                                      /*parsed_bytes=*/&parsed_bytes);
  EXPECT_EQ(parsed_bytes, input.size());
}

TEST(UploadsLogParserTest, CalcParsedBytesWithInvalidLineEnding) {
  uint64_t parsed_bytes;
  std::ostringstream stream;
  stream << kValidLogLine << "\n";
  stream << kInvalidLogLine;
  const auto result = ParseUploadsLog(stream.str(), /*is_uploaded=*/true,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/kInitOffset,
                                      /*parsed_bytes=*/&parsed_bytes);
  EXPECT_EQ(parsed_bytes, base::StrCat({kValidLogLine, "\n"}).size());
}

TEST(UploadsLogParserTest, CalcParsedBytesWithWhitespaceEnding) {
  uint64_t parsed_bytes;
  std::ostringstream stream;
  stream << kValidLogLine << "\n";
  stream << kInvalidLogLine << "\n";
  const auto input = stream.str();
  const auto result = ParseUploadsLog(input, /*is_uploaded=*/true,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/kInitOffset,
                                      /*parsed_bytes=*/&parsed_bytes);
  EXPECT_EQ(parsed_bytes, input.size());
}

TEST(UploadsLogParserTest, MultipleDelimitersLogLineBreaksCorrectly) {
  constexpr char kWhitespaces[] = {' ', '\n', '\t', '\r', '\f'};
  std::ostringstream stream;
  for (const auto delimiter : kWhitespaces) {
    stream << kValidLogLine << delimiter;
  }
  const auto result = ParseUploadsLog(stream.str(), /*is_uploaded=*/true,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/kInitOffset);
  EXPECT_EQ(result.size(), std::size(kWhitespaces));
}

// Tests invalid or blank lines.
class UploadsLogParserInvalidTest
    : public ::testing::TestWithParam<
          std::tuple<std::string, std::string, std::string>> {
 protected:
  void SetUp() override { brillo::LogToString(true); }
  void TearDown() override { brillo::LogToString(false); }

  const std::string& invalid_log_line() { return std::get<1>(GetParam()); }

  const std::string& expected_log_string() { return std::get<2>(GetParam()); }
};

TEST_P(UploadsLogParserInvalidTest, ParseOneInvalid) {
  brillo::ClearLog();
  const auto result = ParseUploadsLog(invalid_log_line(), /*is_uploaded=*/true,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/0u);
  EXPECT_THAT(brillo::GetLog(), HasSubstr(expected_log_string()))
      << "Log does not contain target string: " << brillo::GetLog();
  EXPECT_EQ(result.size(), 0u);
}

TEST_P(UploadsLogParserInvalidTest, ParseOneInvalidFollowingOneValid) {
  std::stringstream stream;
  stream << kValidLogLine << '\n';
  stream << invalid_log_line();
  const auto result = ParseUploadsLog(stream.str(), /*is_uploaded=*/true,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/0u);
  ASSERT_EQ(result.size(), 1u);
  EXPECT_TRUE(result[0].Equals(kExpectedUploadedResultForValidLogLine));
}

INSTANTIATE_TEST_SUITE_P(
    VaryingInvalidLines,
    UploadsLogParserInvalidTest,
    testing::ValuesIn(std::vector<
                      std::tuple<std::string, std::string, std::string>>{
        {"InvalidJSON", "{", "Invalid JSON in crash uploads log"},
        {"MissingLocalID", R"TEXT({"capture_time":"2","upload_id":"abc"})TEXT",
         "Local ID not found"},
        {"MissingCaptureTime",
         R"TEXT({"path_hash":"some_hash","upload_id":"abc"})TEXT",
         "Capture time not found"},
        {"InvalidCaptureTime",
         R"T({"path_hash":"some_hash","upload_id":"abc","capture_time":"ab"})T",
         "Invalid capture time"},
        {"MissingCrashReportIDWithUploaded",
         R"TEXT({"capture_time":"2","path_hash":"some_hash"})TEXT",
         "Crash report ID is not found while the crash has been uploaded"},
        {"BlankLine", "", ""}}),
    [](const ::testing::TestParamInfo<UploadsLogParserInvalidTest::ParamType>&
           info) { return std::get<0>(info.param); });

// Tests valid lines when there are invalid lines. Focuses on varying the
// relative locations of valid lines and invalid lines. The relativity of the
// locations are lightly tested but are helpful in case there are bugs caused by
// the change in the line-by-line nature of the parser in the future.

TEST(UploadsLogParserTest, ParseTwoSeparateValidLines) {
  std::ostringstream stream;
  stream << kValidLogLine << "\n";
  stream << kInvalidLogLine << "\n";
  stream << kValidLogLine << "\n";
  const auto result = ParseUploadsLog(stream.str(), /*is_uploaded=*/false,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/0u);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_TRUE(result[0].Equals(kExpectedUnuploadedResultForValidLogLine));
  EXPECT_TRUE(result[1].Equals(kExpectedUnuploadedResultForValidLogLine));
}

TEST(UploadsLogParserTest, ParseTwoTrailingValidLinesWithBlank) {
  std::ostringstream stream;
  stream << kInvalidLogLine << "\n";
  stream << "\n";  // Blank line
  stream << kValidLogLine << "\n";
  stream << kValidLogLine << "\n";
  const auto result = ParseUploadsLog(stream.str(), /*is_uploaded=*/false,
                                      /*creation_time=*/base::Time(),
                                      /*init_offset=*/0u);
  ASSERT_EQ(result.size(), 2u);
  EXPECT_TRUE(result[0].Equals(kExpectedUnuploadedResultForValidLogLine));
  EXPECT_TRUE(result[1].Equals(kExpectedUnuploadedResultForValidLogLine));
}

// Tests for the CrashEvents class.
class CrashEventsTest : public testing::Test {
 protected:
  CrashEventsTest() = default;
  CrashEventsTest(const CrashEventsTest&) = delete;
  CrashEventsTest& operator=(const CrashEventsTest&) = delete;

  void SetUp() override {
    mojo::PendingReceiver<mojom::EventObserver> observer_receiver(
        remote_observer_.InitWithNewPipeAndPassReceiver());
    observer_ = std::make_unique<NiceMock<MockEventObserver>>(
        std::move(observer_receiver));
    ON_CALL(*mock_observer(), OnEvent(_))
        .WillByDefault([this](mojom::EventInfoPtr info) {
          this->received_events_.AddValue(std::move(info));
        });
  }

  // Adds an observer of our interest.
  void AddObserver() { crash_events_.AddObserver(std::move(remote_observer_)); }

  // Adds an observer that we are not interested in checking.
  void AddUninterestingObserver() {
    mojo::PendingRemote<mojom::EventObserver> remote_observer;
    mojo::PendingReceiver<mojom::EventObserver> observer_receiver(
        remote_observer.InitWithNewPipeAndPassReceiver());
    uninteresting_observer_ = std::make_unique<NiceMock<MockEventObserver>>(
        std::move(observer_receiver));
    crash_events_.AddObserver(std::move(remote_observer));
  }

  // Advances the clock by one period.
  void AdvanceClockByOnePeriod() {
    task_environment_.FastForwardBy(base::Minutes(20));
  }

  // Sets mock executor's normal crash sender execution response.
  void SetExecutorCrashSenderNormalResponse(std::string out) {
    auto response = mojom::ExecutedProcessResult::New();
    response->return_code = EXIT_SUCCESS;
    response->out = std::move(out);
    EXPECT_CALL(*mock_executor(), FetchCrashFromCrashSender(_))
        .WillOnce(base::test::RunOnceCallback<0>(std::move(response)));
  }

  // Sets mock executor's empty crash sender execution response.
  void SetExecutorCrashSenderEmptyResponse() {
    SetExecutorCrashSenderNormalResponse("");
  }

  // Sets mock executor's failure crash sender execution response.
  void SetExecutorCrashSenderFailureResponse() {
    auto response = mojom::ExecutedProcessResult::New();
    response->return_code = 1;
    EXPECT_CALL(*mock_executor(), FetchCrashFromCrashSender(_))
        .WillOnce(base::test::RunOnceCallback<0>(std::move(response)));
  }

  // Sets mock executor's reading and getting info from uploads.log.
  // |uploads_log| is the content of uploads.log to mock. If |begin| is larger
  // than the size of |uploads_log|, file reading returns std::nullopt.
  void SetExecutorFileNormalResponse(base::StringPiece uploads_log,
                                     uint64_t begin = 0u,
                                     base::Time creation_time = base::Time()) {
    EXPECT_CALL(*mock_executor(), ReadFilePart(mojom::Executor::File::kCrashLog,
                                               begin, Eq(std::nullopt), _))
        .WillOnce(base::test::RunOnceCallback<3>(
            (begin < uploads_log.size())
                ? std::optional<std::string>(uploads_log.substr(begin))
                : std::nullopt));

    SetExecutorGetFileInfoResponse(
        mojom::FileInfo::New(/*creation_time=*/creation_time));
  }

  // Sets mock executor's reading empty content from uploads.log.
  void SetExecutorFileEmptyResponse() {
    EXPECT_CALL(*mock_executor(), ReadFilePart(mojom::Executor::File::kCrashLog,
                                               _, Eq(std::nullopt), _))
        .WillOnce(base::test::RunOnceCallback<3>(std::string()));

    SetExecutorGetFileInfoResponse(
        mojom::FileInfo::New(/*creation_time=*/base::Time()));
  }

  // Sets mock executor's failure of getting file info from uploads.log.
  void SetExecutorFileFailureResponse() {
    SetExecutorGetFileInfoResponse(nullptr);
  }

  // Expects the received event.
  void ExpectReceivedEvent(const mojom::CrashEventInfoPtr& expected_result) {
    auto received_info = WaitForReceivedEvent();
    ASSERT_TRUE(received_info->is_crash_event_info())
        << "Received info is not crash info.";
    const auto& crash_event_info = received_info->get_crash_event_info();
    EXPECT_TRUE(crash_event_info.Equals(expected_result))
        << "Received crash info does not equal the expected result.";
  }

  // Skips an uninteresting event.
  void SkipEvent() { WaitForReceivedEvent(); }

  // Expects no event.
  void ExpectNoEvent() { EXPECT_CALL(*mock_observer(), OnEvent(_)).Times(0); }

  // Waits for the next received event.
  mojom::EventInfoPtr WaitForReceivedEvent() { return received_events_.Take(); }

  MockEventObserver* mock_observer() { return observer_.get(); }
  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

 private:
  // Sets mock executor's response of |GetFileInfo|.
  void SetExecutorGetFileInfoResponse(mojom::FileInfoPtr response) {
    EXPECT_CALL(*mock_executor(),
                GetFileInfo(mojom::Executor::File::kCrashLog, _))
        .WillOnce(base::test::RunOnceCallback<1>(std::move(response)));
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  MockContext mock_context_;
  CrashEvents crash_events_{&mock_context_};
  // Because we don't always EXPECT_CALL `OnEvent` and we need to modify the
  // behavior of `OnEvent` with `ON_CALL`, we use `NiceMock` here to suppress
  // uninteresting warnings.
  std::unique_ptr<NiceMock<MockEventObserver>> observer_;
  // Although we are uninterested in this observer, we still need to keep it in
  // memory to keep the observer alive.
  std::unique_ptr<NiceMock<MockEventObserver>> uninteresting_observer_;
  mojo::PendingRemote<mojom::EventObserver> remote_observer_;
  base::test::RepeatingTestFuture<mojom::EventInfoPtr> received_events_;
};

TEST_F(CrashEventsTest, PeriodicUnuploadedEvents) {
  AddObserver();
  SetExecutorCrashSenderNormalResponse(kValidLogLine);
  SetExecutorFileEmptyResponse();
  AdvanceClockByOnePeriod();
  ExpectReceivedEvent(kExpectedUnuploadedResultForValidLogLine);
}

TEST_F(CrashEventsTest, PeriodicUploadedEvents) {
  AddObserver();
  SetExecutorCrashSenderEmptyResponse();
  SetExecutorFileNormalResponse(kValidLogLine);
  AdvanceClockByOnePeriod();
  ExpectReceivedEvent(kExpectedUploadedResultForValidLogLine);
}

TEST_F(CrashEventsTest, PeriodicUnuploadedEventsIfUploadedFails) {
  AddObserver();
  SetExecutorCrashSenderNormalResponse(kValidLogLine);
  SetExecutorFileFailureResponse();
  AdvanceClockByOnePeriod();
  ExpectReceivedEvent(kExpectedUnuploadedResultForValidLogLine);
}

TEST_F(CrashEventsTest, PeriodicUploadedEventsIfUnuploadedFails) {
  AddObserver();
  SetExecutorCrashSenderFailureResponse();
  SetExecutorFileNormalResponse(kValidLogLine);
  AdvanceClockByOnePeriod();
  ExpectReceivedEvent(kExpectedUploadedResultForValidLogLine);
}

TEST_F(CrashEventsTest, PeriodicUnuploadedBeforeUploadedEvents) {
  AddObserver();
  SetExecutorCrashSenderNormalResponse(kValidLogLine);
  SetExecutorFileNormalResponse(kValidLogLine);
  AdvanceClockByOnePeriod();
  ExpectReceivedEvent(kExpectedUnuploadedResultForValidLogLine);
  ExpectReceivedEvent(kExpectedUploadedResultForValidLogLine);
}

TEST_F(CrashEventsTest, PeriodicUnuploadedNoDuplicate) {
  AddObserver();
  SetExecutorCrashSenderNormalResponse(kValidLogLine);
  SetExecutorFileEmptyResponse();
  AdvanceClockByOnePeriod();
  SkipEvent();  // The first event, skip it as it is not interesting here.

  // Second time, shouldn't receive the same event again.
  SetExecutorCrashSenderNormalResponse(kValidLogLine);
  SetExecutorFileEmptyResponse();
  ExpectNoEvent();
  AdvanceClockByOnePeriod();
}

TEST_F(CrashEventsTest, PeriodicUnuploadedSecondDifferentEvent) {
  AddObserver();
  SetExecutorCrashSenderNormalResponse(kUninterestingValidLogLine);
  SetExecutorFileEmptyResponse();
  AdvanceClockByOnePeriod();
  SkipEvent();  // The first event, skip it as it is not interesting here.

  // Second time a different additional event is returned. Shouldn't receive the
  // same event again, but the second event must be received.
  SetExecutorCrashSenderNormalResponse(kValidLogLine);
  SetExecutorFileEmptyResponse();
  AdvanceClockByOnePeriod();
  ExpectReceivedEvent(kExpectedUnuploadedResultForValidLogLine);
}

TEST_F(CrashEventsTest, PeriodicUploadedSecondTimeNewEvent) {
  AddObserver();
  SetExecutorFileNormalResponse(kUninterestingValidLogLine);
  SetExecutorCrashSenderEmptyResponse();
  AdvanceClockByOnePeriod();
  SkipEvent();  // The first event, skip it as it is not interesting here.

  // Second time, should only receive the second event.
  SetExecutorFileNormalResponse(
      base::StrCat({kUninterestingValidLogLine, "\n", kValidLogLine}),
      /*begin=*/base::StringPiece(kUninterestingValidLogLine).size());
  SetExecutorCrashSenderEmptyResponse();
  AdvanceClockByOnePeriod();
  auto expected_result = kExpectedUploadedResultForValidLogLine.Clone();
  expected_result->upload_info->offset = 1;
  ExpectReceivedEvent(expected_result);
}

TEST_F(CrashEventsTest, PeriodicUploadedSecondTimeNoNewEvent) {
  AddObserver();
  SetExecutorFileNormalResponse(kUninterestingValidLogLine);
  SetExecutorCrashSenderEmptyResponse();
  AdvanceClockByOnePeriod();
  SkipEvent();  // The first event, skip it as it is not interesting here.

  // Second time, should receive no event.
  SetExecutorFileNormalResponse(
      kUninterestingValidLogLine,
      /*begin=*/base::StringPiece(kUninterestingValidLogLine).size());
  SetExecutorCrashSenderEmptyResponse();
  ExpectNoEvent();
  AdvanceClockByOnePeriod();
}

TEST_F(CrashEventsTest, PeriodicUploadedSecondTimeAbnormallyShortUploadsLog) {
  AddObserver();
  SetExecutorFileNormalResponse(kUninterestingValidLogLine);
  SetExecutorCrashSenderEmptyResponse();
  AdvanceClockByOnePeriod();
  SkipEvent();  // The first event, skip it as it is not interesting here.

  // Second time, should receive no event. The system should continue working as
  // normal.
  SetExecutorFileNormalResponse(
      base::StringPiece(kUninterestingValidLogLine)
          .substr(0u, std::size(kUninterestingValidLogLine) / 2),
      /*begin=*/base::StringPiece(kUninterestingValidLogLine).size());
  SetExecutorCrashSenderEmptyResponse();
  ExpectNoEvent();
  AdvanceClockByOnePeriod();
}

// When the first time uploads.log contains an incomplete final line, it should
// be parsed second time when it becomes complete.
TEST_F(CrashEventsTest, PeriodicUploadedFirstTimePartialLineSecondTimeParsed) {
  const std::string kCompleteUploadsLog =
      base::StrCat({kUninterestingValidLogLine, "\n", kValidLogLine});
  AddObserver();
  SetExecutorFileNormalResponse(kCompleteUploadsLog.substr(
      0u, kCompleteUploadsLog.size() - std::size(kValidLogLine) / 2));
  SetExecutorCrashSenderEmptyResponse();
  AdvanceClockByOnePeriod();
  SkipEvent();  // The first event, skip it as it is not interesting here.

  // Second time, should receive the second event.
  SetExecutorFileNormalResponse(
      kCompleteUploadsLog,
      /*begin=*/base::StrCat({kUninterestingValidLogLine, "\n"}).size());
  SetExecutorCrashSenderEmptyResponse();
  AdvanceClockByOnePeriod();
  auto expected_result = kExpectedUploadedResultForValidLogLine.Clone();
  expected_result->upload_info->offset = 1;
  ExpectReceivedEvent(expected_result);
}

// Tests when uploads.log is recreated. Parameterize this test to make sure both
// later and earlier creation time are treated the same. See the comment block
// "Why do we not check that creation_time is later than the current?"
class CrashEventsUploadsLogRecreatedTest
    : public CrashEventsTest,
      public ::testing::WithParamInterface<base::Time> {
 public:
  static constexpr auto kCurrentCreationTime = base::Time::FromTimeT(2);

 protected:
  base::Time creation_time() { return GetParam(); }
};

TEST_P(CrashEventsUploadsLogRecreatedTest, PeriodicUploaded) {
  AddObserver();
  SetExecutorFileNormalResponse(kValidLogLine, /*begin=*/0u,
                                /*creation_time=*/kCurrentCreationTime);
  SetExecutorCrashSenderEmptyResponse();
  AdvanceClockByOnePeriod();
  SkipEvent();  // The first event, skip it as it is not interesting here.

  // Uploads.log recreated, should receive the same event.
  SetExecutorFileNormalResponse(kValidLogLine, /*begin=*/0u,
                                /*creation_time=*/creation_time());
  SetExecutorCrashSenderEmptyResponse();
  AdvanceClockByOnePeriod();
  auto expected_result = kExpectedUploadedResultForValidLogLine.Clone();
  expected_result->upload_info->creation_time = creation_time();
  ExpectReceivedEvent(expected_result);
}

INSTANTIATE_TEST_SUITE_P(
    VaryingCreationTime,
    CrashEventsUploadsLogRecreatedTest,
    testing::Values(CrashEventsUploadsLogRecreatedTest::kCurrentCreationTime -
                        base::Seconds(1),
                    CrashEventsUploadsLogRecreatedTest::kCurrentCreationTime +
                        base::Seconds(1)));

TEST_F(CrashEventsTest, UponSubscriptionUploadedEvents) {
  // Get one uploaded event in the history and then add the observer of
  // interest.
  AddUninterestingObserver();
  SetExecutorCrashSenderEmptyResponse();
  SetExecutorFileNormalResponse(kValidLogLine);
  AdvanceClockByOnePeriod();
  SetExecutorCrashSenderEmptyResponse();
  SetExecutorFileEmptyResponse();
  AddObserver();

  // Should receive this event in the history upon subscription.
  ExpectReceivedEvent(kExpectedUploadedResultForValidLogLine);
}

TEST_F(CrashEventsTest, UponSubscriptionUnuploadedEvents) {
  // Get one unuploaded event in the history and then add the observer of
  // interest.
  AddUninterestingObserver();
  SetExecutorCrashSenderNormalResponse(kValidLogLine);
  AdvanceClockByOnePeriod();
  SetExecutorCrashSenderEmptyResponse();
  SetExecutorFileEmptyResponse();
  AddObserver();

  // Should receive this event in the history upon subscription.
  ExpectReceivedEvent(kExpectedUnuploadedResultForValidLogLine);
}

TEST_F(CrashEventsTest, UponSubscriptionUnuploadedBeforeUploadedEvents) {
  // Get one unuploaded event in the history and then add the observer of
  // interest.
  AddUninterestingObserver();
  SetExecutorCrashSenderNormalResponse(kValidLogLine);
  SetExecutorFileNormalResponse(kValidLogLine);
  AdvanceClockByOnePeriod();
  SetExecutorCrashSenderEmptyResponse();
  SetExecutorFileEmptyResponse();
  AddObserver();

  // Should receive these events in the history upon subscription.
  ExpectReceivedEvent(kExpectedUnuploadedResultForValidLogLine);
  ExpectReceivedEvent(kExpectedUploadedResultForValidLogLine);
}
}  // namespace
}  // namespace diagnostics
