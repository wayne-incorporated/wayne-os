// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_line_reader.h"

#include <iterator>
#include <string>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "gtest/gtest.h"

#include "croslog/file_map_reader.h"

namespace croslog {

namespace {

const char* kNormalLines[] = {"Lorem ipsum dolor sit amet, consectetur",
                              "adipiscing elit, sed do eiusmod tempor",
                              "incididunt ut labore et dolore magna aliqua.",
                              "Ut enim ad minim veniam, quis nostrud",
                              "exercitation ullamco laboris nisi ut aliquip ex",
                              "ea commodo consequat. Duis aute irure dolor in",
                              "reprehenderit in voluptate velit esse cillum",
                              "dolore eu fugiat nulla pariatur."};

const char* kIrregularLines[] = {
    "",
    "   Lorem ipsum dolor sit amet, consectetur",
    " adipiscing elit, sed do eiusmod tempor ",
    "",
    "",
    " incididunt ut labore et dolore magna aliqua."};

const char* kEmptyLines[] = {"", "", "", "", ""};

const char* kAppendingLines[][2] = {{"A", "A\n"},
                                    {"B", "A\nB\n"},
                                    {"C", "A\nB\nC\n"},
                                    {"D", "A\nB\nC\nD\n"},
                                    {"E", "A\nB\nC\nD\nE\n"}};

}  // anonymous namespace

class LogLineReaderTest : public ::testing::Test,
                          public LogLineReader::Observer {
 public:
  LogLineReaderTest() = default;
  LogLineReaderTest(const LogLineReaderTest&) = delete;
  LogLineReaderTest& operator=(const LogLineReaderTest&) = delete;

  void SetLogContentText(LogLineReader* reader, const char* text) {
    reader->OpenMemoryBufferForTest(text, strlen(text));
  }

  void OnFileChanged(LogLineReader* reader) override {
    changed_event_receieved_++;
  }
  int changed_event_receieved_ = 0;

  int changed_event_receieved() const { return changed_event_receieved_; }

  bool WaitForChangeEvent(int previous_value) {
    base::RunLoop().RunUntilIdle();

    constexpr base::TimeDelta kTinyTimeout = base::Milliseconds(100);
    int max_try = 50;
    while (previous_value == changed_event_receieved_) {
      base::PlatformThread::Sleep(kTinyTimeout);
      base::RunLoop().RunUntilIdle();
      max_try--;
      EXPECT_NE(0u, max_try);
      if (max_try == 0)
        return false;
    }
    return true;
  }
};

TEST_F(LogLineReaderTest, Forward) {
  {
    LogLineReader reader(LogLineReader::Backend::FILE);
    reader.OpenFile(base::FilePath("./testdata/TEST_NORMAL_LINES"));

    for (const auto& line : kNormalLines) {
      auto [s, result] = reader.Forward();
      EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
      EXPECT_EQ(line, s);
    }

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }

  {
    LogLineReader reader(LogLineReader::Backend::FILE);
    reader.OpenFile(base::FilePath("./testdata/TEST_IRREGULAR_LINES"));

    for (const auto& line : kIrregularLines) {
      auto [s, result] = reader.Forward();
      EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
      EXPECT_EQ(line, s);
    }

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }

  {
    LogLineReader reader(LogLineReader::Backend::FILE);
    reader.OpenFile(base::FilePath("./testdata/TEST_EMPTY_LINES"));

    for (const auto& line : kEmptyLines) {
      auto [s, result] = reader.Forward();
      EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
      EXPECT_EQ(line, s);
    }

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }

  {
    LogLineReader reader(LogLineReader::Backend::FILE);
    reader.OpenFile(base::FilePath("./testdata/TEST_EMPTY_FILE"));

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }
}

TEST_F(LogLineReaderTest, Backward) {
  {
    LogLineReader reader(LogLineReader::Backend::FILE);
    reader.OpenFile(base::FilePath("./testdata/TEST_NORMAL_LINES"));

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));

    reader.SetPositionLast();

    for (int i = std::size(kNormalLines) - 1; i >= 0; i--) {
      auto [s, result] = reader.Backward();
      EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
      EXPECT_EQ(kNormalLines[i], s);
    }

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
  }

  {
    LogLineReader reader(LogLineReader::Backend::FILE);
    reader.OpenFile(base::FilePath("./testdata/TEST_IRREGULAR_LINES"));

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));

    reader.SetPositionLast();

    for (int i = std::size(kIrregularLines) - 1; i >= 0; i--) {
      auto [s, result] = reader.Backward();
      EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
      EXPECT_EQ(kIrregularLines[i], s);
    }

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
  }

  {
    LogLineReader reader(LogLineReader::Backend::FILE);
    reader.OpenFile(base::FilePath("./testdata/TEST_EMPTY_LINES"));

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));

    reader.SetPositionLast();

    for (int i = std::size(kEmptyLines) - 1; i >= 0; i--) {
      auto [s, result] = reader.Backward();
      EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
      EXPECT_EQ(kEmptyLines[i], s);
    }

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
  }

  {
    LogLineReader reader(LogLineReader::Backend::FILE);
    reader.OpenFile(base::FilePath("./testdata/TEST_EMPTY_FILE"));

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));

    reader.SetPositionLast();

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Backward()));
  }
}

TEST_F(LogLineReaderTest, ForwardAndBackward) {
  LogLineReader reader(LogLineReader::Backend::FILE);
  reader.OpenFile(base::FilePath("./testdata/TEST_NORMAL_LINES"));

  for (const auto& line : kNormalLines) {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(line, s);
  }

  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));
  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));

  for (int i = std::size(kNormalLines) - 1; i >= 0; i--) {
    auto [s, result] = reader.Backward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(kNormalLines[i], s);
  }

  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Backward()));
  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Backward()));
}

TEST_F(LogLineReaderTest, AppendingLines) {
  LogLineReader reader(LogLineReader::Backend::MEMORY_FOR_TEST);
  reader.OpenMemoryBufferForTest("", 0);

  for (const auto& line : kAppendingLines) {
    const char* logFileContent = line[1];
    reader.OpenMemoryBufferForTest(logFileContent, strlen(logFileContent));

    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(line[0], s);

    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }
}

TEST_F(LogLineReaderTest, LastPosition) {
  LogLineReader reader(LogLineReader::Backend::MEMORY_FOR_TEST);

  SetLogContentText(&reader, "");
  reader.SetPositionLast();
  EXPECT_EQ(0u, reader.position());

  SetLogContentText(&reader, "A\nB\n");
  reader.SetPositionLast();
  EXPECT_EQ(4u, reader.position());

  SetLogContentText(&reader, "A\nB");
  reader.SetPositionLast();
  EXPECT_EQ(2u, reader.position());

  SetLogContentText(&reader, "A\n");
  reader.SetPositionLast();
  EXPECT_EQ(2u, reader.position());

  SetLogContentText(&reader, "\n");
  reader.SetPositionLast();
  EXPECT_EQ(1u, reader.position());
}

TEST_F(LogLineReaderTest, ReadEmptyFile) {
  base::FilePath temp_path;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path));
  ASSERT_FALSE(temp_path.empty());

  LogLineReader reader(LogLineReader::Backend::FILE);
  reader.OpenFile(temp_path);

  // Nothing to be read, since the file is empty.
  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));
  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));
}

TEST_F(LogLineReaderTest, ReadFileBeingWritten) {
  // This is not used explicitly but necessary for FileChange class.
  // base::MessageLoopForIO message_loop;

  base::FilePath temp_path;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path));
  ASSERT_FALSE(temp_path.empty());

  LogLineReader reader(LogLineReader::Backend::FILE_FOLLOW);
  reader.AddObserver(this);
  reader.OpenFile(temp_path);

  base::File file(temp_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  // Nothing to be read, since the file is empty.
  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));

  // Write and read
  {
    std::string test_string("TESTTEST");
    std::string test_string_with_lf = test_string + "\n";
    int previous_change_event_counter = changed_event_receieved();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string_with_lf.c_str(),
                                     test_string_with_lf.length()),
              test_string_with_lf.length());
    WaitForChangeEvent(previous_change_event_counter);

    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string, s);
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }

  // Write and read
  {
    std::string test_string("HOGEHOGE");
    std::string test_string_with_lf = test_string + "\n";
    int previous_change_event_counter = changed_event_receieved();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string_with_lf.c_str(),
                                     test_string_with_lf.length()),
              test_string_with_lf.length());
    WaitForChangeEvent(previous_change_event_counter);

    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string, s);
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }

  reader.RemoveObserver(this);
}

TEST_F(LogLineReaderTest, ReadFileRotated) {
  base::FilePath temp_path;
  base::FilePath temp_path2;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path));
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path2));

  LogLineReader reader(LogLineReader::Backend::FILE_FOLLOW);
  reader.AddObserver(this);
  reader.OpenFile(temp_path);

  base::File file(temp_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  // Nothing to be read, since the file is empty.
  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));

  // Write and read
  {
    std::string test_string1("TESTTEST");
    std::string test_string1_with_lf = test_string1 + "\n";
    int previous_change_event_counter = changed_event_receieved();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string1_with_lf.c_str(),
                                     test_string1_with_lf.length()),
              test_string1_with_lf.length());
    WaitForChangeEvent(previous_change_event_counter);

    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string1, s);
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }

  // Rotate
  {
    // Rename the old file.
    base::File::Error rename_error;
    int previous_change_event_counter = changed_event_receieved();
    ASSERT_TRUE(base::ReplaceFile(temp_path, temp_path2, &rename_error));
    WaitForChangeEvent(previous_change_event_counter);

    // Create a new file with the same file name.
    file = base::File(temp_path,
                      base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_WRITE);
    EXPECT_TRUE(file.IsValid());
    // Nothing to be read, since the new file is empty.
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }

  // Write and read
  {
    std::string test_string2("FUGAFUGA");
    std::string test_string2_with_lf = test_string2 + "\n";
    int previous_change_event_counter = changed_event_receieved();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string2_with_lf.c_str(),
                                     test_string2_with_lf.length()),
              test_string2_with_lf.length());
    WaitForChangeEvent(previous_change_event_counter);

    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string2, s);
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }
  reader.RemoveObserver(this);
}

TEST_F(LogLineReaderTest, ReadFileRotatedMisorder) {
  base::FilePath temp_path;
  base::FilePath temp_path2;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path));
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path2));

  std::string test_string1("TESTTEST");
  std::string test_string1_with_lf = test_string1 + "\n";
  std::string test_string2("FUGAFUGA");
  std::string test_string2_with_lf = test_string2 + "\n";

  LogLineReader reader(LogLineReader::Backend::FILE_FOLLOW);
  reader.AddObserver(this);
  reader.OpenFile(temp_path);

  base::File file(temp_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);

  // Write to the first file.
  {
    int previous_change_event_counter = changed_event_receieved();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string1_with_lf.c_str(),
                                     test_string1_with_lf.length()),
              test_string1_with_lf.length());
    WaitForChangeEvent(previous_change_event_counter);
  }

  // Rotate
  {
    base::File::Error rename_error;
    int previous_change_event_counter = changed_event_receieved();
    ASSERT_TRUE(base::ReplaceFile(temp_path, temp_path2, &rename_error));
    WaitForChangeEvent(previous_change_event_counter);

    file = base::File(temp_path,
                      base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_WRITE);
    EXPECT_TRUE(file.IsValid());
  }

  // Write to the second file.
  {
    int previous_change_event_counter = changed_event_receieved();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string2_with_lf.c_str(),
                                     test_string2_with_lf.length()),
              test_string2_with_lf.length());
    EXPECT_EQ(previous_change_event_counter, changed_event_receieved());
  }

  // First read, should be from the first file.
  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string1, s);
  }

  // First read, should be from the second file.
  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string2, s);
  }

  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));

  reader.RemoveObserver(this);
}

TEST_F(LogLineReaderTest, ReadFileRotatedWithoutLf) {
  base::FilePath temp_path;
  base::FilePath temp_path2;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path));
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path2));

  // The first file doesn't end with '\n' but the whole can be read since the
  // file is rotated to new file.
  std::string test_string1("TESTTEST");

  std::string test_string2("FUGAFUGA");
  std::string test_string2_with_lf = test_string2 + "\n";

  LogLineReader reader(LogLineReader::Backend::FILE_FOLLOW);
  reader.AddObserver(this);
  reader.OpenFile(temp_path);

  base::File file(temp_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);

  // Write to the first file.
  {
    int previous_change_event_counter = changed_event_receieved();
    EXPECT_EQ(
        file.WriteAtCurrentPos(test_string1.c_str(), test_string1.length()),
        test_string1.length());
    WaitForChangeEvent(previous_change_event_counter);
  }

  // Rotate
  {
    base::File::Error rename_error;
    int previous_change_event_counter = changed_event_receieved();
    ASSERT_TRUE(base::ReplaceFile(temp_path, temp_path2, &rename_error));
    WaitForChangeEvent(previous_change_event_counter);

    file = base::File(temp_path,
                      base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_WRITE);
    EXPECT_TRUE(file.IsValid());
  }

  // Write to the second file.
  {
    int previous_change_event_counter = changed_event_receieved();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string2_with_lf.c_str(),
                                     test_string2_with_lf.length()),
              test_string2_with_lf.length());
    EXPECT_EQ(previous_change_event_counter, changed_event_receieved());
  }

  // First read, should be from the first file.
  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string1, s);
  }

  // First read, should be from the second file.
  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string2, s);
  }

  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));

  reader.RemoveObserver(this);
}

TEST_F(LogLineReaderTest, ReadLarge) {
  LogLineReader::SetMaxLineLengthForTest(8 * 1024);
  FileMapReader::SetBlockSizesForTest(8 * 1024, 2);

  base::FilePath temp_path;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path));

  base::File file(temp_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);

  // Write
  for (int i = 0; i < (10 * 1024); i++) {
    std::string test_string = base::StringPrintf("%019d\n", i);
    EXPECT_EQ(file.WriteAtCurrentPos(test_string.c_str(), test_string.length()),
              test_string.length());
  }

  LogLineReader reader(LogLineReader::Backend::FILE_FOLLOW);
  reader.OpenFile(temp_path);

  // Read
  for (int i = 0; i < (10 * 1024); i++) {
    std::string test_string = base::StringPrintf("%019d", i);

    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string, s);
  }
  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));
}

TEST_F(LogLineReaderTest, ReadLargeAppend) {
  LogLineReader::SetMaxLineLengthForTest(8 * 1024);
  FileMapReader::SetBlockSizesForTest(8 * 1024, 2);

  base::FilePath temp_path;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path));

  LogLineReader reader(LogLineReader::Backend::FILE_FOLLOW);
  reader.AddObserver(this);
  reader.OpenFile(temp_path);

  base::File file(temp_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  // Nothing to be read, since the file is empty.
  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));

  // Write and read
  for (int i = 0; i < 10; i++) {
    // 2000 byte line including LF.
    std::string test_string = base::StringPrintf("%1999d", i);
    std::string test_string_with_lf = test_string + "\n";

    int previous_change_event_counter = changed_event_receieved();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string_with_lf.c_str(),
                                     test_string_with_lf.length()),
              test_string_with_lf.length());
    WaitForChangeEvent(previous_change_event_counter);

    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string, s);
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
              std::get<1>(reader.Forward()));
  }

  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Forward()));
  reader.RemoveObserver(this);
}

TEST_F(LogLineReaderTest, ReadLargeBackward) {
  LogLineReader::SetMaxLineLengthForTest(8 * 1024);
  FileMapReader::SetBlockSizesForTest(8 * 1024, 2);

  base::FilePath temp_path;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_path));

  base::File file(temp_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);

  // Write
  for (int i = 0; i < (10 * 1024); i++) {
    std::string test_string = base::StringPrintf("%019d\n", i);
    EXPECT_EQ(file.WriteAtCurrentPos(test_string.c_str(), test_string.length()),
              test_string.length());
  }

  LogLineReader reader(LogLineReader::Backend::FILE_FOLLOW);
  reader.OpenFile(temp_path);
  reader.SetPositionLast();

  // Read
  for (int i = 10 * 1024 - 1; i >= 0; i--) {
    std::string test_string = base::StringPrintf("%019d", i);

    auto [s, result] = reader.Backward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ(test_string, s);
  }
  EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS,
            std::get<1>(reader.Backward()));
}

TEST_F(LogLineReaderTest, ForwardAfterTruncationToEmpty) {
  LogLineReader reader(LogLineReader::Backend::MEMORY_FOR_TEST);
  const char* kInitialFileContent = "AAAA\nBBBB\n";
  reader.OpenMemoryBufferForTest(kInitialFileContent,
                                 strlen(kInitialFileContent));

  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ("AAAA", s);
  }

  reader.OpenMemoryBufferForTest("", 0);
  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::ERROR_FILE_TRUNCATED, result);
    EXPECT_TRUE(s.empty());
  }
}

TEST_F(LogLineReaderTest, BackwardAfterTruncationToEmpty) {
  LogLineReader reader(LogLineReader::Backend::MEMORY_FOR_TEST);
  const char* kInitialFileContent = "AAAA\nBBBB\n";
  reader.OpenMemoryBufferForTest(kInitialFileContent,
                                 strlen(kInitialFileContent));

  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ("AAAA", s);
  }

  reader.OpenMemoryBufferForTest("", 0);
  {
    auto [s, result] = reader.Backward();
    EXPECT_EQ(LogLineReader::ReadResult::ERROR_FILE_TRUNCATED, result);
    EXPECT_TRUE(s.empty());
  }
}

TEST_F(LogLineReaderTest, ForwardAfterTruncation) {
  LogLineReader reader(LogLineReader::Backend::MEMORY_FOR_TEST);
  const char* kInitialFileContent1 = "AAAA\nBBBB\n";
  reader.OpenMemoryBufferForTest(kInitialFileContent1,
                                 strlen(kInitialFileContent1));
  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ("AAAA", s);
  }

  const char* kInitialFileContent2 = "AAAA\n";
  reader.OpenMemoryBufferForTest(kInitialFileContent2,
                                 strlen(kInitialFileContent2));
  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_MORE_LOGS, result);
    EXPECT_TRUE(s.empty());
  }
}

TEST_F(LogLineReaderTest, BackwardAfterTruncation) {
  LogLineReader reader(LogLineReader::Backend::MEMORY_FOR_TEST);
  const char* kInitialFileContent1 = "AAAA\nBBBB\n";
  reader.OpenMemoryBufferForTest(kInitialFileContent1,
                                 strlen(kInitialFileContent1));

  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ("AAAA", s);
  }

  {
    auto [s, result] = reader.Forward();
    EXPECT_EQ(LogLineReader::ReadResult::NO_ERROR, result);
    EXPECT_EQ("BBBB", s);
  }

  const char* kInitialFileContent2 = "AAAA\n";
  reader.OpenMemoryBufferForTest(kInitialFileContent2,
                                 strlen(kInitialFileContent2));
  {
    auto [s, result] = reader.Backward();
    EXPECT_EQ(LogLineReader::ReadResult::ERROR_FILE_TRUNCATED, result);
    EXPECT_TRUE(s.empty());
  }
}

}  // namespace croslog
