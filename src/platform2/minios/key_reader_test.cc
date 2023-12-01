// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "minios/key_reader.h"

using testing::_;

namespace minios {

class KeyReaderTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_root_ = temp_dir_.GetPath();
    ASSERT_TRUE(base::CreateDirectory(
        base::FilePath(test_root_).Append("usr/share/misc")));
    ev_.value = 0;
  }
  struct input_event ev_;
  // Test directory.
  base::ScopedTempDir temp_dir_;
  base::FilePath test_root_;
};

class MockKeyReader : public KeyReader {
 public:
  MockKeyReader() : KeyReader(true) {}
  explicit MockKeyReader(bool include_usb) : KeyReader(include_usb) {}
  MockKeyReader(bool include_usb, std::string country_code)
      : KeyReader(include_usb, country_code) {}
  MOCK_METHOD(bool, GetEpEvent, (int epfd, struct input_event* ev, int* index));
  MOCK_METHOD(bool, GetValidFds, (bool check_supported_keys));
  MOCK_METHOD(bool, EpollCreate, (base::ScopedFD * epfd));
};

class MockDelegate : public KeyReader::Delegate {
 public:
  MOCK_METHOD(void, OnKeyPress, (int, int, bool));
};

TEST_F(KeyReaderTest, BasicKeyTest) {
  KeyReader key_reader(true, "us");
  EXPECT_TRUE(key_reader.SetKeyboardContext());
  // Test Basic Numbers.
  ev_.code = 2;
  key_reader.GetCharForTest(ev_);

  ev_.code = 4;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13", key_reader.GetUserInputForTest());

  // Test capitalization and special characters.
  // Left shift key down.
  ev_.code = 42;
  ev_.value = 1;
  key_reader.GetCharForTest(ev_);

  ev_.code = 16;
  ev_.value = 0;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13Q", key_reader.GetUserInputForTest());

  ev_.code = 17;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13QW", key_reader.GetUserInputForTest());

  ev_.code = 3;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13QW@", key_reader.GetUserInputForTest());

  // Left shit key release.
  ev_.code = 42;
  ev_.value = 0;
  key_reader.GetCharForTest(ev_);

  // No longer capitalized or special.
  ev_.code = 18;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13QW@e", key_reader.GetUserInputForTest());

  ev_.code = 3;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13QW@e2", key_reader.GetUserInputForTest());
}

TEST_F(KeyReaderTest, PrintableKeyTest) {
  KeyReader key_reader(true, "us");
  EXPECT_TRUE(key_reader.SetKeyboardContext());

  ev_.code = 2;
  key_reader.GetCharForTest(ev_);

  ev_.code = 4;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13", key_reader.GetUserInputForTest());

  // Non-alphanumeric keys should not affect input length.
  // Left Shift.
  ev_.code = 42;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13", key_reader.GetUserInputForTest());

  // Escape.
  ev_.code = 1;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13", key_reader.GetUserInputForTest());

  // Left Alt.
  ev_.code = 56;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13", key_reader.GetUserInputForTest());

  // Tab.
  ev_.code = 15;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13", key_reader.GetUserInputForTest());

  // Ctrl.
  ev_.code = 29;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("13", key_reader.GetUserInputForTest());

  // Continue taking in input.
  ev_.code = 3;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("132", key_reader.GetUserInputForTest());

  // Space bar.
  ev_.code = 57;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("132 ", key_reader.GetUserInputForTest());
}

TEST_F(KeyReaderTest, InputLengthTest) {
  KeyReader key_reader(true, "us");
  EXPECT_TRUE(key_reader.SetKeyboardContext());

  // Add max input chars.
  ev_.code = 52;
  for (int i = 0; i < kMaxInputLength; i++) {
    key_reader.GetCharForTest(ev_);
  }

  EXPECT_EQ(std::string(kMaxInputLength, '.'),
            key_reader.GetUserInputForTest());

  // Cannot add past kMaxInputLength.
  ev_.code = 3;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ(std::string(kMaxInputLength, '.'),
            key_reader.GetUserInputForTest());

  // Test backspace. individual key press.
  ev_.code = 14;
  for (int i = 0; i < 20; i++) {
    key_reader.GetCharForTest(ev_);
  }

  EXPECT_EQ(std::string(kMaxInputLength - 20, '.'),
            key_reader.GetUserInputForTest());

  // Back space repeated keypress.
  // Stop deleting when string empty.
  ev_.value = 2;
  int remaining_chars = kRepeatedSensitivity * (kMaxInputLength - 20);
  for (int i = 0; i < remaining_chars + 2; i++) {
    key_reader.GetCharForTest(ev_);
  }

  EXPECT_EQ("", key_reader.GetUserInputForTest());
}

TEST_F(KeyReaderTest, ReturnKeyTest) {
  KeyReader key_reader(true, "us");
  EXPECT_TRUE(key_reader.SetKeyboardContext());

  // Return key press should return true.

  ev_.code = 28;
  EXPECT_TRUE(key_reader.GetCharForTest(ev_));

  ev_.code = 16;
  ev_.value = 0;
  for (int i = 0; i < 5; i++) {
    key_reader.GetCharForTest(ev_);
  }
  EXPECT_EQ("qqqqq", key_reader.GetUserInputForTest());

  ev_.code = 28;
  EXPECT_TRUE(key_reader.GetCharForTest(ev_));
}

TEST_F(KeyReaderTest, FrenchKeyTest) {
  KeyReader key_reader(true, "fr");
  EXPECT_TRUE(key_reader.SetKeyboardContext());

  ev_.code = 16;
  key_reader.GetCharForTest(ev_);

  ev_.code = 17;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("az", key_reader.GetUserInputForTest());

  ev_.code = 4;
  key_reader.GetCharForTest(ev_);
  ev_.code = 5;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("az\"'", key_reader.GetUserInputForTest());

  // Not a printable ASCII (accent aigu), do not add to input.
  ev_.code = 8;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("az\"'", key_reader.GetUserInputForTest());

  // Test capitalization and special characters.
  // Left shift key down.
  ev_.code = 42;
  ev_.value = 1;
  key_reader.GetCharForTest(ev_);

  ev_.value = 0;
  ev_.code = 17;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("az\"'Z", key_reader.GetUserInputForTest());

  ev_.code = 4;
  key_reader.GetCharForTest(ev_);
  ev_.code = 5;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("az\"'Z34", key_reader.GetUserInputForTest());

  ev_.code = 42;
  ev_.value = 0;
  key_reader.GetCharForTest(ev_);

  // Get third char on key.
  // ALTGR (right alt) + CTL key press.

  ev_.code = 29;
  ev_.value = 1;
  key_reader.GetCharForTest(ev_);

  ev_.code = 100;
  ev_.value = 1;
  key_reader.GetCharForTest(ev_);

  ev_.code = 4;
  ev_.value = 0;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("az\"'Z34#", key_reader.GetUserInputForTest());
}

TEST_F(KeyReaderTest, JapaneseKeyTest) {
  KeyReader key_reader(true, "jp");
  EXPECT_TRUE(key_reader.SetKeyboardContext());

  ev_.code = 16;
  key_reader.GetCharForTest(ev_);

  ev_.code = 17;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("qw", key_reader.GetUserInputForTest());

  ev_.code = 42;
  ev_.value = 1;
  key_reader.GetCharForTest(ev_);

  ev_.value = 0;
  ev_.code = 4;
  key_reader.GetCharForTest(ev_);
  ev_.code = 5;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("qw#$", key_reader.GetUserInputForTest());

  // Test capitalization and special characters.
  // Left shift key down.
  ev_.code = 42;
  ev_.value = 1;
  key_reader.GetCharForTest(ev_);

  ev_.value = 0;
  ev_.code = 17;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("qw#$W", key_reader.GetUserInputForTest());

  ev_.code = 42;
  ev_.value = 0;
  key_reader.GetCharForTest(ev_);

  // Get third char on key.
  // ALT + CTL key press.

  ev_.code = 29;
  ev_.value = 1;
  key_reader.GetCharForTest(ev_);

  ev_.code = 56;
  ev_.value = 1;
  key_reader.GetCharForTest(ev_);

  // Japanese character should not be added to input.
  ev_.code = 16;
  ev_.value = 0;
  key_reader.GetCharForTest(ev_);
  EXPECT_EQ("qw#$W", key_reader.GetUserInputForTest());
}

TEST_F(KeyReaderTest, OnlyEvWaitKeyFunction) {
  MockKeyReader key_reader;
  // Cannot access password functions.
  EXPECT_FALSE(key_reader.InputSetUp());
}

TEST_F(KeyReaderTest, OnlyEvWaitKeyFunctionFalse) {
  MockKeyReader key_reader(false);
  // Cannot access password functions when include usb is false.
  EXPECT_FALSE(key_reader.InputSetUp());
}

TEST_F(KeyReaderTest, GetUserInputTab) {
  MockKeyReader key_reader(false, "us");
  EXPECT_CALL(key_reader, GetValidFds(false)).WillOnce(testing::Return(true));
  EXPECT_CALL(key_reader, EpollCreate(_)).WillOnce(testing::Return(true));
  // Tab key release recorded
  struct input_event ev_release {
    .type = EV_KEY, .code = 15, .value = 0,
  };
  EXPECT_CALL(key_reader, GetEpEvent(_, _, _))
      .WillOnce(testing::DoAll(testing::SetArgPointee<1>(ev_release),
                               testing::Return(true)));

  bool enter, tab = false;
  std::string input;

  EXPECT_TRUE(key_reader.InputSetUp());
  EXPECT_TRUE(key_reader.GetUserInput(&enter, &tab, &input));
  EXPECT_TRUE(tab);
  EXPECT_TRUE(input.empty());
}

TEST_F(KeyReaderTest, GetUserInputEnter) {
  MockKeyReader key_reader(false, "us");
  testing::InSequence s;
  EXPECT_CALL(key_reader, GetValidFds(false)).WillOnce(testing::Return(true));
  EXPECT_CALL(key_reader, EpollCreate(_)).WillOnce(testing::Return(true));
  // Enter key release recorded.
  struct input_event ev_release {
    .type = EV_KEY, .code = 28, .value = 1,
  };
  EXPECT_CALL(key_reader, GetEpEvent(_, _, _))
      .WillOnce(testing::DoAll(testing::SetArgPointee<1>(ev_release),
                               testing::Return(true)));

  ev_release.value = 0;
  EXPECT_CALL(key_reader, GetEpEvent(_, _, _))
      .WillOnce(testing::DoAll(testing::SetArgPointee<1>(ev_release),
                               testing::Return(true)));

  bool enter, tab = false;
  std::string input;

  EXPECT_TRUE(key_reader.InputSetUp());
  // Record enter press and release key events.
  EXPECT_TRUE(key_reader.GetUserInput(&enter, &tab, &input));
  EXPECT_TRUE(key_reader.GetUserInput(&enter, &tab, &input));
  EXPECT_TRUE(enter);
  EXPECT_TRUE(input.empty());
}

TEST_F(KeyReaderTest, GetUserInputError) {
  MockKeyReader key_reader(false, "us");

  EXPECT_CALL(key_reader, GetValidFds(false)).WillOnce(testing::Return(true));
  EXPECT_CALL(key_reader, EpollCreate(_)).WillOnce(testing::Return(true));

  EXPECT_CALL(key_reader, GetEpEvent(_, _, _)).WillOnce(testing::Return(false));

  bool enter, tab;
  std::string input;

  EXPECT_TRUE(key_reader.InputSetUp());
  EXPECT_FALSE(key_reader.GetUserInput(&enter, &tab, &input));
  EXPECT_TRUE(input.empty());
}

TEST_F(KeyReaderTest, GetUserInputGetChar) {
  MockKeyReader key_reader(false, "us");
  EXPECT_CALL(key_reader, GetValidFds(false)).WillOnce(testing::Return(true));
  EXPECT_CALL(key_reader, EpollCreate(_)).WillOnce(testing::Return(true));
  // A-key release recorded.
  struct input_event ev_release {
    .type = EV_KEY, .code = 30, .value = 0,
  };
  EXPECT_CALL(key_reader, GetEpEvent(_, _, _))
      .WillOnce(testing::DoAll(testing::SetArgPointee<1>(ev_release),
                               testing::Return(true)));

  bool enter, tab;
  std::string input;

  // Check keyboard input multiple chars.
  EXPECT_TRUE(key_reader.InputSetUp());
  EXPECT_TRUE(key_reader.GetUserInput(&enter, &tab, &input));
  EXPECT_EQ("a", input);

  // P-key release recorded.
  ev_release.code = 25;
  EXPECT_CALL(key_reader, GetEpEvent(_, _, _))
      .WillOnce(testing::DoAll(testing::SetArgPointee<1>(ev_release),
                               testing::Return(true)));

  EXPECT_TRUE(key_reader.GetUserInput(&enter, &tab, &input));
  EXPECT_EQ("ap", input);
}

TEST_F(KeyReaderTest, InitFdFailure) {
  MockKeyReader key_reader(false);
  EXPECT_CALL(key_reader, GetValidFds(true)).WillOnce(testing::Return(false));
  EXPECT_FALSE(key_reader.Init({103, 108, 28}));
}

TEST_F(KeyReaderTest, InitEpollFailure) {
  MockKeyReader key_reader(false);
  EXPECT_CALL(key_reader, GetValidFds(true)).WillOnce(testing::Return(true));
  EXPECT_CALL(key_reader, EpollCreate(_)).WillOnce(testing::Return(false));
  EXPECT_FALSE(key_reader.Init({103, 108, 28}));
}

TEST_F(KeyReaderTest, OnKeyEventRepeat) {
  MockKeyReader key_reader(false, "us");
  MockDelegate delegate;

  // Key repeat event.
  struct input_event ev_repeat {
    .type = EV_KEY, .code = KEY_ENTER, .value = 2,
  };
  EXPECT_CALL(key_reader, GetEpEvent(_, _, _))
      .WillRepeatedly(testing::DoAll(testing::SetArgPointee<1>(ev_repeat),
                                     testing::Return(true)));

  int num_repeats = 5;
  EXPECT_CALL(delegate, OnKeyPress(_, _, false)).Times(num_repeats);
  EXPECT_CALL(delegate, OnKeyPress(_, _, true)).Times(num_repeats);

  key_reader.keys_ = {KEY_UP, KEY_DOWN, KEY_ENTER, KEY_ESC};
  key_reader.SetDelegate(&delegate);
  // Repeated key press.
  for (int i = 0; i < num_repeats * kRepeatedSensitivity; ++i)
    key_reader.OnKeyEvent();
}

}  // namespace minios
