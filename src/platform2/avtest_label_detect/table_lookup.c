// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <stdio.h>
#include <string.h>
#include <regex.h>

#include "label_detect.h"

bool get_board_name(int board_buffer_len, char* board) {
  const char* kBoardKey = "CHROMEOS_RELEASE_BOARD=";
  char line[1024];
  bool found = false;
  FILE* fp = fopen("/etc/lsb-release", "r");

  if (!fp) {
    TRACE("failed to open /etc/lsb-release\n");
    return false;
  }

  while (fgets(line, sizeof(line), fp)) {
    if (strlen(line) == sizeof(line) - 1) {
      TRACE("line too long\n");
      break;
    }

    if (strncmp(line, kBoardKey, strlen(kBoardKey)) != 0)
      continue;

    /* chomp trailing newline character. */
    line[strlen(line) - 1] = '\0';

    char* p = line + strlen(kBoardKey);
    if (strlen(p) >= board_buffer_len) {
      TRACE("board name too long: %s\n", p);
      break;
    }
    strcpy(board, p);
    found = true;
  }
  fclose(fp);

  if (!found) {
    TRACE("not found line starts with %s\n", kBoardKey);
  }
  return found;
}

void match_rule(char* board, char* rule_line) {
  char *pattern, *label;
  char* comment = strchr(rule_line, '#');

  /* ignore comments */
  if (comment)
    *comment = '\0';

  pattern = strtok(rule_line, " \t\n");
  if (!pattern)
    return;  // blank line

  regex_t reg;
  regmatch_t match;

  regcomp(&reg, pattern, REG_EXTENDED);
  if (regexec(&reg, board, 1, &match, 0) == 0) {
    TRACE("matched %s\n", pattern);
    for (label = strtok(NULL, " \t\n"); label; label = strtok(NULL, " \t\n")) {
      printf("Detected label: %s\n", label);
    }
  }
  regfree(&reg);
}

void detect_label_by_board_name() {
  const char* conf_filename = "/usr/local/etc/avtest_label_detect.conf";
  const int kMaxBoardLen = 64;
  char board[kMaxBoardLen];
  char rule_line[1024];
  FILE* fp;

  if (!get_board_name(sizeof(board), board))
    return;

  TRACE("board=%s\n", board);

  fp = fopen(conf_filename, "r");
  if (fp) {
    while (fgets(rule_line, sizeof(rule_line), fp)) {
      if (strlen(rule_line) == sizeof(rule_line) - 1) {
        TRACE("rule line too long, skip\n");
        continue;
      }
      match_rule(board, rule_line);
    }
    fclose(fp);
  } else {
    TRACE("Cannot read %s, skip\n", conf_filename);
  }
}
