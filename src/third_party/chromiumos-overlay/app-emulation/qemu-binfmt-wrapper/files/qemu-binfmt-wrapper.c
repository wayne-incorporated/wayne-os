// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Put a wrapper around qemu so that argv[0] is preserved when using binfmt_misc
// to execute custom binaries.  Normally what happens is:
//  - user runs ARM `ls`
//  - kernel runs `/usr/bin/qemu-arm /bin/ls`
//  - QEMU does its magic to emulate /bin/ls
//  - the ls program is executed with argv[0]="/bin/ls"
// Most of the time this does not matter.  But in some cases, the program really
// needs its argv[0] to be exact (in cases where it is checked).
//
// When we enable the P flag to the binfmt_misc wrapper, the situation is:
//  - user runs ARM `ls`
//  - kernel runs `/usr/bin/qemu-arm /bin/ls ls`
//  - QEMU does its magic to emulate /bin/ls
//  - the ls program is executed with argv[0]="/bin/ls" argv[1]="ls"
// See /usr/src/linux/Documentation/binfmt_misc.txt for details on the P flag.
//
// But when we deploy this wrapper, we get:
//  - user runs ARM `ls`
//  - kernel runs `/usr/bin/qemu-arm-binfmt-wrapper /bin/ls ls`
//  - wrapper runs `/usr/bin/qemu-arm -0 ls /bin/ls`
//  - QEMU does its magic to emulate /bin/ls
//  - the ls program is executed with argv[0]="ls"
//
// Ideally QEMU should be able to handle this itself, but today it cannot.

#define _GNU_SOURCE
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  int ret;
  char **qargv;

  // If we don't have the min # of args, then the user is probably poking
  // us, so dump a message.  The code below assumes we have at least 3 as
  // that is what the P binfmt_misc flag will provide.
  if (argc < 3) {
    fprintf(stderr, "%s: do not execute directly; run through binfmt_misc\n",
            basename(argv[0]));
    return 1;
  }
  // Make space for the new argv.  It'll be argv but with -0 and NULL.
  qargv = malloc(sizeof(*argv) * (argc + 2));

  // Reformat the argv[0] of the wrapper to point to the real QEMU.
  // We assume it'll be `/usr/bin/qemu-arm-binfmt-wrapper`, so we just
  // chop off the trailing "-binfmt-wrapper" to get `/usr/bin/qemu-arm`.
  qargv[0] = strdup(argv[0]);
  // This math is correct as sizeof("str") counts the \0.
  qargv[0][strlen(argv[0]) - sizeof("binfmt-wrapper")] = '\0';

  // Set qargv[1] to -0, load qargv[2] with the original argv[0] that
  // the kernel has passed to us, and then set qargv[3] with the full
  // path to the program we want to actually interpret.
  // {/bin/ls, ls} -> {-0, ls, /bin/ls}
  qargv[1] = "-0";
  qargv[2] = argv[2];
  qargv[3] = argv[1];

  // Now copy over the remaining args untouched.  We also copy the sentinel
  // NULL which is why the argc math is like this.
  memcpy(&qargv[4], &argv[3], (argc - 3 + 1) * sizeof(*argv));

  ret = execv(qargv[0], qargv);
  printf("%s: failed to exec %s: %m\n", argv[0], qargv[0]);
  return ret;
}
