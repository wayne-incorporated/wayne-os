// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {ParallaxError} from '@parallax/common/error';
import {isArrayLike} from '@parallax/common/helpers';

const loaderCallbacks = new Set<(data: any) => void>();

/**
 * Register a callback function to parse new messages.
 *
 * @param call Parsing callback function.
 */
export function registerParser(call: (data: any) => void) {
  loaderCallbacks.add(call);
}

/**
 * Performs data conversions and parses new messages.
 *
 * @param messages 0 or more messages to parse.
 */
export function parseMessages(messages: any) {
  console.log('processMessage', messages);
  if (!messages) {
    return;
  }
  if (typeof messages === 'string') {
    messages = JSON.parse(messages);
  }
  if (!isArrayLike(messages)) {
    messages = [messages];
  }
  for (const mess of messages) {
    runParsers(mess);
  }
}

/**
 * Parse a single message.
 *
 * @param message A single message to parse.
 */
function runParsers(message: any) {
  for (const call of loaderCallbacks) {
    call(message);
  }
}
