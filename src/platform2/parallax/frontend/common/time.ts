// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {ParallaxError} from '@parallax/common/error';

export type second = number

/**
 * Implements a subset of the strftime spec to produce timestamp strings.
 * By default it will generate a timestamp string with the current local time.
 *
 * Supported format codes:
 *   2 digit date: %y, %m, %d
 *   2 digit time: %H, %M, %S
 *   Escape: %%
 *
 * @param format    Timestamp format string.
 * @param opts      Optional named arguments.
 * @param opts.date Replaces the Date with a provided Date object.
 * @param opts.utc  When true converts the local timestamp to UTC timestamp.
 * @return          Timestamp String.
 */
export function strftime(format: string, opts?: {date?: Date, utc?: boolean}) {
  let date = opts?.date ? opts.date : new Date();
  if (opts?.utc) {
    date = new Date(date.getTime() + date.getTimezoneOffset() * 60000);
  }
  const codes = {
    '%Y': String(date.getFullYear()),
    '%y': String(date.getFullYear() % 100).padStart(2, '0'),
    '%m': String(date.getMonth() + 1).padStart(2, '0'),
    '%d': String(date.getDate()).padStart(2, '0'),
    '%H': String(date.getHours()).padStart(2, '0'),
    '%M': String(date.getMinutes()).padStart(2, '0'),
    '%S': String(date.getSeconds()).padStart(2, '0'),
  };
  let parsed = format;
  for (const [key, value] of Object.entries(codes)) {
    const regex = new RegExp('(?<!%)' + key, 'g');
    parsed = parsed.replaceAll(regex, value);
  }
  // Check for invalid flags by searching for any odd number of %
  // characters.
  const invalidFlags = parsed.match(/(?<!%)(?:(%%)*)%($|[^%])/g);
  if (invalidFlags) {
    throw new ParallaxError(
        'Invalid Flags found',
        {'format': format, 'parsed': parsed, 'invalidFlags': invalidFlags});
  }
  // Replace all of the even matchings.
  parsed = parsed.replaceAll('%%', '%');
  return parsed;
}

/**
 * Returns the current UTC timestamp. This will be impacted by user clock
 * changes so it is not monotonic.
 *
 * @return Floating point UTC timestamp.
 */
export function getUTC() {
  return new Date().getTime() / 1000;
}

/**
 * Returns the relative time in seconds. Browsers may restrict resolution
 * for security so while the value is monotonic, it will not always increase.
 *
 * @return Returns the floating point timestamp in seconds.
 */
export function getRelTime() {
  return performance.now() / 1000;
}

/**
 * Calculates the time elapsed.
 *
 * @param startTime Start time we are comparing against.
 * @return Returns the time elapsed in seconds
 */
export function timeElapsed(startTime: second) {
  const now = getRelTime();
  return now - startTime;
}
