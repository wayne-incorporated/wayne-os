// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {ParallaxError} from '@parallax/common/error';

/**
 * Checks if a object is an iterable collection of values, Arrays and Sets.
 *
 * @param data Object to check.
 * @return     True if the data is an iterable ArrayLike object.
 */
export function isArrayLike(data: any) {
  if (Array.isArray(data) || data instanceof Set) {
    return true;
  }
  return false;
}

/**
 * Checks if a object is an iterable collection of values, Arrays and Sets.
 * If an object is not array-like then a ParallaxError will be thrown.
 *
 * @param data Object to check.
 * @return     Same object
 */
export function iterableArray(data: any) {
  if (isArrayLike(data)) {
    return data;
  }
  throw new ParallaxError('Not array-like', {'data': data});
}

/**
 * Helper function to iterate over a map-like objects consistently.
 * If an object is not map-like then a ParallaxError will be thrown.
 *
 * @param data  An map-like object we wish to iterate.
 * @return      [key, value] like iterable object.
 */
export function iterableMap(data: any) {
  if (!isArrayLike(data)) {
    if (data instanceof Map) {
      return data;
    } else if (data.constructor === Object.prototype.constructor) {
      return Object.entries(data);
    }
  }
  throw new ParallaxError('Not map-like', {'data': data});
}

/**
 * Sorts a Array of text strings with a natural numeric sort.
 *
 * @param text Input text array.
 * @return Sorted array using a natural numeric sort.
 */
function naturalSort(text: string[]) {
  text = [...text];
  let numeric = new Intl.Collator(undefined, {numeric: true});
  return text.sort(numeric.compare);
}
