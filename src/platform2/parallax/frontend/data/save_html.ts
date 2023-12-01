// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import * as file from '@parallax/data/file';
import {ParallaxError} from '@parallax/common/error';

/**
 * We need a clean copy of the html document before tasks have edited it.
 * The easiest method is to simply grab a copy as soon as possible and delay
 * editing it until the onload event.
 */
const CLEAN_HTML = document.documentElement.outerHTML;

/**
 * Gets a clean copy of the HTML page.
 * @return The HTML text.
 */
export function getCleanHtml() {
  return CLEAN_HTML;
}

/**
 * Locates the begin and end injection comments in the HTML and injects
 * the text string into the region.
 *
 * @param html Input HTML document to edit.
 * @param text Text to inject into the tag.
 * @return HTML document with data injected into the tag.
 */
export function injectIntoHtml(html: string, text: string) {
  const beginReg = /\/\*\s*{BEGIN_PARALLAX_DATA_INJECTION}\s*\*\//;
  const endReg = /\/\*\s*{END_PARALLAX_DATA_INJECTION}\s*\*\//;
  const beginMatch = beginReg.exec(html);
  const endMatch = endReg.exec(html);
  if (!beginMatch || !endMatch) {
    throw new ParallaxError('Missing Regex Match', {
      'beginReg': beginReg,
      'beginMatch': beginMatch,
      'endReg': endReg,
      'endMatch': endMatch,
    });
  }
  const beginIndex = beginMatch.index + beginMatch[0].length;
  const endIndex = endMatch.index;
  if (beginIndex > endIndex) {
    throw new ParallaxError('Begin and end indexes swapped', {
      'beginMatch': beginMatch,
      'beginIndex': beginIndex,
      'endMatch': endMatch,
      'endIndex': endIndex,
    });
  }
  return html.slice(0, beginIndex) + text + html.slice(endIndex);
}

/**
 * Saves the HTML page and data as a self contained document.
 */
export async function saveHtml() {
  const opts = {
    excludeAcceptAllOption: true,
    suggestedName: 'report.html',
    types: [
      {description: 'HTML', accept: {'application/html': ['.html']}},
    ],
  };
  file.save(opts, CLEAN_HTML);
}
