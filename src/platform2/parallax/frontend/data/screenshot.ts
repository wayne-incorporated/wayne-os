// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import * as htmlToImage from 'html-to-image';
import * as file from '@parallax/data/file';

/**
 * Takes a screenshot of the whole document as a full page screenshot.
 * The results will generally not be a perfect representation as there
 * is currently no interface.
 *
 * There's several libraries and methods which can do this and they have
 * some pros and cons between results generated and performance. We want
 * to be able to test results side by side to assess how it performs in
 * real world datasets.
 *
 * TODO (bnemec): Identify which method we want to use for saving charts
 * and if additional improvements exist. For example Google Charts
 * getImageURI() functions allow extracting a screenshot of an individual
 * plot.
 *
 * @param useDefault If true it uses the default screenshot method,
 *                    if false uses an experimental method.
 */
export async function screenshot(useDefault = true) {
  const opts = {
    excludeAcceptAllOption: true,
    suggestedName: 'screenshot.png',
    types: [
      {description: 'PNG', accept: {'application/png': ['.png']}},
    ],
  };
  if (useDefault) {
    // @ts-ignore: Loaded via gstatic instead of node.
    const canvas = await html2canvas(document.body);
    const dataBlob = await canvas.toBlob((x: Blob) => {
      file.save(opts, x);
    });
  } else {
    const data = await htmlToImage.toBlob(document.body);
    if (data) {
      file.save(opts, data);
    }
  }
}
