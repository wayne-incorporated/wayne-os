// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {ParallaxError} from '@parallax/common/error';
import * as file from '@parallax/data/file';
import {screenshot} from '@parallax/data/screenshot';
import {saveHtml} from '@parallax/data/save_html';
import {toggleClient} from '@parallax/data/client';

// TODO (bnemec) We need to rate limit some of the controls:
// Double clicks, response delays, and competing UI elements may
// create some problems for end users.

/**
 * Loads one or more JSON files and imports the data.
 * Will result in a file save window opening to specify target name.
 */
export async function controlLoadJson() {
  const opts = {
    multiple: true,
    excludeAcceptAllOption: true,
    types: [
      {description: 'JSON', accept: {'application/json': ['.json']}},
    ],
  };
  file.load(opts);
}

/**
 * Saves the data as a JSON file which can be imported.
 * Will result in a file save window opening to specify target name.
 * TODO (bnemec): Unfinished.
 */
export async function controlSaveJson() {
  const opts = {
    excludeAcceptAllOption: true,
    suggestedName: 'data.json',
    types: [
      {description: 'JSON', accept: {'application/json': ['.json']}},
    ],
  };
  file.save(opts, 'text');
}

/**
 * Saves the HTML page and data as a self contained document.
 * Will result in a file save window opening to specify target name.
 * TODO (bnemec): Unfinished.
 */
export async function controlSaveHtml() {
  saveHtml();
}

/**
 * Takes a screenshot of the whole document as a full page screenshot.
 * Will result in a file save window opening to specify target name.
 * Supports alternative screenshot functions by right clicking.
 *
 * @param useDefault If true it uses the default screenshot method,
 *                   if false uses an experimental method.
 */
export async function controlTakeScreenshot(useDefault = true) {
  screenshot(useDefault);
}

/**
 * Connects or disconnects from the streaming server.
 */
export async function controlStream() {
  const serverIp = document.getElementById('server-ip') as HTMLInputElement;
  if (!serverIp) {
    throw new ParallaxError('server-ip selector not found');
  }
  toggleClient(serverIp.value);
}
