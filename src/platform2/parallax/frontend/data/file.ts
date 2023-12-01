// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {ParallaxError} from '@parallax/common/error';

/**
 * Opens a file picker and loads data from the file system.
 *
 * @param opts ShowOpenFilePicker configuration options.
 */
export async function load(opts: object) {
  let handles: FileSystemFileHandle[] = [];
  let results: string[] = [];
  try {
    // @ts-ignore
    handles = await window.showOpenFilePicker(opts);
  } catch (err) {
    console.warn('Load was canceled', err);
    return results;
  }
  // Load each file.
  for (const handle of handles) {
    const file = await handle.getFile();
    const reader = new FileReader();
    const data = await new Promise((resolve) => {
      reader.onloadend = () => {
        resolve(reader.result);
      };
      reader.readAsText(file);
    });
    if (reader.error) {
      throw new ParallaxError(
          'File read failed', {'file': file.name, 'error': reader.error});
    }
    results.push(data as string);
  }
  return results;
}

/**
 * Opens a file picker and saves data to the file system.
 *
 * @param opts ShowSaveFilePicker configuration options.
 * @param data Data to be saved.
 */
export async function save(opts: object, data: Blob|string) {
  let handle: FileSystemFileHandle;
  try {
    // @ts-ignore
    handle = await window.showSaveFilePicker(opts);
  } catch (err) {
    console.warn('Save was canceled', err);
    return;
  }
  // @ts-ignore
  const writer = await handle.createWritable();
  await writer.write(data);
  await writer.close();
}
