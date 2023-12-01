// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * Promisifies the given function that is using the callback style with
 * chrome.runtime.lastError for error handling.
 * @param {function(*): *} fn A function to be promisified.
 * @return {function(*): !Promise<*>} The promisified function.
 */
function promisifyFunction(fn) {
  const newFn = (...args) => new Promise((resolve, reject) => {
    fn(...args, (result) => {
      const err = chrome.runtime.lastError;
      if (err !== undefined) {
        reject(new Error(err.message));
      } else {
        resolve(result)
      }
    });
  });
  return newFn;
}

/**
 * Promisifies the given object by replacing all methods on it with
 * promisifyFunction(). Non-function attributes are not touched.
 * @param {!Object<string, *>} obj An object to be promisified.
 * @return {!Object<string, *>} The promisified object.
 */
function promisifyObject(obj) {
  return new Proxy(obj, {
    get(target, prop, receiver) {
      const maybeFn = Reflect.get(target, prop, receiver);
      if (typeof maybeFn === 'function') {
        return promisifyFunction(maybeFn).bind(target);
      } else {
        return maybeFn;
      }
    }
  });
}

/**
 * Asserts the given condition.
 * @param {boolean} cond The condition.
 * @param {string=} message The message to show on failure.
 */
function assert(cond, message = 'Assertion failed') {
  if (!cond) {
    throw new Error(message);
  }
}

/**
 * Sleeps for the given duration.
 * @param {number} duration How long to sleep in milliseconds.
 * @return {!Promise<void>} Resolved when |duration| milliseconds is passed.
 */
async function sleep(duration) {
  return new Promise((resolve) => {
    setTimeout(resolve, duration);
  });
}

/**
 * Polls until the given function return a value instead of throwing an error.
 * If it failed to poll within the timeout, the last error would be thrown.
 * @template T
 * @param {function(): T} fn Returns an awaitable value or throws an error.
 * @param {{timeout?: number, interval?: number}=} opts Options in milliseconds.
 * @return {!Promise<Awaited<T>>} The return value of the given function.
 */
async function poll(fn, {timeout = 5000, interval = 10} = {}) {
  let lastError = null;
  const deadline = Date.now() + timeout;

  while (Date.now() < deadline) {
    try {
      const value = await fn();
      return value;
    } catch (e) {
      lastError = e;
    }
    await sleep(interval);
  }

  throw new Error(
      'Timed out polling', lastError !== null ? {cause: lastError} : {})
}


/**
 * The chrome.autotestPrivate API is a ChromeOS only API for testing, and is
 * only allowed on the test extensions. Reference:
 * https://source.chromium.org/chromium/chromium/src/+/main:chrome/common/extensions/api/autotest_private.idl
 * @typedef {Object} Autotest
 * @prop {function(): !Promise<void>} waitForSystemWebAppsInstall
 * @prop {(appName: string, url: string) => !Promise<void>} launchSystemWebApp
 */

/**
 * @type {Autotest}
 */
const autotest = promisifyObject(chrome.autotestPrivate);

// The chrome.automation API allows developers to access the automation
// (accessibility) tree for the browser. Reference:
// https://developer.chrome.com/docs/extensions/reference/automation/

/**
 * @typedef {Object} FindParams
 * @prop {Object<string, string | !RegExp | number | boolean>=} attributes
 * @prop {string=} role
 * @prop {Object<string, boolean>=} state
 */

/**
 * @typedef {Object} AutomationNode
 * @prop {function(FindParams): ?AutomationNode} find
 * @prop {function(): void} doDefault
 */

/**
 * @type {{getDesktop: function(): !Promise<AutomationNode>}}
 */
const automation = promisifyObject(chrome.automation);

class CCA {
  /**
   * Gets the target automation node in CCA window with automatic polling.
   * @param {!FindParams} finder
   * @return {!Promise<!AutomationNode>}
   */
  async getNode(finder) {
    return poll(async () => {
      let node = await automation.getDesktop();
      const finders =
          [{attributes: {name: 'Camera', className: 'BrowserFrame'}}, finder];
      for (const finder of finders) {
        node = node.find(finder);
        assert(
            node !== null,
            `Failed to find node with ${JSON.stringify(finder)}`);
      }
      return node;
    });
  }

  /**
   * Performs the specified action.
   * TODO(shik): Support non-English names.
   * @param {string} name The action name in a11y tree.
   * @return {!Promise<void>}
   */
  async doAction(name) {
    const node = await this.getNode({
      states: {focusable: true, disabled: false},
      attributes: {defaultActionVerb: /./, name},
    });
    node.doDefault();
  }

  /**
   * Opens the camera app.
   * @param {{facing?: string, mode?: string}=} opts Target facing and mode.
   * @returns {!Promise<void>} Resolved when the app is launched.
   */
  async open({facing, mode} = {}) {
    // TODO(shik): Check if CCA is already opened.

    await autotest.waitForSystemWebAppsInstall();

    const url = new URL('chrome://camera-app/views/main.html')
    if (facing !== undefined) {
      url.searchParams.append('facing', facing);
    }
    if (mode !== undefined) {
      url.searchParams.append('mode', mode);
    }
    await autotest.launchSystemWebApp('Camera', url.href);

    // TODO(shik): Wait until the preview is streaming.
    // TODO(shik): Check the landed facing.
    // TODO(shik): Check the landed mode.
  }

  /**
   * Takes a photo. This assumes CCA is already opened.
   * @return {!Promise<void>}
   */
  async takePhoto() {
    await this.doAction('Take photo');
    // TODO(shik): Wait until the photo is saved.
  }

  async startRecording() {
    await this.doAction('Start recording');
    // TODO(shik): Wait until the recording is started.
  }

  async stopRecording() {
    await this.doAction('Stop recording');
    // TODO(shik): Wait until the video is saved.
  }
}

export const cca = new CCA();
