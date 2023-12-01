// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * Extension on Error to include an optional data object payload allowing
 * additional parameters to be included in the errors. ErrorEvents can
 * use these to provide more useful debug information.
 */
export class ParallaxError extends Error {
  /* Optional payload. */
  data: object|undefined;

  /**
   * Creates a new ParallaxError
   *
   * @param message Error message string.
   * @param data    Optional data payload which may be printed.
   */
  constructor(message: string, data?: object) {
    super(message);
    this.name = 'ParallaxError';
    this.data = data;
  }

  /**
   * Prints the error to the console.
   */
  consoleError() {
    if (this.data === undefined) {
      console.error(this.message);
    } else {
      console.error(this.message + '\n', this.data);
    }
  }

  /**
   * Enable console error printing of any uncaught errors.
   */
  static enableLogs() {
    window.addEventListener('error', (ev: ErrorEvent) => {
      if (ev.error instanceof ParallaxError) {
        ev.error.consoleError();
      }
    });
  }
}
