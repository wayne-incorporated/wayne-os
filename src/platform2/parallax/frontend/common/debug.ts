// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * Lightweight class to benchmark the execution times of operations
 * and print the time to the console. It expands on the console.time()
 * functionality slightly by treating the timestamps as a sequence.
 */
export class Bechmark {
  private names: string[] = [];
  private ts: number[] = [];

  /**
   * Creates a new Benchmark instance and create the first log.
   *
   * @param name The first log name.
   */
  constructor(name?: string) {
    name = this.defaultName(name);
    this.log(name);
  }

  /**
   * Log the time of an event.
   *
   * @param name The log entry's name
   */
  log(name?: string) {
    name = this.defaultName(name);
    this.ts.push(performance.now());
    this.names.push(name);
  }

  /**
   * Prints the Benchmark's history showing the event and time deltas.
   *
   * @param name The log entry's name
   */
  print(name?: string) {
    name = this.defaultName(name);
    this.log(name);

    const firstName = this.names[0];
    let lines: string[] = [];

    lines.push(`Bechmark : ${firstName}`);
    lines.push(this.deltaTS(0, this.names.length - 1));

    for (let i = 1; i < this.names.length; i++) {
      lines.push(this.deltaTS(i - 1, i));
    }
    console.log(lines.join('\n'));
  }

  /**
   * [deltaTS description]
   * @param  start [description]
   * @param  stop  [description]
   * @return       [description]
   */
  private deltaTS(start: number, stop: number): string {
    const deltaText = String(Math.round(this.ts[stop] - this.ts[start]));
    const deltaPadding = ' '.repeat(Math.max(0, 8 - deltaText.length));
    const startName = this.names[start];
    const stopName = this.names[stop];
    return `${deltaText}${deltaPadding} : ${startName} → ${stopName}`;
  }

  /**
   * Sets a useful default name if it is missing. Attempts to use the
   * stack trace to find the line number of the caller, if that fails uses
   * the number of calls.
   *
   * @param name Optional name.
   * @returns Log name
   */
  private defaultName(name?: string) {
    if (name !== undefined) {
      return name;
    }
    const stack = this.getCallerFromStack();
    if (stack !== undefined) {
      return stack;
    }
    return String(this.names.length);
  }

  /**
   * Extracts the line number of the caller function using the V8 JS API's
   * non-standard method to get a stack trace.
   *
   * @returns Returns the line of the caller function if possible.
   */
  private getCallerFromStack(): string|undefined {
    // https://v8.dev/docs/stack-trace-api
    const fullTrace = new Error().stack;
    if (!fullTrace) {
      return undefined;
    }
    const lines = fullTrace.split('\n').map((x) => x.match(/\([^()]+\)/));
    const match = lines.map((x) => x ? x[0] : null).filter((x) => x);
    // Magic number here gets us out of the Benchmark class's functions and
    // points at the line which called the public interface.
    const result = match[3];
    if (typeof result === 'string') {
      return result;
    }
    return undefined;
  }
}
