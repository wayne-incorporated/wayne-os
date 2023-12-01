// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {getUTC, getRelTime, timeElapsed, second} from '@parallax/common/time';
import {parseMessages} from '@parallax/data/parse';

let client: StreamingClient|undefined;

/**
 * Handles the connection with a streaming server.
 */
class StreamingClient {
  /* Server network path. */
  readonly server: string;
  /* Interval between fetching data. */
  readonly fetchInterval: second;
  /* Maximum time disconnected from the server before disconnecting. */
  readonly maxDisconnection: second;
  /* Reference timestamp for disconnection. */
  private timestamp: second;
  /* Timer ID */
  private timer: ReturnType<typeof setTimeout>|undefined;
  /* Connected status. */
  private connected = false;

  /**
   * Creates a new Server
   * @param server Server path including port
   */
  constructor(server: string) {
    this.server = server;
    this.fetchInterval = 0.1;
    this.maxDisconnection = 10;
    this.timestamp = getRelTime();
  }

  /**
   * Reset the timer.
   */
  async run() {
    this.connected = true;
    try {
      // Attempt to fetch the data.
      await this.getData();
      this.timestamp = getRelTime();
    } catch (error) {
      console.error('Error', error);
    }
    if (timeElapsed(this.timestamp) <= this.maxDisconnection) {
      this.resetTimer();
    } else {
      console.error('Disonnecting from client due to timeout.');
      this.disconnect();
    }
  }

  /**
   * Reset the timer so we call run again.
   */
  resetTimer() {
    clearTimeout(this.timer);
    this.timer = setTimeout(this.run.bind(this), this.fetchInterval * 1000);
  }

  /**
   * Disconnect the client from the server.
   */
  disconnect() {
    clearTimeout(this.timer);
    this.connected = false;
  }

  /**
   * Send and receive objects between the server.
   *
   * Uses JSON and POST methods to serialize a message and submit it to
   * the server. Deserializes the response from the server and returns it.
   *
   * @param sendData JSON serializable object passed to the server.
   * @return Deserialized JSON response from the server.
   */
  async transfer(sendData: any) {
    const sendText = JSON.stringify(sendData);
    const response = await fetch(this.server, {
      method: 'POST',
      mode: 'cors',
      cache: 'no-cache',
      headers: {'Content-Type': 'text/plain'},
      body: sendText,
    });
    const text = await response.text();
    return JSON.parse(text);
  }

  /**
   * Request data from the server and pass the response to the callbacks.
   * @param server Server address and port.
   */
  async getData() {
    let utc = getUTC();
    const request = {
      type: 'getData',
      startTime: utc - 10,
    };
    const data = await this.transfer(request);
    parseMessages(data);
  }

  /**
   * Query if the client is currently connected to the server.
   * @return True if it is connected.
   */
  isConnected() {
    return this.connected;
  }
}

/**
 * Query if any clients are connected to the server.
 * @return True if any clients are connected.
 */
export function clientConnected() {
  if (client) {
    return client.isConnected();
  }
  return false;
}

/**
 * Connect and disconnect the client from the streaming server.
 * @param server Server path and port.
 */
export async function toggleClient(server: string) {
  if (!clientConnected()) {
    client = new StreamingClient(server);
    client.run();
  } else {
    if (client) {
      client.disconnect();
    }
    client = undefined;
  }
}
