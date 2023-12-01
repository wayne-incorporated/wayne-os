# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Simple test server for evaluating the frontend."""

import bisect
from http import server
import json
import math
import threading
import time


class SamplingTest:
    """Stores samples and provides JSON output."""

    def __init__(self, names):
        num_samples = len(names)
        self.samples = []
        self.meta = {"rowMeta": []}
        for i in range(num_samples):
            self.samples.append([])
            rowMeta = {"name": names[i]}
            self.meta["rowMeta"].append(rowMeta)

    def addSamples(self, samples):
        assert len(self.samples) == len(samples)
        for i, samp in enumerate(samples):
            self.samples[i].append(samp)

    def toJSON(self, out_type, start_time=0):
        start = 0
        if start_time:
            start = bisect.bisect(self.samples[0], start_time)
        end = len(self.samples[-1])
        print("JSON", start_time, start, end, end - start)
        transmit = []
        for samples in self.samples:
            transmit.append(samples[start:end])
        data = {
            "type": out_type,
            "meta": self.meta,
            "matrix": transmit,
        }
        return json.dumps(data)


sample_container = SamplingTest(["time", "A", "B", "C"])


class StreamingTest(server.BaseHTTPRequestHandler):
    """HTTP request handler."""

    def postInput(self):
        length = int(self.headers["Content-Length"])
        payload = self.rfile.read(length)
        text = payload.decode("utf_8")
        return json.loads(text)

    def do_POST(self):
        data = self.postInput()
        start_time = data.get("startTime")

        payload = sample_container.toJSON("streaming_chart", start_time)
        payload = payload.encode("utf_8")

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)


def sample_generator():
    while True:
        latest_samples = [
            math.sin(time.time()),
            math.sin(time.time() * 2),
            math.sin(time.time() * 3),
        ]
        sample_container.addSamples([time.time()] + latest_samples)
        time.sleep(0.01)


def start_server(port):
    threading.Thread(target=sample_generator).start()
    with server.HTTPServer(("localhost", port), StreamingTest) as serv:
        print("Starting Server")
        serv.serve_forever()


if __name__ == "__main__":
    start_server(9000)
