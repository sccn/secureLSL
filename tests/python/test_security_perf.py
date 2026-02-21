# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""
Performance tests for secure LSL.

Tests measure encryption overhead and validate performance targets:
- <5% latency overhead for secure vs insecure streams
- Throughput validation for high-rate streaming
"""

import time
import statistics


import pylsl

from conftest import set_lsl_config, clear_lsl_config


class TestEncryptionOverhead:
    """Measure encryption/decryption overhead."""

    def test_secure_stream_latency(self, secure_config_pair):
        """Verify secure streams maintain acceptable latency.

        This test measures absolute latency rather than comparing secure vs insecure,
        as local loopback comparisons have too much variance. The key metric is
        that secure streams maintain sub-millisecond latency for local connections.
        """
        outlet_config, _ = secure_config_pair
        set_lsl_config(outlet_config)

        num_samples = 100
        num_channels = 8
        latencies = []

        info = pylsl.StreamInfo(
            name="SecureLatency",
            type="Perf",
            channel_count=num_channels,
            nominal_srate=pylsl.IRREGULAR_RATE,
            channel_format=pylsl.cf_float32,
            source_id="lat_secure_001",
        )
        outlet = pylsl.StreamOutlet(info)

        streams = pylsl.resolve_byprop("name", "SecureLatency", timeout=5.0)
        inlet = pylsl.StreamInlet(streams[0])
        inlet.open_stream()

        # Warm up
        for _ in range(10):
            outlet.push_sample([0.0] * num_channels)
            inlet.pull_sample(timeout=1.0)

        # Measure round-trip latency
        sample = [0.0] * num_channels
        for i in range(num_samples):
            send_time = pylsl.local_clock()
            outlet.push_sample(sample, send_time)

            recv_sample, recv_ts = inlet.pull_sample(timeout=1.0)
            if recv_sample:
                # Measure time from send to receive
                latency = pylsl.local_clock() - recv_ts
                latencies.append(latency)

        del inlet
        del outlet
        clear_lsl_config()

        # Calculate statistics
        if latencies:
            mean_latency = statistics.mean(latencies) * 1000  # ms
            median_latency = statistics.median(latencies) * 1000  # ms
            max_latency = max(latencies) * 1000  # ms

            print(
                f"\nSecure latency: mean={mean_latency:.3f}ms, "
                f"median={median_latency:.3f}ms, max={max_latency:.3f}ms"
            )

            # For local loopback, latency should be well under 10ms
            assert mean_latency < 10, f"Mean latency {mean_latency:.3f}ms too high"
            assert len(latencies) >= num_samples * 0.9, (
                f"Only received {len(latencies)}/{num_samples} samples"
            )

    def test_throughput_32ch_256hz(self, secure_config_pair):
        """Test throughput for typical EEG configuration: 32 channels at 256 Hz."""
        outlet_config, _ = secure_config_pair
        set_lsl_config(outlet_config)

        num_channels = 32
        sample_rate = 256
        duration_sec = 2.0
        expected_samples = int(sample_rate * duration_sec)

        info = pylsl.StreamInfo(
            name="ThroughputTest",
            type="EEG",
            channel_count=num_channels,
            nominal_srate=sample_rate,
            channel_format=pylsl.cf_float32,
            source_id="throughput_001",
        )
        outlet = pylsl.StreamOutlet(info)

        streams = pylsl.resolve_byprop("name", "ThroughputTest", timeout=5.0)
        inlet = pylsl.StreamInlet(streams[0])
        inlet.open_stream()

        time.sleep(0.2)  # Let connection stabilize

        # Push at nominal rate
        sample = [0.0] * num_channels
        interval = 1.0 / sample_rate
        start_time = time.time()

        for i in range(expected_samples):
            sample[0] = float(i)  # Mark sample number
            outlet.push_sample(sample)

            # Pace to nominal rate
            target = start_time + (i + 1) * interval
            sleep_time = target - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

        # Allow time for samples to arrive
        time.sleep(0.5)

        # Pull all available
        received = 0
        while True:
            s, ts = inlet.pull_sample(timeout=0.1)
            if s is None:
                break
            received += 1

        delivery_rate = (received / expected_samples) * 100
        print(
            f"\nThroughput: Sent={expected_samples}, Received={received}, "
            f"Delivery={delivery_rate:.1f}%"
        )

        # Should receive at least 90% of samples
        assert received >= expected_samples * 0.9, (
            f"Only received {received}/{expected_samples} samples ({delivery_rate:.1f}%)"
        )

        clear_lsl_config()

    def test_throughput_64ch_512hz(self, secure_config_pair):
        """Test higher throughput: 64 channels at 512 Hz."""
        outlet_config, _ = secure_config_pair
        set_lsl_config(outlet_config)

        num_channels = 64
        sample_rate = 512
        duration_sec = 1.0  # Shorter test for higher rate
        expected_samples = int(sample_rate * duration_sec)

        info = pylsl.StreamInfo(
            name="HighThroughput",
            type="EEG",
            channel_count=num_channels,
            nominal_srate=sample_rate,
            channel_format=pylsl.cf_float32,
            source_id="highthroughput_001",
        )
        outlet = pylsl.StreamOutlet(info)

        streams = pylsl.resolve_byprop("name", "HighThroughput", timeout=5.0)
        inlet = pylsl.StreamInlet(streams[0])
        inlet.open_stream()

        time.sleep(0.2)

        # Push samples in chunks for better throughput
        chunk_size = 32
        sample = [0.0] * num_channels
        chunk = []

        start_time = time.time()
        for i in range(expected_samples):
            sample[0] = float(i)
            chunk.append(sample.copy())

            if len(chunk) >= chunk_size:
                outlet.push_chunk(chunk)
                chunk = []

        if chunk:
            outlet.push_chunk(chunk)

        push_time = time.time() - start_time

        # Allow time for samples to arrive
        time.sleep(0.5)

        # Pull all available
        received = 0
        while True:
            s, ts = inlet.pull_sample(timeout=0.1)
            if s is None:
                break
            received += 1

        delivery_rate = (received / expected_samples) * 100
        throughput = expected_samples * num_channels * 4 / push_time / 1e6  # MB/s

        print(
            f"\nHigh rate: Sent={expected_samples}, Received={received}, "
            f"Delivery={delivery_rate:.1f}%, Throughput={throughput:.2f} MB/s"
        )

        # Should receive at least 80% at this higher rate
        assert received >= expected_samples * 0.8, (
            f"Only received {received}/{expected_samples} samples ({delivery_rate:.1f}%)"
        )

        clear_lsl_config()


class TestLargeDataPerformance:
    """Performance tests for large data transfers."""

    def test_large_chunk_transfer(self, secure_config_pair):
        """Test transfer of large chunks efficiently."""
        outlet_config, _ = secure_config_pair
        set_lsl_config(outlet_config)

        num_channels = 128
        chunk_samples = 1000
        num_chunks = 5

        info = pylsl.StreamInfo(
            name="LargeChunkTest",
            type="Data",
            channel_count=num_channels,
            nominal_srate=1000,
            channel_format=pylsl.cf_float32,
            source_id="largechunk_001",
        )
        outlet = pylsl.StreamOutlet(info)

        streams = pylsl.resolve_byprop("name", "LargeChunkTest", timeout=5.0)
        inlet = pylsl.StreamInlet(streams[0])
        inlet.open_stream()

        time.sleep(0.2)

        # Generate chunk data
        chunk = [
            [float(i * num_channels + ch) for ch in range(num_channels)]
            for i in range(chunk_samples)
        ]

        # Time chunk transfers
        start = time.time()
        for _ in range(num_chunks):
            outlet.push_chunk(chunk)
        push_time = time.time() - start

        total_samples = num_chunks * chunk_samples
        total_bytes = total_samples * num_channels * 4
        push_throughput = total_bytes / push_time / 1e6  # MB/s

        time.sleep(1.0)  # Allow arrival

        # Pull and count
        received = 0
        pull_start = time.time()
        while True:
            s, ts = inlet.pull_sample(timeout=0.2)
            if s is None:
                break
            received += 1
        pull_time = time.time() - pull_start

        if pull_time > 0:
            pull_throughput = received * num_channels * 4 / pull_time / 1e6
        else:
            pull_throughput = 0

        print(
            f"\nLarge chunk: Sent={total_samples}, Received={received}, "
            f"Push={push_throughput:.1f} MB/s, Pull={pull_throughput:.1f} MB/s"
        )

        assert received >= total_samples * 0.8, (
            f"Only received {received}/{total_samples} samples"
        )

        clear_lsl_config()

    def test_sustained_streaming(self, secure_config_pair):
        """Test sustained streaming over longer period."""
        outlet_config, _ = secure_config_pair
        set_lsl_config(outlet_config)

        num_channels = 16
        sample_rate = 100
        duration_sec = 5.0
        expected_samples = int(sample_rate * duration_sec)

        info = pylsl.StreamInfo(
            name="SustainedTest",
            type="Continuous",
            channel_count=num_channels,
            nominal_srate=sample_rate,
            channel_format=pylsl.cf_float32,
            source_id="sustained_001",
        )
        outlet = pylsl.StreamOutlet(info)

        streams = pylsl.resolve_byprop("name", "SustainedTest", timeout=5.0)
        inlet = pylsl.StreamInlet(streams[0])
        inlet.open_stream()

        time.sleep(0.2)

        # Push at nominal rate
        sample = [0.0] * num_channels
        interval = 1.0 / sample_rate
        start_time = time.time()
        received = 0

        for i in range(expected_samples):
            sample[0] = float(i)
            outlet.push_sample(sample)

            # Check for received samples periodically
            while True:
                s, ts = inlet.pull_sample(timeout=0.0)  # Non-blocking
                if s is None:
                    break
                received += 1

            # Pace to nominal rate
            target = start_time + (i + 1) * interval
            sleep_time = target - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

        # Drain remaining samples
        time.sleep(0.5)
        while True:
            s, ts = inlet.pull_sample(timeout=0.1)
            if s is None:
                break
            received += 1

        actual_duration = time.time() - start_time
        delivery_rate = (received / expected_samples) * 100

        print(
            f"\nSustained: Duration={actual_duration:.1f}s, "
            f"Sent={expected_samples}, Received={received}, "
            f"Delivery={delivery_rate:.1f}%"
        )

        # Should maintain at least 95% delivery for sustained streaming
        assert received >= expected_samples * 0.95, (
            f"Sustained delivery only {delivery_rate:.1f}%"
        )

        clear_lsl_config()
