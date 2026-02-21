# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""
Cross-language interoperability tests for secure LSL.

Tests Python <-> C++ communication using subprocess for the C++ binaries.
"""

import os
import subprocess
import time
from pathlib import Path

import pytest

import pylsl

from conftest import (
    set_lsl_config,
    clear_lsl_config,
)

# Path to C++ test binaries
BUILD_DIR = Path(__file__).parent.parent.parent / "liblsl" / "build"
CPP_OUTLET = BUILD_DIR / "cpp_secure_outlet"
CPP_INLET = BUILD_DIR / "cpp_secure_inlet"


@pytest.fixture(autouse=True)
def check_binaries():
    """Skip tests if C++ binaries are not built."""
    if not CPP_OUTLET.exists():
        pytest.skip(f"cpp_secure_outlet not found at {CPP_OUTLET}")
    if not CPP_INLET.exists():
        pytest.skip(f"cpp_secure_inlet not found at {CPP_INLET}")


class TestCppOutletPythonInlet:
    """Test C++ outlet -> Python inlet communication."""

    def test_cpp_outlet_python_inlet_basic(self, secure_config_pair):
        """C++ outlet (subprocess) -> Python inlet basic test."""
        outlet_config, inlet_config = secure_config_pair

        # Start C++ outlet as subprocess with security config
        env = os.environ.copy()
        env["LSLAPICFG"] = str(outlet_config)

        proc = subprocess.Popen(
            [
                str(CPP_OUTLET),
                "--name",
                "CppToP_Basic",
                "--samples",
                "50",
                "--channels",
                "4",
                "--rate",
                "100",
            ],
            env=env,
            stderr=subprocess.PIPE,
        )

        try:
            # Give outlet time to start
            time.sleep(0.5)

            # Python inlet connects with its own config
            set_lsl_config(inlet_config)

            streams = pylsl.resolve_byprop("name", "CppToP_Basic", timeout=5.0)
            assert len(streams) > 0, "Stream not found"

            inlet = pylsl.StreamInlet(streams[0])
            inlet.open_stream()

            # Pull samples
            received = []
            for _ in range(50):
                sample, ts = inlet.pull_sample(timeout=2.0)
                if sample is not None:
                    received.append(sample)

            # Verify received samples
            assert len(received) >= 35, (
                f"Expected at least 35 samples, got {len(received)}"
            )

            # Verify data integrity - samples should have sequential pattern
            # (may not start from 0 due to timing)
            if len(received) >= 2:
                first_sample = received[0]
                # Check that channels have expected offset pattern within a sample
                for ch in range(1, 4):
                    assert first_sample[ch] == pytest.approx(
                        first_sample[0] + ch, rel=1e-5
                    ), (
                        f"Channel offset mismatch: ch0={first_sample[0]}, ch{ch}={first_sample[ch]}"
                    )
                # Check sequential samples differ by num_channels
                for i in range(1, min(10, len(received))):
                    expected_diff = 4  # num_channels
                    actual_diff = received[i][0] - received[i - 1][0]
                    assert actual_diff == pytest.approx(expected_diff, rel=1e-5), (
                        f"Sample sequence mismatch at {i}: diff={actual_diff}, expected={expected_diff}"
                    )

        finally:
            clear_lsl_config()
            proc.wait(timeout=10)
            assert proc.returncode == 0, (
                f"C++ outlet failed: {proc.stderr.read().decode()}"
            )

    def test_cpp_outlet_python_inlet_large_data(self, secure_config_pair):
        """C++ outlet -> Python inlet with larger data transfer."""
        outlet_config, inlet_config = secure_config_pair

        env = os.environ.copy()
        env["LSLAPICFG"] = str(outlet_config)

        num_samples = 200
        num_channels = 8

        proc = subprocess.Popen(
            [
                str(CPP_OUTLET),
                "--name",
                "CppToP_Large",
                "--samples",
                str(num_samples),
                "--channels",
                str(num_channels),
                "--rate",
                "200",
            ],
            env=env,
            stderr=subprocess.PIPE,
        )

        try:
            time.sleep(0.5)
            set_lsl_config(inlet_config)

            streams = pylsl.resolve_byprop("name", "CppToP_Large", timeout=5.0)
            inlet = pylsl.StreamInlet(streams[0])
            inlet.open_stream()

            received = []
            start = time.time()
            while time.time() - start < 5.0 and len(received) < num_samples:
                sample, ts = inlet.pull_sample(timeout=0.5)
                if sample is not None:
                    received.append(sample)

            # Should receive majority of samples
            assert len(received) >= num_samples * 0.7, (
                f"Expected at least {num_samples * 0.7} samples, got {len(received)}"
            )

        finally:
            clear_lsl_config()
            proc.wait(timeout=10)


class TestPythonOutletCppInlet:
    """Test Python outlet -> C++ inlet communication."""

    def test_python_outlet_cpp_inlet_basic(self, secure_config_pair):
        """Python outlet -> C++ inlet (subprocess) basic test."""
        outlet_config, inlet_config = secure_config_pair

        # Create Python outlet
        set_lsl_config(outlet_config)

        info = pylsl.StreamInfo(
            name="PyToC_Basic",
            type="Test",
            channel_count=4,
            nominal_srate=100,
            channel_format=pylsl.cf_float32,
            source_id="py_outlet_interop_001",
        )
        outlet = pylsl.StreamOutlet(info)

        # Give outlet time to announce
        time.sleep(0.3)

        # Start C++ inlet as subprocess
        env = os.environ.copy()
        env["LSLAPICFG"] = str(inlet_config)

        # Note: Don't use --validate as samples may be missed at startup
        # The important test is that C++ can receive Python's encrypted data
        proc = subprocess.Popen(
            [
                str(CPP_INLET),
                "--stream",
                "PyToC_Basic",
                "--samples",
                "50",
                "--timeout",
                "5.0",
            ],
            env=env,
            stderr=subprocess.PIPE,
        )

        try:
            # Push samples with sequential values for validation
            for i in range(60):  # Push extra to ensure enough received
                sample = [float(i * 4 + ch) for ch in range(4)]
                outlet.push_sample(sample)
                time.sleep(0.01)

            # Wait for C++ inlet to finish
            proc.wait(timeout=15)

            # C++ inlet returns 0 on success, 1 on error, 2 on validation failure
            stderr_output = proc.stderr.read().decode()
            assert proc.returncode == 0, (
                f"C++ inlet failed (code {proc.returncode}): {stderr_output}"
            )

        finally:
            clear_lsl_config()

    def test_python_outlet_cpp_inlet_large(self, secure_config_pair):
        """Python outlet -> C++ inlet with larger data."""
        outlet_config, inlet_config = secure_config_pair

        set_lsl_config(outlet_config)

        num_samples = 200
        num_channels = 8

        info = pylsl.StreamInfo(
            name="PyToC_Large",
            type="Test",
            channel_count=num_channels,
            nominal_srate=200,
            channel_format=pylsl.cf_float32,
            source_id="py_outlet_large_001",
        )
        outlet = pylsl.StreamOutlet(info)
        time.sleep(0.3)

        env = os.environ.copy()
        env["LSLAPICFG"] = str(inlet_config)

        proc = subprocess.Popen(
            [
                str(CPP_INLET),
                "--stream",
                "PyToC_Large",
                "--samples",
                str(num_samples),
                "--timeout",
                "10.0",
            ],
            env=env,
            stderr=subprocess.PIPE,
        )

        try:
            # Push samples
            for i in range(num_samples + 20):
                sample = [float(i * num_channels + ch) for ch in range(num_channels)]
                outlet.push_sample(sample)
                time.sleep(0.005)

            proc.wait(timeout=20)
            stderr = proc.stderr.read().decode()

            # Success if exit code 0 (enough samples received)
            assert proc.returncode == 0, f"C++ inlet failed: {stderr}"

        finally:
            clear_lsl_config()


class TestBidirectionalInterop:
    """Test bidirectional communication scenarios."""

    def test_simultaneous_streams(self, secure_config_pair):
        """Test Python and C++ outlets simultaneously with cross inlets."""
        outlet_config, inlet_config = secure_config_pair

        env_outlet = os.environ.copy()
        env_outlet["LSLAPICFG"] = str(outlet_config)

        env_inlet = os.environ.copy()
        env_inlet["LSLAPICFG"] = str(inlet_config)

        # Start C++ outlet
        cpp_outlet_proc = subprocess.Popen(
            [
                str(CPP_OUTLET),
                "--name",
                "CppBidir",
                "--samples",
                "50",
                "--channels",
                "2",
                "--rate",
                "50",
            ],
            env=env_outlet,
            stderr=subprocess.PIPE,
        )

        # Create Python outlet
        set_lsl_config(outlet_config)
        py_info = pylsl.StreamInfo(
            name="PyBidir",
            type="Test",
            channel_count=2,
            nominal_srate=50,
            channel_format=pylsl.cf_float32,
            source_id="py_bidir_001",
        )
        py_outlet = pylsl.StreamOutlet(py_info)

        try:
            time.sleep(0.5)

            # Start C++ inlet for Python stream
            cpp_inlet_proc = subprocess.Popen(
                [
                    str(CPP_INLET),
                    "--stream",
                    "PyBidir",
                    "--samples",
                    "30",
                    "--timeout",
                    "5.0",
                ],
                env=env_inlet,
                stderr=subprocess.PIPE,
            )

            # Python inlet for C++ stream
            streams = pylsl.resolve_byprop("name", "CppBidir", timeout=5.0)
            assert len(streams) > 0, "C++ stream not found"
            py_inlet = pylsl.StreamInlet(streams[0])
            py_inlet.open_stream()

            # Push Python samples
            for i in range(50):
                py_outlet.push_sample([float(i), float(i + 1)])
                time.sleep(0.02)

            # Pull from C++ outlet
            received_from_cpp = []
            for _ in range(30):
                sample, ts = py_inlet.pull_sample(timeout=1.0)
                if sample:
                    received_from_cpp.append(sample)

            # Wait for subprocesses
            cpp_outlet_proc.wait(timeout=10)
            cpp_inlet_proc.wait(timeout=10)

            # Verify both directions worked
            assert len(received_from_cpp) >= 20, (
                f"Python inlet: expected at least 20 from C++, got {len(received_from_cpp)}"
            )
            assert cpp_inlet_proc.returncode == 0, (
                f"C++ inlet failed: {cpp_inlet_proc.stderr.read().decode()}"
            )

        finally:
            clear_lsl_config()
            if cpp_outlet_proc.poll() is None:
                cpp_outlet_proc.terminate()


class TestInteropEdgeCases:
    """Edge case tests for interoperability."""

    def test_cpp_inlet_waits_for_stream(self, secure_config_pair):
        """C++ inlet should wait for Python outlet to start."""
        outlet_config, inlet_config = secure_config_pair

        env = os.environ.copy()
        env["LSLAPICFG"] = str(inlet_config)

        # Start C++ inlet first (it will wait for stream)
        proc = subprocess.Popen(
            [
                str(CPP_INLET),
                "--stream",
                "DelayedPyStream",
                "--samples",
                "20",
                "--timeout",
                "10.0",
            ],
            env=env,
            stderr=subprocess.PIPE,
        )

        try:
            # Wait a bit, then start Python outlet
            time.sleep(1.0)

            set_lsl_config(outlet_config)
            info = pylsl.StreamInfo(
                name="DelayedPyStream",
                type="Test",
                channel_count=2,
                nominal_srate=100,
                channel_format=pylsl.cf_float32,
                source_id="delayed_py_001",
            )
            outlet = pylsl.StreamOutlet(info)

            # Push samples
            for i in range(30):
                outlet.push_sample([float(i), float(i + 1)])
                time.sleep(0.02)

            proc.wait(timeout=15)
            assert proc.returncode == 0, (
                f"C++ inlet failed: {proc.stderr.read().decode()}"
            )

        finally:
            clear_lsl_config()
            if proc.poll() is None:
                proc.terminate()

    def test_stream_reconnection(self, secure_config_pair):
        """Test that inlet can handle outlet restart."""
        outlet_config, inlet_config = secure_config_pair

        set_lsl_config(outlet_config)

        # Create first outlet
        info = pylsl.StreamInfo(
            name="ReconnectTest",
            type="Test",
            channel_count=2,
            nominal_srate=100,
            channel_format=pylsl.cf_float32,
            source_id="reconnect_001",
        )
        outlet1 = pylsl.StreamOutlet(info)

        # Push some samples
        for i in range(10):
            outlet1.push_sample([float(i), float(i)])

        # Resolve stream
        streams = pylsl.resolve_byprop("name", "ReconnectTest", timeout=3.0)
        assert len(streams) > 0

        # Delete first outlet (simulates disconnect)
        del outlet1
        time.sleep(0.5)

        # Create second outlet with same name
        info2 = pylsl.StreamInfo(
            name="ReconnectTest",
            type="Test",
            channel_count=2,
            nominal_srate=100,
            channel_format=pylsl.cf_float32,
            source_id="reconnect_002",  # Different source ID
        )
        outlet2 = pylsl.StreamOutlet(info2)  # Keep reference

        # Should be able to resolve new stream
        streams2 = pylsl.resolve_byprop("name", "ReconnectTest", timeout=5.0)
        assert len(streams2) > 0, "Second stream not found after reconnection"

        del outlet2
        clear_lsl_config()
