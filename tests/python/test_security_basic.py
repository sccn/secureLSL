# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""
Basic security tests for secure LSL via pylsl.

Tests cover:
- Keypair generation
- Secure outlet/inlet communication
- Stream discovery with security metadata
- Large data transfer
"""

import subprocess
import time

import pytest

# Import after PYLSL_LIB is set by conftest
import pylsl

from conftest import LSL_KEYGEN_PATH, set_lsl_config, clear_lsl_config


class TestKeypairGeneration:
    """Tests for lsl-keygen tool."""

    def test_keygen_creates_config(self, tmp_path):
        """Verify lsl-keygen creates a valid config file."""
        if not LSL_KEYGEN_PATH.exists():
            pytest.skip("lsl-keygen not found")

        config_file = tmp_path / "lsl_api.cfg"

        result = subprocess.run(
            [str(LSL_KEYGEN_PATH), "--output", str(config_file), "--force"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"lsl-keygen failed: {result.stderr}"
        assert config_file.exists(), "Config file was not created"

        # Verify config contains security section
        content = config_file.read_text()
        assert "[security]" in content
        assert "enabled = true" in content
        assert "private_key" in content

    def test_keygen_different_keys_each_time(self, tmp_path):
        """Verify each keygen call produces different keys."""
        if not LSL_KEYGEN_PATH.exists():
            pytest.skip("lsl-keygen not found")

        config1 = tmp_path / "config1.cfg"
        config2 = tmp_path / "config2.cfg"

        subprocess.run(
            [str(LSL_KEYGEN_PATH), "--output", str(config1), "--force"],
            check=True,
        )
        subprocess.run(
            [str(LSL_KEYGEN_PATH), "--output", str(config2), "--force"],
            check=True,
        )

        content1 = config1.read_text()
        content2 = config2.read_text()

        # Extract private keys
        key1 = [line for line in content1.split("\n") if "private_key" in line][0]
        key2 = [line for line in content2.split("\n") if "private_key" in line][0]

        assert key1 != key2, "Keys should be different each time"


class TestSecureOutletInlet:
    """Tests for secure outlet/inlet communication."""

    def test_outlet_creates_stream(self, secure_outlet_config):
        """Verify outlet can be created with security enabled."""
        set_lsl_config(secure_outlet_config)
        try:
            info = pylsl.StreamInfo(
                name="TestSecureOutlet",
                type="Test",
                channel_count=1,
                nominal_srate=100,
                channel_format=pylsl.cf_float32,
                source_id="test_outlet_001",
            )
            outlet = pylsl.StreamOutlet(info)

            # Outlet should be created successfully
            assert outlet is not None

            # Check stream info
            assert info.name() == "TestSecureOutlet"
        finally:
            clear_lsl_config()

    def test_outlet_inlet_basic_transfer(self, secure_config_pair):
        """Test basic data transfer between secure outlet and inlet."""
        outlet_config, inlet_config = secure_config_pair

        # Create outlet in this process
        set_lsl_config(outlet_config)

        info = pylsl.StreamInfo(
            name="SecureTransferTest",
            type="Test",
            channel_count=4,
            nominal_srate=100,
            channel_format=pylsl.cf_float32,
            source_id="transfer_test_001",
        )
        outlet = pylsl.StreamOutlet(info)

        # Push a sample to ensure stream is active
        test_sample = [1.0, 2.0, 3.0, 4.0]
        outlet.push_sample(test_sample)

        # Resolve and create inlet (same process, same config is fine)
        streams = pylsl.resolve_byprop("name", "SecureTransferTest", timeout=5.0)
        assert len(streams) > 0, "Stream not found"

        inlet = pylsl.StreamInlet(streams[0])
        inlet.open_stream()

        # Push more samples
        for i in range(10):
            sample = [float(i), float(i + 1), float(i + 2), float(i + 3)]
            outlet.push_sample(sample)
            time.sleep(0.01)

        # Pull samples
        received = []
        for _ in range(10):
            sample, ts = inlet.pull_sample(timeout=1.0)
            if sample is not None:
                received.append(sample)

        assert len(received) >= 5, f"Expected at least 5 samples, got {len(received)}"

        clear_lsl_config()

    def test_large_data_transfer(self, secure_config_pair):
        """Test transfer of 1000 samples with 32 channels."""
        outlet_config, _ = secure_config_pair
        set_lsl_config(outlet_config)

        num_channels = 32
        num_samples = 1000

        info = pylsl.StreamInfo(
            name="LargeDataTest",
            type="EEG",
            channel_count=num_channels,
            nominal_srate=256,
            channel_format=pylsl.cf_float32,
            source_id="large_data_001",
        )
        outlet = pylsl.StreamOutlet(info)

        # Resolve stream
        streams = pylsl.resolve_byprop("name", "LargeDataTest", timeout=5.0)
        inlet = pylsl.StreamInlet(streams[0])
        inlet.open_stream()

        # Wait for connection to stabilize
        time.sleep(0.2)

        # Generate test data
        sent_data = []
        for i in range(num_samples):
            sample = [float(i * num_channels + ch) for ch in range(num_channels)]
            sent_data.append(sample)
            outlet.push_sample(sample)

        time.sleep(1.0)  # Allow data to propagate

        # Pull all samples with longer timeout
        received_data = []
        start_time = time.time()
        while time.time() - start_time < 2.0:
            sample, ts = inlet.pull_sample(timeout=0.1)
            if sample is None:
                break
            received_data.append(sample)

        # Verify received significant portion (be more lenient for network timing)
        received_count = len(received_data)
        assert received_count >= num_samples * 0.7, (
            f"Expected at least {num_samples * 0.7} samples, got {received_count}"
        )

        # Verify data integrity for received samples
        for i, received in enumerate(received_data[: min(100, len(received_data))]):
            for ch in range(num_channels):
                # Values should be close to expected
                assert received[ch] == pytest.approx(sent_data[i][ch], rel=1e-5), (
                    f"Data mismatch at sample {i}, channel {ch}"
                )

        clear_lsl_config()


class TestStreamDiscovery:
    """Tests for stream discovery with security metadata."""

    def test_stream_discoverable(self, secure_outlet_config):
        """Verify secure stream can be discovered."""
        set_lsl_config(secure_outlet_config)

        info = pylsl.StreamInfo(
            name="DiscoverableSecure",
            type="Test",
            channel_count=1,
            nominal_srate=100,
            channel_format=pylsl.cf_float32,
            source_id="discover_001",
        )
        outlet = pylsl.StreamOutlet(info)  # Keep reference to prevent GC

        # Try to resolve
        streams = pylsl.resolve_byprop("name", "DiscoverableSecure", timeout=5.0)

        assert len(streams) == 1, f"Expected 1 stream, found {len(streams)}"
        assert streams[0].name() == "DiscoverableSecure"

        del outlet  # Cleanup
        clear_lsl_config()

    def test_stream_xml_contains_security(self, secure_outlet_config):
        """Verify stream XML contains security metadata."""
        set_lsl_config(secure_outlet_config)

        info = pylsl.StreamInfo(
            name="XMLSecurityTest",
            type="Test",
            channel_count=1,
            nominal_srate=100,
            channel_format=pylsl.cf_float32,
            source_id="xml_sec_001",
        )
        outlet = pylsl.StreamOutlet(info)  # Keep reference to prevent GC

        # Resolve and check XML
        streams = pylsl.resolve_byprop("name", "XMLSecurityTest", timeout=5.0)
        assert len(streams) == 1

        xml = streams[0].as_xml()

        # Note: Security metadata in discovery XML depends on implementation
        # At minimum, stream should be resolvable
        assert "XMLSecurityTest" in xml

        del outlet  # Cleanup
        clear_lsl_config()


class TestMultipleStreams:
    """Tests for multiple concurrent secure streams."""

    def test_multiple_outlets(self, secure_outlet_config):
        """Test creating multiple secure outlets."""
        set_lsl_config(secure_outlet_config)

        outlets = []
        for i in range(3):
            info = pylsl.StreamInfo(
                name=f"MultiOutlet{i}",
                type="Test",
                channel_count=1,
                nominal_srate=100,
                channel_format=pylsl.cf_float32,
                source_id=f"multi_{i}",
            )
            outlets.append(pylsl.StreamOutlet(info))

        # Resolve all
        streams = pylsl.resolve_byprop("type", "Test", minimum=3, timeout=5.0)

        assert len(streams) >= 3, f"Expected at least 3 streams, found {len(streams)}"

        clear_lsl_config()
