# Copyright (C) 2025-2026 The Regents of the University of California. All Rights Reserved.
# Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
# See LICENSE in the repository root for terms.

"""
Pytest fixtures for secure LSL Python tests.

Provides fixtures for:
- Keypair generation via lsl-keygen
- Secure configuration setup
- PYLSL_LIB environment configuration
"""

import os
import subprocess
from pathlib import Path

import pytest

# Path to the secure liblsl build
LIBLSL_PATH = Path(__file__).parent.parent.parent / "liblsl" / "build" / "liblsl.dylib"

# Set PYLSL_LIB before any modules are imported
# This must happen at module load time, not in a fixture
if LIBLSL_PATH.exists():
    os.environ["PYLSL_LIB"] = str(LIBLSL_PATH)

# Import security helper to patch pylsl with security_enabled/security_fingerprint methods
# This must happen before test modules import pylsl
try:
    import lsl_security_helper  # noqa: F401
except ImportError:
    pass  # Helper not available

LSL_KEYGEN_PATH = (
    Path(__file__).parent.parent.parent / "liblsl" / "build" / "lsl-keygen"
)
LSL_CONFIG_PATH = (
    Path(__file__).parent.parent.parent / "liblsl" / "build" / "lsl-config"
)


@pytest.fixture(scope="session", autouse=True)
def setup_pylsl_lib():
    """Ensure secure liblsl is available."""
    if not LIBLSL_PATH.exists():
        pytest.skip(f"Secure liblsl not found at {LIBLSL_PATH}")
    yield


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary directory for LSL configuration."""
    config_dir = tmp_path / "lsl_config"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def generate_keypair(temp_config_dir):
    """Generate a keypair using lsl-keygen and return the config path."""
    if not LSL_KEYGEN_PATH.exists():
        pytest.skip(f"lsl-keygen not found at {LSL_KEYGEN_PATH}")

    config_file = temp_config_dir / "lsl_api.cfg"

    result = subprocess.run(
        [str(LSL_KEYGEN_PATH), "--output", str(config_file), "--force"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pytest.fail(f"lsl-keygen failed: {result.stderr}")

    return config_file


@pytest.fixture
def secure_outlet_config(tmp_path):
    """Generate keypair for outlet and return config path."""
    if not LSL_KEYGEN_PATH.exists():
        pytest.skip(f"lsl-keygen not found at {LSL_KEYGEN_PATH}")

    outlet_dir = tmp_path / "outlet"
    outlet_dir.mkdir()
    config_file = outlet_dir / "lsl_api.cfg"

    result = subprocess.run(
        [str(LSL_KEYGEN_PATH), "--output", str(config_file), "--force"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pytest.fail(f"lsl-keygen failed for outlet: {result.stderr}")

    return config_file


@pytest.fixture
def secure_inlet_config(tmp_path):
    """Generate keypair for inlet and return config path."""
    if not LSL_KEYGEN_PATH.exists():
        pytest.skip(f"lsl-keygen not found at {LSL_KEYGEN_PATH}")

    inlet_dir = tmp_path / "inlet"
    inlet_dir.mkdir()
    config_file = inlet_dir / "lsl_api.cfg"

    result = subprocess.run(
        [str(LSL_KEYGEN_PATH), "--output", str(config_file), "--force"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pytest.fail(f"lsl-keygen failed for inlet: {result.stderr}")

    return config_file


@pytest.fixture
def secure_config_pair(tmp_path):
    """Generate keypairs for both outlet and inlet, return tuple of paths."""
    if not LSL_KEYGEN_PATH.exists():
        pytest.skip(f"lsl-keygen not found at {LSL_KEYGEN_PATH}")

    outlet_dir = tmp_path / "outlet"
    inlet_dir = tmp_path / "inlet"
    outlet_dir.mkdir()
    inlet_dir.mkdir()

    outlet_config = outlet_dir / "lsl_api.cfg"
    inlet_config = inlet_dir / "lsl_api.cfg"

    # Generate outlet keypair
    result = subprocess.run(
        [str(LSL_KEYGEN_PATH), "--output", str(outlet_config), "--force"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"lsl-keygen failed for outlet: {result.stderr}")

    # Generate inlet keypair
    result = subprocess.run(
        [str(LSL_KEYGEN_PATH), "--output", str(inlet_config), "--force"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"lsl-keygen failed for inlet: {result.stderr}")

    return outlet_config, inlet_config


@pytest.fixture
def insecure_config(tmp_path):
    """Create a config file with security disabled."""
    config_dir = tmp_path / "insecure"
    config_dir.mkdir()
    config_file = config_dir / "lsl_api.cfg"

    config_file.write_text(
        """[security]
enabled = false

[log]
level = 6
"""
    )

    return config_file


def set_lsl_config(config_path):
    """Helper to set LSLAPICFG environment variable."""
    os.environ["LSLAPICFG"] = str(config_path)


def clear_lsl_config():
    """Helper to clear LSLAPICFG environment variable."""
    os.environ.pop("LSLAPICFG", None)


@pytest.fixture
def with_secure_config(secure_outlet_config):
    """Context manager to temporarily set secure config."""
    set_lsl_config(secure_outlet_config)
    yield secure_outlet_config
    clear_lsl_config()
