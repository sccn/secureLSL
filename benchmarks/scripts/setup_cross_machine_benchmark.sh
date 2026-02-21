#!/bin/bash
#
# Secure LSL Cross-Machine Benchmark Setup Script
#
# This script sets up and runs cross-machine benchmarks between a host machine
# (Mac/Linux) and a Raspberry Pi connected via direct Ethernet and/or WiFi.
#
# Prerequisites:
# - Raspberry Pi with secureLSL deployed (use deploy_to_rpi.sh first)
# - SSH key-based authentication configured
# - For Ethernet: Direct cable connection between host and RPi
#
# Usage:
#   ./setup_cross_machine_benchmark.sh [OPTIONS]
#
# Options:
#   --wifi-host HOSTNAME    SSH hostname for WiFi connection (default: pi)
#   --eth-host HOSTNAME     SSH hostname for Ethernet connection (default: pi-eth)
#   --eth-ip IP             Static IP for host Ethernet interface (default: 192.168.10.1)
#   --rpi-eth-ip IP         Static IP for RPi Ethernet interface (default: 192.168.10.2)
#   --eth-interface IFACE   Host Ethernet interface name (default: auto-detect)
#   --iterations N          Number of benchmark iterations (default: 5)
#   --channels N            Number of channels to stream (default: 64)
#   --rate HZ               Sample rate in Hz (default: 1000)
#   --duration SECS         Duration of each test in seconds (default: 30)
#   --skip-ethernet         Skip Ethernet tests (WiFi only)
#   --skip-wifi             Skip WiFi tests (Ethernet only)
#   --help                  Show this help message
#

set -e

# Default configuration
WIFI_HOST="pi"
ETH_HOST="pi-eth"
HOST_ETH_IP="192.168.10.1"
RPI_ETH_IP="192.168.10.2"
ETH_INTERFACE=""
ITERATIONS=5
CHANNELS=64
RATE=1000
DURATION=30
SKIP_ETHERNET=false
SKIP_WIFI=false
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/../results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_help() {
    head -35 "$0" | tail -30
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --wifi-host) WIFI_HOST="$2"; shift 2 ;;
        --eth-host) ETH_HOST="$2"; shift 2 ;;
        --eth-ip) HOST_ETH_IP="$2"; shift 2 ;;
        --rpi-eth-ip) RPI_ETH_IP="$2"; shift 2 ;;
        --eth-interface) ETH_INTERFACE="$2"; shift 2 ;;
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --channels) CHANNELS="$2"; shift 2 ;;
        --rate) RATE="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --skip-ethernet) SKIP_ETHERNET=true; shift ;;
        --skip-wifi) SKIP_WIFI=true; shift ;;
        --help) show_help ;;
        *) log_error "Unknown option: $1"; show_help ;;
    esac
done

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin*) echo "macos" ;;
        Linux*) echo "linux" ;;
        *) echo "unknown" ;;
    esac
}

OS=$(detect_os)
log_info "Detected OS: $OS"

# Auto-detect Ethernet interface if not specified
detect_ethernet_interface() {
    if [[ -n "$ETH_INTERFACE" ]]; then
        echo "$ETH_INTERFACE"
        return
    fi

    if [[ "$OS" == "macos" ]]; then
        # On Mac, en0 is typically the built-in Ethernet
        if networksetup -listallhardwareports | grep -A1 "Ethernet" | grep -q "en0"; then
            echo "en0"
        else
            # Find first Ethernet interface
            networksetup -listallhardwareports | grep -A1 "Ethernet" | grep "Device:" | head -1 | awk '{print $2}'
        fi
    else
        # On Linux, look for eth0 or enp*
        ip link show | grep -E "^[0-9]+: (eth|enp)" | head -1 | cut -d: -f2 | tr -d ' '
    fi
}

# Setup Ethernet on host
setup_host_ethernet() {
    local iface=$(detect_ethernet_interface)

    if [[ -z "$iface" ]]; then
        log_error "Could not detect Ethernet interface"
        return 1
    fi

    log_info "Setting up Ethernet on interface: $iface"

    if [[ "$OS" == "macos" ]]; then
        # Check if IP is already set
        if ifconfig "$iface" | grep -q "$HOST_ETH_IP"; then
            log_info "IP $HOST_ETH_IP already configured on $iface"
        else
            log_info "Setting IP $HOST_ETH_IP on $iface (may require sudo)"
            sudo ifconfig "$iface" "$HOST_ETH_IP" netmask 255.255.255.0 up
        fi

        # Add route if not present
        if ! netstat -rn | grep -q "192.168.10.*$iface"; then
            log_info "Adding route for 192.168.10.0/24 via $iface (may require sudo)"
            sudo route add -net 192.168.10.0/24 -interface "$iface" 2>/dev/null || true
        fi
    else
        # Linux
        if ! ip addr show "$iface" | grep -q "$HOST_ETH_IP"; then
            log_info "Setting IP $HOST_ETH_IP on $iface (may require sudo)"
            sudo ip addr add "$HOST_ETH_IP/24" dev "$iface" 2>/dev/null || true
            sudo ip link set "$iface" up
        fi
    fi

    ETH_INTERFACE="$iface"
}

# Setup Ethernet on RPi
setup_rpi_ethernet() {
    log_info "Setting up Ethernet on RPi..."

    # Use WiFi connection to configure Ethernet
    if ! ssh "$WIFI_HOST" "ip addr show eth0 | grep -q '$RPI_ETH_IP'" 2>/dev/null; then
        log_info "Adding IP $RPI_ETH_IP to RPi eth0"
        ssh "$WIFI_HOST" "sudo ip addr add $RPI_ETH_IP/24 dev eth0 2>/dev/null || true"
    else
        log_info "IP $RPI_ETH_IP already configured on RPi eth0"
    fi
}

# Test connectivity
test_connectivity() {
    local host="$1"
    local desc="$2"

    log_info "Testing $desc connectivity..."

    if ssh -o ConnectTimeout=5 "$host" "echo 'SSH OK'" >/dev/null 2>&1; then
        log_info "$desc SSH: OK"
        return 0
    else
        log_warn "$desc SSH: FAILED"
        return 1
    fi
}

# Run benchmark iterations
run_benchmarks() {
    local host="$1"
    local output_dir="$2"
    local desc="$3"

    log_info "Running $ITERATIONS iterations over $desc..."
    mkdir -p "$output_dir"

    for i in $(seq 1 $ITERATIONS); do
        log_info "=== $desc Iteration $i/$ITERATIONS ==="

        local iter_dir="$output_dir/iter$i"

        "$SCRIPT_DIR/run_cross_machine.sh" "$host" \
            -c "$CHANNELS" \
            -r "$RATE" \
            -d "$DURATION"

        # Move results to organized directory
        local latest=$(ls -td "$RESULTS_DIR"/cross_machine_* 2>/dev/null | head -1)
        if [[ -n "$latest" ]]; then
            mv "$latest" "$iter_dir"
        fi

        sleep 3
    done
}

# Main execution
main() {
    echo "=============================================="
    echo "  Secure LSL Cross-Machine Benchmark Setup"
    echo "=============================================="
    echo
    echo "Configuration:"
    echo "  WiFi host:     $WIFI_HOST"
    echo "  Ethernet host: $ETH_HOST"
    echo "  Host ETH IP:   $HOST_ETH_IP"
    echo "  RPi ETH IP:    $RPI_ETH_IP"
    echo "  Iterations:    $ITERATIONS"
    echo "  Channels:      $CHANNELS"
    echo "  Rate:          $RATE Hz"
    echo "  Duration:      $DURATION s"
    echo

    # Create timestamped results directory
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    # Test WiFi connectivity first (needed for Ethernet setup)
    if ! test_connectivity "$WIFI_HOST" "WiFi"; then
        log_error "Cannot connect to RPi via WiFi. Please check SSH configuration."
        exit 1
    fi

    # Setup and run Ethernet tests
    if [[ "$SKIP_ETHERNET" != "true" ]]; then
        log_info "Setting up Ethernet connection..."
        setup_host_ethernet
        setup_rpi_ethernet

        # Wait for network to stabilize
        sleep 2

        # Test Ethernet connectivity
        if ping -c 2 "$RPI_ETH_IP" >/dev/null 2>&1; then
            log_info "Ethernet ping: OK"

            if test_connectivity "$ETH_HOST" "Ethernet"; then
                ETH_RESULTS_DIR="$RESULTS_DIR/ethernet_${TIMESTAMP}"
                run_benchmarks "$ETH_HOST" "$ETH_RESULTS_DIR" "Ethernet"
            else
                log_warn "Ethernet SSH failed, skipping Ethernet tests"
            fi
        else
            log_warn "Ethernet ping failed, skipping Ethernet tests"
        fi
    fi

    # Run WiFi tests
    if [[ "$SKIP_WIFI" != "true" ]]; then
        WIFI_RESULTS_DIR="$RESULTS_DIR/wifi_${TIMESTAMP}"
        run_benchmarks "$WIFI_HOST" "$WIFI_RESULTS_DIR" "WiFi"
    fi

    # Run statistical analysis
    log_info "Running statistical analysis..."

    if [[ -d "$ETH_RESULTS_DIR" ]]; then
        echo
        echo "=== ETHERNET STATISTICAL ANALYSIS ==="
        python3 "$SCRIPT_DIR/statistical_analysis.py" "$ETH_RESULTS_DIR" || true
    fi

    if [[ -d "$WIFI_RESULTS_DIR" ]]; then
        echo
        echo "=== WIFI STATISTICAL ANALYSIS ==="
        python3 "$SCRIPT_DIR/statistical_analysis.py" "$WIFI_RESULTS_DIR" || true
    fi

    echo
    log_info "Benchmark complete!"
    echo
    echo "Results saved to:"
    [[ -d "$ETH_RESULTS_DIR" ]] && echo "  Ethernet: $ETH_RESULTS_DIR"
    [[ -d "$WIFI_RESULTS_DIR" ]] && echo "  WiFi:     $WIFI_RESULTS_DIR"
}

main "$@"
