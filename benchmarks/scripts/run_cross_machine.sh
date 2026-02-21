#!/bin/bash
# run_cross_machine.sh - Run cross-machine benchmark between Mac Mini and RPi
#
# Usage:
#   ./run_cross_machine.sh <rpi_host> [options]
#
# This script coordinates outlet/inlet processes across two machines to measure
# network latency with and without encryption.
#
# Note: <rpi_host> can be an SSH config alias (e.g., "pi") or full hostname (e.g., "pi@192.168.1.100")

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
RPI_DEPLOY_DIR="~/securelsl_benchmark"

# Default configuration
CHANNELS=64
RATE=1000
DURATION=30
RUN_SECURE=true
RUN_INSECURE=true
LOCAL_AS_OUTLET=true  # Mac as outlet, RPi as inlet

# Parse arguments
RPI_HOST=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--channels)
            CHANNELS="$2"
            shift 2
            ;;
        -r|--rate)
            RATE="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        --secure-only)
            RUN_INSECURE=false
            shift
            ;;
        --insecure-only)
            RUN_SECURE=false
            shift
            ;;
        --rpi-outlet)
            LOCAL_AS_OUTLET=false
            shift
            ;;
        --help|-h)
            echo "Usage: $0 <rpi_host> [options]"
            echo ""
            echo "Options:"
            echo "  -c, --channels N    Number of channels (default: 64)"
            echo "  -r, --rate N        Sampling rate in Hz (default: 1000)"
            echo "  -d, --duration N    Test duration in seconds (default: 30)"
            echo "  --secure-only       Only run secure (encrypted) test"
            echo "  --insecure-only     Only run insecure (plaintext) test"
            echo "  --rpi-outlet        Run outlet on RPi, inlet on Mac (default: Mac outlet)"
            echo "  -h, --help          Show this help"
            echo ""
            echo "Note: <rpi_host> can be an SSH config alias or full hostname"
            echo ""
            echo "Examples:"
            echo "  $0 pi                              # Using SSH config alias"
            echo "  $0 pi -c 128 -r 2000 -d 60"
            echo "  $0 pi@192.168.1.100                # Using full hostname"
            echo "  $0 pi --secure-only"
            exit 0
            ;;
        *)
            if [[ -z "$RPI_HOST" ]]; then
                RPI_HOST="$1"
            else
                echo "Error: Unknown option: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "$RPI_HOST" ]]; then
    echo "Error: No RPi host specified"
    echo "Usage: $0 <rpi_host> [options]"
    exit 1
fi

echo "=============================================="
echo "Secure LSL - Cross-Machine Benchmark"
echo "=============================================="
echo "Configuration:"
echo "  Channels:  $CHANNELS"
echo "  Rate:      $RATE Hz"
echo "  Duration:  $DURATION seconds"
echo "  RPi Host:  $RPI_HOST"
if [[ "$LOCAL_AS_OUTLET" == "true" ]]; then
    echo "  Topology:  Mac (outlet) -> RPi (inlet)"
else
    echo "  Topology:  RPi (outlet) -> Mac (inlet)"
fi
echo ""

# Test connectivity
echo "Testing SSH connection to RPi..."
if ! ssh -o ConnectTimeout=5 "$RPI_HOST" "echo 'OK'" &>/dev/null; then
    echo "Error: Cannot connect to $RPI_HOST"
    exit 1
fi
echo "Connection OK"
echo ""

# Create results directories
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOCAL_RESULTS_DIR="$PROJECT_ROOT/benchmarks/results/cross_machine_$TIMESTAMP"
mkdir -p "$LOCAL_RESULTS_DIR"

# Set up environment
export PYLSL_LIB="$PROJECT_ROOT/liblsl/build/liblsl.dylib"
if [[ ! -f "$PYLSL_LIB" ]]; then
    echo "Warning: Local liblsl not found at $PYLSL_LIB"
    echo "Make sure liblsl is built with: cd liblsl/build && cmake .. && make"
fi

# Activate conda environment if available
if [[ -f ~/miniconda3/etc/profile.d/conda.sh ]]; then
    source ~/miniconda3/etc/profile.d/conda.sh
    conda activate securelsl 2>/dev/null || true
fi

# Function to create config file
create_config() {
    local enabled="$1"
    local config_file="$2"
    cat > "$config_file" << EOF
[security]
enabled = $enabled
EOF
}

# Function to run a single cross-machine test
run_cross_test() {
    local secure="$1"
    local label="$2"

    echo ""
    echo "=============================================="
    echo "Running: $label"
    echo "=============================================="

    # Create temp config files
    local local_config="/tmp/lsl_api_local_$$.cfg"
    local remote_config="/tmp/lsl_api_remote_$$.cfg"

    if [[ "$secure" == "true" ]]; then
        create_config "true" "$local_config"
    else
        create_config "false" "$local_config"
    fi

    # Copy config to RPi
    scp "$local_config" "$RPI_HOST:/tmp/lsl_api.cfg" &>/dev/null

    export LSLAPICFG="$local_config"

    local outlet_output="$LOCAL_RESULTS_DIR/outlet_${label}_$TIMESTAMP.json"
    local inlet_output="$LOCAL_RESULTS_DIR/inlet_${label}_$TIMESTAMP.json"

    if [[ "$LOCAL_AS_OUTLET" == "true" ]]; then
        # Mac as outlet, RPi as inlet
        echo "Starting outlet on Mac..."
        python3 "$SCRIPT_DIR/benchmark_outlet.py" \
            -c "$CHANNELS" -r "$RATE" -d "$DURATION" \
            --name "CrossMachine-$label" \
            -o "$outlet_output" \
            $([ "$secure" == "true" ] && echo "--secure" || echo "--insecure") &
        local outlet_pid=$!

        # Wait for outlet to be ready
        sleep 2

        echo "Starting inlet on RPi..."
        ssh "$RPI_HOST" "LSLAPICFG=/tmp/lsl_api.cfg PYLSL_LIB=$RPI_DEPLOY_DIR/liblsl/build/liblsl.so python3 $RPI_DEPLOY_DIR/benchmarks/scripts/benchmark_inlet.py -d $DURATION --name 'CrossMachine-$label' -o /tmp/inlet_result.json $([ "$secure" == "true" ] && echo "--secure" || echo "--insecure")"

        # Wait for outlet to finish
        wait $outlet_pid 2>/dev/null || true

        # Copy inlet results from RPi
        scp "$RPI_HOST:/tmp/inlet_result.json" "$inlet_output" &>/dev/null || echo "Warning: Could not copy inlet results"

    else
        # RPi as outlet, Mac as inlet
        echo "Starting outlet on RPi..."
        ssh "$RPI_HOST" "LSLAPICFG=/tmp/lsl_api.cfg PYLSL_LIB=$RPI_DEPLOY_DIR/liblsl/build/liblsl.so python3 $RPI_DEPLOY_DIR/benchmarks/scripts/benchmark_outlet.py -c $CHANNELS -r $RATE -d $DURATION --name 'CrossMachine-$label' -o /tmp/outlet_result.json $([ "$secure" == "true" ] && echo "--secure" || echo "--insecure")" &
        local outlet_pid=$!

        # Wait for outlet to be ready
        sleep 2

        echo "Starting inlet on Mac..."
        python3 "$SCRIPT_DIR/benchmark_inlet.py" \
            -d "$DURATION" \
            --name "CrossMachine-$label" \
            -o "$inlet_output" \
            $([ "$secure" == "true" ] && echo "--secure" || echo "--insecure")

        # Wait for outlet to finish
        wait $outlet_pid 2>/dev/null || true

        # Copy outlet results from RPi
        scp "$RPI_HOST:/tmp/outlet_result.json" "$outlet_output" &>/dev/null || echo "Warning: Could not copy outlet results"
    fi

    # Cleanup
    rm -f "$local_config"
    ssh "$RPI_HOST" "rm -f /tmp/lsl_api.cfg /tmp/inlet_result.json /tmp/outlet_result.json" &>/dev/null || true

    echo "Results saved to: $LOCAL_RESULTS_DIR"
}

# Run tests
if [[ "$RUN_INSECURE" == "true" ]]; then
    run_cross_test "false" "insecure"
fi

if [[ "$RUN_SECURE" == "true" ]]; then
    run_cross_test "true" "secure"
fi

echo ""
echo "=============================================="
echo "Cross-machine benchmark complete!"
echo "=============================================="
echo ""
echo "Results saved to: $LOCAL_RESULTS_DIR"
echo ""
echo "To analyze results:"
echo "  python3 $SCRIPT_DIR/analyze_results.py $LOCAL_RESULTS_DIR/*.json -o $LOCAL_RESULTS_DIR/figures"
