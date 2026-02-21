#!/bin/bash
# deploy_to_rpi.sh - Deploy Secure LSL benchmarks to Raspberry Pi
#
# Usage:
#   ./deploy_to_rpi.sh <rpi_host> [options]
#
# Examples:
#   ./deploy_to_rpi.sh pi                    # Using SSH config alias
#   ./deploy_to_rpi.sh pi --build
#   ./deploy_to_rpi.sh pi@192.168.1.100      # Using full hostname
#   ./deploy_to_rpi.sh pi --run-benchmark

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Configuration
RPI_DEPLOY_DIR="~/securelsl_benchmark"
BUILD_ON_PI=false
RUN_BENCHMARK=false
SYNC_ONLY=false

# Parse arguments
RPI_HOST=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --build)
            BUILD_ON_PI=true
            shift
            ;;
        --run-benchmark)
            RUN_BENCHMARK=true
            shift
            ;;
        --sync-only)
            SYNC_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 <rpi_host> [options]"
            echo ""
            echo "Options:"
            echo "  --build          Build liblsl on the RPi after deployment"
            echo "  --run-benchmark  Run the benchmark suite after deployment"
            echo "  --sync-only      Only sync files, skip setup"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 pi                    # Using SSH config alias"
            echo "  $0 pi --build"
            echo "  $0 pi@192.168.1.100      # Using full hostname"
            echo "  $0 pi --run-benchmark"
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
echo "Secure LSL - Raspberry Pi Deployment"
echo "=============================================="
echo "Target: $RPI_HOST"
echo "Deploy dir: $RPI_DEPLOY_DIR"
echo ""

# Test SSH connection
echo "Testing SSH connection..."
if ! ssh -o ConnectTimeout=5 "$RPI_HOST" "echo 'SSH OK'" &>/dev/null; then
    echo "Error: Cannot connect to $RPI_HOST"
    echo "Make sure:"
    echo "  1. RPi is powered on and connected to network"
    echo "  2. SSH is enabled on the RPi"
    echo "  3. SSH key is configured or password auth is enabled"
    exit 1
fi
echo "SSH connection OK"
echo ""

# Create remote directory structure
echo "Creating remote directory structure..."
ssh "$RPI_HOST" "mkdir -p $RPI_DEPLOY_DIR/{benchmarks/scripts,benchmarks/results,liblsl}"

# Sync benchmark scripts
echo "Syncing benchmark scripts..."
rsync -avz --progress \
    "$SCRIPT_DIR/" \
    "$RPI_HOST:$RPI_DEPLOY_DIR/benchmarks/scripts/"

# Sync liblsl source (for building on RPi)
echo "Syncing liblsl source..."
rsync -avz --progress \
    --exclude 'build/' \
    --exclude '.git/' \
    --exclude '*.o' \
    --exclude '*.a' \
    --exclude '*.so' \
    --exclude '*.dylib' \
    "$PROJECT_ROOT/liblsl/" \
    "$RPI_HOST:$RPI_DEPLOY_DIR/liblsl/"

# Sync security keys if they exist
if [[ -d "$PROJECT_ROOT/keys" ]]; then
    echo "Syncing security keys..."
    rsync -avz --progress \
        "$PROJECT_ROOT/keys/" \
        "$RPI_HOST:$RPI_DEPLOY_DIR/keys/"
fi

if [[ "$SYNC_ONLY" == "true" ]]; then
    echo ""
    echo "Sync complete (--sync-only mode)"
    exit 0
fi

# Install dependencies on RPi
echo ""
echo "Installing dependencies on RPi..."
ssh "$RPI_HOST" << 'REMOTE_SETUP'
set -e

echo "Updating package list..."
sudo apt-get update

echo "Installing build dependencies..."
sudo apt-get install -y \
    build-essential \
    cmake \
    libsodium-dev \
    python3-pip \
    python3-numpy \
    python3-psutil \
    python3-matplotlib \
    python3-scipy

echo "Installing Python packages..."
# Try to install pylsl via pip (apt doesn't have it)
# Use --break-system-packages for modern Debian-based systems
if ! pip3 install --user pylsl 2>/dev/null; then
    echo "Attempting with --break-system-packages flag..."
    pip3 install --break-system-packages pylsl
fi

echo "Dependencies installed successfully"
REMOTE_SETUP

# Build liblsl on RPi if requested
if [[ "$BUILD_ON_PI" == "true" ]]; then
    echo ""
    echo "Building liblsl on RPi..."
    ssh "$RPI_HOST" << REMOTE_BUILD
set -e
cd $RPI_DEPLOY_DIR/liblsl
mkdir -p build && cd build
cmake -DLSL_SECURITY=ON -DCMAKE_BUILD_TYPE=Release ..
make -j\$(nproc)
echo ""
echo "Build complete. Library at: \$(pwd)/liblsl.so"
REMOTE_BUILD
fi

# Create convenience scripts on RPi
echo ""
echo "Creating convenience scripts on RPi..."
ssh "$RPI_HOST" << REMOTE_SCRIPTS
cat > $RPI_DEPLOY_DIR/run_benchmark.sh << 'EOF'
#!/bin/bash
# Run benchmark suite on Raspberry Pi
set -e

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
export PYLSL_LIB="\$SCRIPT_DIR/liblsl/build/liblsl.so"

cd "\$SCRIPT_DIR/benchmarks/scripts"

# Default: run channel sweep with 30s duration
python3 run_benchmark_suite.py \\
    --duration 30 \\
    --suite channel-sweep \\
    --output ../results \\
    "\$@"
EOF
chmod +x $RPI_DEPLOY_DIR/run_benchmark.sh

cat > $RPI_DEPLOY_DIR/run_inlet.sh << 'EOF'
#!/bin/bash
# Run inlet benchmark (for remote testing with macmini outlet)
set -e

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
export PYLSL_LIB="\$SCRIPT_DIR/liblsl/build/liblsl.so"

cd "\$SCRIPT_DIR/benchmarks/scripts"
python3 benchmark_inlet.py "\$@"
EOF
chmod +x $RPI_DEPLOY_DIR/run_inlet.sh

cat > $RPI_DEPLOY_DIR/run_outlet.sh << 'EOF'
#!/bin/bash
# Run outlet benchmark (for remote testing with macmini inlet)
set -e

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
export PYLSL_LIB="\$SCRIPT_DIR/liblsl/build/liblsl.so"

cd "\$SCRIPT_DIR/benchmarks/scripts"
python3 benchmark_outlet.py "\$@"
EOF
chmod +x $RPI_DEPLOY_DIR/run_outlet.sh

echo "Created: run_benchmark.sh, run_inlet.sh, run_outlet.sh"
REMOTE_SCRIPTS

# Run benchmark if requested
if [[ "$RUN_BENCHMARK" == "true" ]]; then
    echo ""
    echo "Running benchmark on RPi..."
    ssh "$RPI_HOST" "$RPI_DEPLOY_DIR/run_benchmark.sh"
fi

echo ""
echo "=============================================="
echo "Deployment complete!"
echo "=============================================="
echo ""
echo "Next steps on RPi ($RPI_HOST):"
echo "  1. Build liblsl (if not done):"
echo "     ssh $RPI_HOST"
echo "     cd $RPI_DEPLOY_DIR/liblsl/build && cmake .. && make -j4"
echo ""
echo "  2. Run local benchmark:"
echo "     ssh $RPI_HOST '$RPI_DEPLOY_DIR/run_benchmark.sh'"
echo ""
echo "  3. For cross-machine testing, use the run_cross_machine.sh script:"
echo "     ./run_cross_machine.sh $RPI_HOST"
echo ""
echo "  4. Or manually:"
echo "     On Mac Mini (outlet): python benchmark_outlet.py -c 64 -r 1000 -d 30"
echo "     On RPi (inlet):       ssh $RPI_HOST '$RPI_DEPLOY_DIR/run_inlet.sh -c 64 -r 1000 -d 30'"
echo ""
echo "  5. Retrieve results:"
echo "     scp $RPI_HOST:$RPI_DEPLOY_DIR/benchmarks/results/*.json ./benchmarks/results/rpi5/"
