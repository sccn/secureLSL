# MATLAB Tests for Secure LSL

This directory contains MATLAB tests for validating the secure LSL implementation.

## Prerequisites

1. **MATLAB** (R2020b or later recommended)

2. **liblsl-Matlab**: Clone into the project root:
   ```bash
   cd /path/to/secureLSL
   git clone https://github.com/labstreaminglayer/liblsl-Matlab.git
   ```

3. **Built secure liblsl**: The tests expect the library at `liblsl/build/liblsl.dylib`
   ```bash
   cd liblsl
   mkdir -p build && cd build
   cmake -DLSL_SECURITY=ON ..
   cmake --build . --parallel
   ```

## Running Tests

From MATLAB:

```matlab
cd /path/to/secureLSL/tests/matlab
results = test_security_basic();
```

Or from the command line:

```bash
matlab -nodisplay -r "addpath('/path/to/secureLSL/tests/matlab'); test_security_basic(); exit"
```

## Test Files

- `setup_lsl.m` - Helper to load the secure liblsl library
- `test_security_basic.m` - Basic security validation tests
- `test_interop.m` - Cross-language interoperability tests (MATLAB <-> C++)

## Notes

- Tests use temporary keypairs generated via `lsl-keygen`
- The `LSLAPICFG` environment variable is set during tests
- liblsl-Matlab is not committed to this repo; clone it as a dependency
