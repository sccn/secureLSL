function results = test_security_basic()
% TEST_SECURITY_BASIC Basic security tests for secure LSL via MATLAB
%
%   results = TEST_SECURITY_BASIC() runs the security validation tests
%   and returns a struct with test results.
%
%   Prerequisites:
%   1. liblsl-Matlab must be installed and in MATLAB path
%      Get it from: https://github.com/labstreaminglayer/liblsl-Matlab
%   2. Set LSL_MATLAB_PATH environment variable or add to MATLAB path
%   3. Secure liblsl.dylib must be built in liblsl/build/
%   4. lsl-keygen must be built to generate security configuration
%
%   Example:
%     addpath('/path/to/liblsl-Matlab');
%     results = test_security_basic();

    fprintf('=== Secure LSL MATLAB Tests ===\n\n');

    results = struct();
    results.passed = 0;
    results.failed = 0;
    results.skipped = 0;

    % Check prerequisites
    if ~check_prerequisites()
        results.skipped = 5;
        fprintf('\n[SKIPPED] Prerequisites not met. Install liblsl-Matlab.\n');
        return;
    end

    % Get paths
    test_dir = fileparts(mfilename('fullpath'));
    project_root = fullfile(test_dir, '..', '..');
    liblsl_path = fullfile(project_root, 'liblsl', 'build', 'liblsl.dylib');
    keygen_path = fullfile(project_root, 'liblsl', 'build', 'lsl-keygen');

    % Generate temporary config for tests
    temp_dir = tempdir();
    config_path = fullfile(temp_dir, 'lsl_api_matlab.cfg');

    % Generate keypair
    [status, output] = system(sprintf('"%s" --output "%s" --force', keygen_path, config_path));
    if status ~= 0
        error('Failed to generate keypair: %s', output);
    end
    fprintf('Generated test keypair at: %s\n\n', config_path);

    % Set config environment
    setenv('LSLAPICFG', config_path);

    % Load library
    lib = lsl_loadlib(liblsl_path);

    % Run tests
    try
        results = run_test(results, 'test_outlet_creation', @() test_outlet_creation(lib));
        results = run_test(results, 'test_inlet_creation', @() test_inlet_creation(lib));
        results = run_test(results, 'test_data_transfer', @() test_data_transfer(lib));
        results = run_test(results, 'test_large_data', @() test_large_data(lib));
        results = run_test(results, 'test_stream_discovery', @() test_stream_discovery(lib));
    catch ME
        fprintf('Error during tests: %s\n', ME.message);
    end

    % Cleanup
    setenv('LSLAPICFG', '');
    if exist(config_path, 'file')
        delete(config_path);
    end

    % Summary
    fprintf('\n=== Test Summary ===\n');
    fprintf('Passed: %d\n', results.passed);
    fprintf('Failed: %d\n', results.failed);
    fprintf('Skipped: %d\n', results.skipped);
end

function ok = check_prerequisites()
    ok = false;

    test_dir = fileparts(mfilename('fullpath'));
    project_root = fullfile(test_dir, '..', '..');
    lsl_matlab_path = fullfile(project_root, 'liblsl-Matlab');

    % Add liblsl-Matlab and its bin folder to path
    if ~exist(lsl_matlab_path, 'dir')
        fprintf('liblsl-Matlab not found at: %s\n', lsl_matlab_path);
        fprintf('Clone from: https://github.com/labstreaminglayer/liblsl-Matlab\n');
        return;
    end
    addpath(lsl_matlab_path);
    addpath(fullfile(lsl_matlab_path, 'bin'));

    % Check if liblsl.dylib exists
    liblsl_path = fullfile(project_root, 'liblsl', 'build', 'liblsl.dylib');

    if ~exist(liblsl_path, 'file')
        fprintf('Secure liblsl.dylib not found at: %s\n', liblsl_path);
        fprintf('Build the project first.\n');
        return;
    end

    % Check if lsl-keygen exists
    keygen_path = fullfile(project_root, 'liblsl', 'build', 'lsl-keygen');
    if ~exist(keygen_path, 'file')
        fprintf('lsl-keygen not found at: %s\n', keygen_path);
        return;
    end

    ok = true;
end

function results = run_test(results, name, test_fn)
    fprintf('Running %s... ', name);
    try
        test_fn();
        fprintf('[PASSED]\n');
        results.passed = results.passed + 1;
    catch ME
        fprintf('[FAILED]\n');
        fprintf('  Error: %s\n', ME.message);
        results.failed = results.failed + 1;
    end
end

%% Test Functions

function test_outlet_creation(lib)
    % Test creating a secure outlet
    info = lsl_streaminfo(lib, 'MatlabSecureOutlet', 'Test', 4, 100, 'cf_float32', 'matlab_outlet_001');
    outlet = lsl_outlet(info);

    assert(~isempty(outlet), 'Failed to create outlet');

    % Cleanup
    delete(outlet);
    delete(info);
end

function test_inlet_creation(lib)
    % Test creating outlet and resolving for inlet
    info = lsl_streaminfo(lib, 'MatlabInletTest', 'Test', 4, 100, 'cf_float32', 'matlab_inlet_001');
    outlet = lsl_outlet(info);

    % Resolve
    result = lsl_resolve_byprop(lib, 'name', 'MatlabInletTest', 1, 5.0);
    assert(~isempty(result), 'Failed to resolve stream');

    inlet = lsl_inlet(result{1});
    assert(~isempty(inlet), 'Failed to create inlet');

    % Cleanup
    delete(inlet);
    delete(outlet);
    delete(info);
end

function test_data_transfer(lib)
    % Test basic data transfer
    num_channels = 4;
    num_samples = 50;

    info = lsl_streaminfo(lib, 'MatlabDataTest', 'Test', num_channels, 100, 'cf_float32', 'matlab_data_001');
    outlet = lsl_outlet(info);

    result = lsl_resolve_byprop(lib, 'name', 'MatlabDataTest', 1, 5.0);
    inlet = lsl_inlet(result{1});
    inlet.open_stream();

    pause(0.1);  % Let connection stabilize

    % Push samples (use double for MATLAB compatibility)
    for i = 1:num_samples
        sample = double((i-1) * num_channels + (0:num_channels-1));
        outlet.push_sample(sample);
    end

    pause(0.2);

    % Pull samples
    received = 0;
    for i = 1:num_samples
        [data, ts] = inlet.pull_sample(1.0);
        if ~isempty(data)
            received = received + 1;
        end
    end

    assert(received >= num_samples * 0.8, ...
        sprintf('Only received %d/%d samples', received, num_samples));

    % Cleanup
    delete(inlet);
    delete(outlet);
    delete(info);
end

function test_large_data(lib)
    % Test large data transfer
    num_channels = 32;
    num_samples = 500;

    info = lsl_streaminfo(lib, 'MatlabLargeData', 'EEG', num_channels, 256, 'cf_float32', 'matlab_large_001');
    outlet = lsl_outlet(info);

    result = lsl_resolve_byprop(lib, 'name', 'MatlabLargeData', 1, 5.0);
    inlet = lsl_inlet(result{1});
    inlet.open_stream();

    pause(0.2);

    % Push samples (use double for MATLAB compatibility)
    for i = 1:num_samples
        sample = randn(1, num_channels);  % double by default
        outlet.push_sample(sample);
    end

    pause(1.0);

    % Pull samples
    received = 0;
    while true
        [data, ts] = inlet.pull_sample(0.1);
        if isempty(data)
            break;
        end
        received = received + 1;
    end

    assert(received >= num_samples * 0.7, ...
        sprintf('Only received %d/%d samples', received, num_samples));

    % Cleanup
    delete(inlet);
    delete(outlet);
    delete(info);
end

function test_stream_discovery(lib)
    % Test stream discovery with security
    info = lsl_streaminfo(lib, 'MatlabDiscovery', 'Test', 2, 100, 'cf_float32', 'matlab_disc_001');
    outlet = lsl_outlet(info);

    % Resolve by name
    result = lsl_resolve_byprop(lib, 'name', 'MatlabDiscovery', 1, 5.0);
    assert(~isempty(result), 'Failed to discover stream');

    % Check stream info
    resolved_info = result{1};
    assert(strcmp(resolved_info.name(), 'MatlabDiscovery'), 'Stream name mismatch');
    assert(resolved_info.channel_count() == 2, 'Channel count mismatch');

    % Cleanup
    delete(outlet);
    delete(info);
end
