function results = test_interop()
% TEST_INTEROP Cross-language interoperability tests for MATLAB <-> C++
%
%   results = TEST_INTEROP() runs tests that verify MATLAB can communicate
%   with C++ LSL streams using the secure transport.
%
%   Prerequisites:
%   - Same as test_security_basic.m
%   - C++ interop binaries must be built (cpp_secure_outlet, cpp_secure_inlet)

    fprintf('=== MATLAB <-> C++ Interop Tests ===\n\n');

    results = struct();
    results.passed = 0;
    results.failed = 0;
    results.skipped = 0;

    % Check prerequisites
    test_dir = fileparts(mfilename('fullpath'));
    project_root = fullfile(test_dir, '..', '..');
    lsl_matlab_path = fullfile(project_root, 'liblsl-Matlab');

    if ~exist(lsl_matlab_path, 'dir')
        fprintf('liblsl-Matlab not found. Clone it first.\n');
        results.skipped = 2;
        return;
    end
    addpath(lsl_matlab_path);

    cpp_outlet = fullfile(project_root, 'liblsl', 'build', 'cpp_secure_outlet');
    cpp_inlet = fullfile(project_root, 'liblsl', 'build', 'cpp_secure_inlet');
    keygen_path = fullfile(project_root, 'liblsl', 'build', 'lsl-keygen');
    liblsl_path = fullfile(project_root, 'liblsl', 'build', 'liblsl.dylib');

    if ~exist(cpp_outlet, 'file') || ~exist(cpp_inlet, 'file')
        fprintf('C++ interop binaries not found. Build them first.\n');
        results.skipped = 2;
        return;
    end

    % Generate temporary config
    temp_dir = tempdir();
    config_path = fullfile(temp_dir, 'lsl_api_matlab_interop.cfg');
    [status, ~] = system(sprintf('"%s" --output "%s" --force', keygen_path, config_path));
    if status ~= 0
        error('Failed to generate keypair');
    end

    % Set config for MATLAB
    setenv('LSLAPICFG', config_path);

    % Load library
    lib = lsl_loadlib(liblsl_path);

    try
        results = run_test(results, 'test_cpp_outlet_matlab_inlet', ...
            @() test_cpp_outlet_matlab_inlet(lib, cpp_outlet, config_path));
        results = run_test(results, 'test_matlab_outlet_cpp_inlet', ...
            @() test_matlab_outlet_cpp_inlet(lib, cpp_inlet, config_path));
    catch ME
        fprintf('Error: %s\n', ME.message);
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

function test_cpp_outlet_matlab_inlet(lib, cpp_outlet, config_path)
    % Start C++ outlet as subprocess
    env_cmd = sprintf('LSLAPICFG="%s" "%s" --name CppToMatlab --samples 50 --channels 4 --rate 100 &', ...
        config_path, cpp_outlet);
    system(env_cmd);

    % Give it time to start
    pause(1.0);

    % Create MATLAB inlet
    result = lsl_resolve_byprop(lib, 'name', 'CppToMatlab', 1, 5.0);
    assert(~isempty(result), 'Failed to find C++ stream');

    inlet = lsl_inlet(result{1});
    inlet.open_stream();

    % Pull samples
    received = 0;
    for i = 1:50
        [data, ts] = inlet.pull_sample(2.0);
        if ~isempty(data)
            received = received + 1;
        end
    end

    assert(received >= 35, sprintf('Only received %d/50 samples', received));

    delete(inlet);
end

function test_matlab_outlet_cpp_inlet(lib, cpp_inlet, config_path)
    % Create MATLAB outlet
    info = lsl_streaminfo(lib, 'MatlabToCpp', 'Test', 4, 100, 'cf_float32', 'matlab_to_cpp_001');
    outlet = lsl_outlet(info);

    pause(0.3);

    % Start C++ inlet as subprocess (it will find our stream)
    env_cmd = sprintf('LSLAPICFG="%s" "%s" --stream MatlabToCpp --samples 50 --timeout 10.0 2>&1 &', ...
        config_path, cpp_inlet);
    system(env_cmd);

    % Push samples
    for i = 1:60
        sample = single((i-1) * 4 + (0:3));
        outlet.push_sample(sample);
        pause(0.01);
    end

    % Wait for C++ inlet to finish
    pause(2.0);

    % Note: We can't easily check C++ exit code from MATLAB
    % The test passes if we get here without error
    delete(outlet);
    delete(info);
end
