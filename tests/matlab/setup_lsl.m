function lib = setup_lsl()
% SETUP_LSL Load the secure liblsl library for MATLAB
%
%   lib = SETUP_LSL() loads the secure liblsl library and returns
%   the library handle for use with lsl_* functions.
%
%   The function looks for liblsl.dylib in the standard build location
%   relative to this test directory.

    % Get paths
    test_dir = fileparts(mfilename('fullpath'));
    project_root = fullfile(test_dir, '..', '..');
    liblsl_path = fullfile(project_root, 'liblsl', 'build', 'liblsl.dylib');
    lsl_matlab_path = fullfile(project_root, 'liblsl-Matlab');

    if ~exist(liblsl_path, 'file')
        error('Secure liblsl not found at: %s\nBuild the project first.', liblsl_path);
    end

    if ~exist(lsl_matlab_path, 'dir')
        error('liblsl-Matlab not found at: %s\nClone it from: https://github.com/labstreaminglayer/liblsl-Matlab', lsl_matlab_path);
    end

    % Add liblsl-Matlab to path
    addpath(lsl_matlab_path);

    % Set environment to use our liblsl
    setenv('LSLPATH', fileparts(liblsl_path));

    % Load library
    lib = lsl_loadlib(liblsl_path);

    fprintf('Loaded secure liblsl from: %s\n', liblsl_path);
    fprintf('Using liblsl-Matlab from: %s\n', lsl_matlab_path);
end
