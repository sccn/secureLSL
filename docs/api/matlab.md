# MATLAB API Reference

Using Secure LSL with MATLAB.

---

## Setup

### Load Secure liblsl

Point MATLAB to the secure liblsl library:

```matlab
% Add path to secure liblsl
addpath('/path/to/secureLSL/liblsl/build');

% Load the library
lib = lsl_loadlib('/path/to/secureLSL/liblsl/build/liblsl-secure.dylib');
```

### Verify Setup

```matlab
% Check library is loaded
if ~isempty(lib)
    disp('Secure liblsl loaded successfully');
end
```

---

## Security Functions

### Check Stream Security

```matlab
function is_secure = check_stream_security(info)
    % Check if a stream has security enabled
    %
    % Parameters:
    %   info - lsl_streaminfo object
    %
    % Returns:
    %   is_secure - true if security is enabled

    is_secure = info.security_enabled();
end
```

### Get Security Fingerprint

```matlab
function fingerprint = get_fingerprint(info)
    % Get security fingerprint for a stream
    %
    % Parameters:
    %   info - lsl_streaminfo object
    %
    % Returns:
    %   fingerprint - string like 'BLAKE2b:70:14:e1:b5:...'

    fingerprint = info.security_fingerprint();
end
```

---

## Usage Patterns

### Creating a Secure Outlet

```matlab
function secure_outlet_example()
    % Create a secure outlet streaming EEG data

    % Load library
    lib = lsl_loadlib();

    % Create stream info (security is automatic if configured)
    info = lsl_streaminfo(lib, ...
        'SecureEEG', ...      % name
        'EEG', ...            % type
        64, ...               % channels
        1000, ...             % sampling rate
        'cf_float32', ...     % format
        'myuid123');          % source ID

    % Check security status
    if info.security_enabled()
        fprintf('Stream will be encrypted\n');
        fprintf('Fingerprint: %s\n', info.security_fingerprint());
    else
        warning('Security not enabled! Run lsl-keygen first.');
    end

    % Create outlet
    outlet = lsl_outlet(info);

    % Stream data (encrypted automatically)
    sample = zeros(1, 64);
    for i = 1:1000
        % Generate sample data
        sample = randn(1, 64);
        outlet.push_sample(sample);
        pause(1/1000);  % Maintain sampling rate
    end

    % Clean up
    delete(outlet);
    delete(info);
end
```

### Creating a Secure Inlet

```matlab
function secure_inlet_example()
    % Create a secure inlet to receive EEG data

    % Load library
    lib = lsl_loadlib();

    % Resolve streams
    fprintf('Looking for EEG streams...\n');
    result = lsl_resolve_byprop(lib, 'type', 'EEG', 1, 5.0);

    if isempty(result)
        error('No EEG streams found');
    end

    % Check security on discovered streams
    for i = 1:length(result)
        info = result{i};
        fprintf('Found: %s\n', info.name());

        if info.security_enabled()
            fprintf('  Security: ENABLED\n');
            fprintf('  Fingerprint: %s\n', info.security_fingerprint());
        else
            fprintf('  Security: DISABLED\n');
        end
    end

    % Connect to first stream
    inlet = lsl_inlet(result{1});
    fprintf('Connected to: %s\n', result{1}.name());

    % Pull samples (decrypted automatically)
    num_channels = result{1}.channel_count();
    for i = 1:100
        [sample, timestamp] = inlet.pull_sample(1.0);
        if ~isempty(sample)
            fprintf('Sample %d: timestamp=%.3f\n', i, timestamp);
        end
    end

    % Clean up
    delete(inlet);
end
```

### Security Status Report

```matlab
function security_report()
    % Print security status of all discovered streams

    lib = lsl_loadlib();

    fprintf('Security Status Report\n');
    fprintf('======================\n\n');

    % Resolve all streams
    result = lsl_resolve_all(lib, 2.0);

    fprintf('Found %d stream(s):\n\n', length(result));

    for i = 1:length(result)
        info = result{i};

        fprintf('Stream: %s\n', info.name());
        fprintf('  Type: %s\n', info.type());
        fprintf('  Host: %s\n', info.hostname());
        fprintf('  Channels: %d\n', info.channel_count());

        if info.security_enabled()
            fprintf('  Security: ENABLED\n');
            fprintf('  Fingerprint: %s\n', info.security_fingerprint());
        else
            fprintf('  Security: DISABLED\n');
        end
        fprintf('\n');
    end
end
```

---

## Recording Secure Streams

### Basic Recording

```matlab
function record_secure_stream(duration_sec)
    % Record a secure stream to a matrix
    %
    % Parameters:
    %   duration_sec - Recording duration in seconds

    lib = lsl_loadlib();

    % Find EEG stream
    result = lsl_resolve_byprop(lib, 'type', 'EEG', 1, 5.0);
    if isempty(result)
        error('No EEG stream found');
    end

    info = result{1};

    % Verify security
    if ~info.security_enabled()
        warning('Stream is not encrypted!');
    end

    % Create inlet
    inlet = lsl_inlet(info);
    num_channels = info.channel_count();
    srate = info.nominal_srate();

    % Pre-allocate buffer
    expected_samples = ceil(duration_sec * srate * 1.1);  % 10% margin
    data = zeros(num_channels, expected_samples);
    timestamps = zeros(1, expected_samples);

    fprintf('Recording %s for %d seconds...\n', info.name(), duration_sec);

    % Record
    sample_idx = 0;
    start_time = tic;

    while toc(start_time) < duration_sec
        [sample, ts] = inlet.pull_sample(0.1);
        if ~isempty(sample)
            sample_idx = sample_idx + 1;
            data(:, sample_idx) = sample;
            timestamps(sample_idx) = ts;
        end
    end

    % Trim to actual size
    data = data(:, 1:sample_idx);
    timestamps = timestamps(1:sample_idx);

    fprintf('Recorded %d samples\n', sample_idx);

    % Save to file
    save('secure_recording.mat', 'data', 'timestamps', 'info');
    fprintf('Saved to secure_recording.mat\n');

    % Clean up
    delete(inlet);
end
```

### Multi-Stream Recording

```matlab
function record_multi_secure(stream_types, duration_sec)
    % Record multiple secure streams
    %
    % Parameters:
    %   stream_types - Cell array of stream types to record
    %   duration_sec - Recording duration

    lib = lsl_loadlib();

    inlets = {};
    infos = {};

    % Connect to all streams
    for i = 1:length(stream_types)
        result = lsl_resolve_byprop(lib, 'type', stream_types{i}, 1, 5.0);
        if ~isempty(result)
            info = result{1};

            % Check security
            if info.security_enabled()
                fprintf('Connected to secure stream: %s\n', info.name());
            else
                fprintf('Warning: %s is not encrypted\n', info.name());
            end

            inlets{end+1} = lsl_inlet(info);
            infos{end+1} = info;
        end
    end

    if isempty(inlets)
        error('No streams found');
    end

    % Record (simplified for example)
    fprintf('Recording for %d seconds...\n', duration_sec);
    pause(duration_sec);

    % Clean up
    for i = 1:length(inlets)
        delete(inlets{i});
    end
end
```

---

## Error Handling

```matlab
function safe_connect_example()
    % Demonstrate error handling for secure connections

    lib = lsl_loadlib();

    try
        result = lsl_resolve_byprop(lib, 'type', 'EEG', 1, 5.0);

        if isempty(result)
            error('No streams found');
        end

        inlet = lsl_inlet(result{1});

        [sample, ts] = inlet.pull_sample(1.0);

    catch ME
        % Check for security-related errors
        if contains(ME.message, 'security')
            fprintf('Security error: %s\n', ME.message);
            fprintf('Ensure all devices have matching security configuration.\n');
        else
            rethrow(ME);
        end
    end
end
```

Common error messages:

| Error | Cause | Solution |
|-------|-------|----------|
| "security mismatch" | Devices have different keypairs | Import the shared keypair: `./lsl-keygen --import lab_shared.key.enc` |
| "outlet does not have security" | Secure inlet, insecure outlet | Enable security on outlet device |
| "outlet requires security" | Insecure inlet, secure outlet | Enable security on inlet device |

---

## Best Practices

### 1. Always Check Security Status

```matlab
function best_practice_example()
    lib = lsl_loadlib();
    result = lsl_resolve_byprop(lib, 'type', 'EEG', 1, 5.0);

    if ~isempty(result)
        info = result{1};

        % Always verify security before recording sensitive data
        if ~info.security_enabled()
            warning('Recording unencrypted data!');
            response = input('Continue anyway? (y/n): ', 's');
            if ~strcmpi(response, 'y')
                return;
            end
        end

        % Proceed with recording
    end
end
```

### 2. Log Security Status

```matlab
function log_security_status(info, logfile)
    % Log security information for audit trail

    fid = fopen(logfile, 'a');
    fprintf(fid, '%s - Stream: %s\n', datestr(now), info.name());
    fprintf(fid, '  Security: %s\n', string(info.security_enabled()));
    if info.security_enabled()
        fprintf(fid, '  Fingerprint: %s\n', info.security_fingerprint());
    end
    fclose(fid);
end
```

---

## Next Steps

- [Python API Reference](python.md) - Python interface
- [C++ API Reference](cpp-api.md) - C++ interface
- [Quick Start Guide](../getting-started/quickstart.md) - Getting started
