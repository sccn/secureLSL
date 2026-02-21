function results = run_all_tests()
% RUN_ALL_TESTS Run all MATLAB security tests
%
%   results = RUN_ALL_TESTS() runs all security tests and returns
%   aggregated results.
%
%   Example:
%     results = run_all_tests();
%     fprintf('Total: %d passed, %d failed\n', results.passed, results.failed);

    fprintf('========================================\n');
    fprintf('   Secure LSL MATLAB Test Suite\n');
    fprintf('========================================\n\n');

    results = struct();
    results.passed = 0;
    results.failed = 0;
    results.skipped = 0;

    % Run basic security tests
    fprintf('Running test_security_basic...\n');
    fprintf('----------------------------------------\n');
    basic_results = test_security_basic();
    results.passed = results.passed + basic_results.passed;
    results.failed = results.failed + basic_results.failed;
    results.skipped = results.skipped + basic_results.skipped;

    fprintf('\n');

    % Run interop tests
    fprintf('Running test_interop...\n');
    fprintf('----------------------------------------\n');
    interop_results = test_interop();
    results.passed = results.passed + interop_results.passed;
    results.failed = results.failed + interop_results.failed;
    results.skipped = results.skipped + interop_results.skipped;

    % Final summary
    fprintf('\n========================================\n');
    fprintf('   Final Results\n');
    fprintf('========================================\n');
    fprintf('Passed:  %d\n', results.passed);
    fprintf('Failed:  %d\n', results.failed);
    fprintf('Skipped: %d\n', results.skipped);
    fprintf('========================================\n');

    if results.failed > 0
        fprintf('\n[FAIL] Some tests failed!\n');
    elseif results.skipped > 0
        fprintf('\n[WARN] Some tests skipped. Check prerequisites.\n');
    else
        fprintf('\n[PASS] All tests passed!\n');
    end
end
