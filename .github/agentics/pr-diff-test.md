<!-- This prompt will be imported in the agentic workflow .github/workflows/pr-diff-test.md at runtime. -->
<!-- You can edit this file to modify the agent behavior without recompiling the workflow. -->

# PR Diff Testing: Generate Tests from Pull Request Changes

This workflow captures the unified diff of a pull request, stores it in a file, and invokes the DeepTest-V0 agent to generate comprehensive tests for the modified code.

## Input

- **pr_number**: The pull request number to analyze
- **Default (PR trigger)**: Automatically uses the current PR number from the trigger event

## Workflow Steps

1. **Fetch PR Unified Diff**: The workflow uses `gh pr diff` to retrieve the complete unified diff for the specified pull request
2. **Store Diff**: The diff is saved to `pr-diffs/pr-{number}.diff` for analysis
3. **Invoke DeepTest**: The DeepTest-V0 agent is called with the diff file as context

## Instructions for DeepTest-V0 Agent

1. **Analyze the diff file** at `pr-diffs/pr-${{ github.event.pull_request.number }}.diff`
2. **Identify all modified functions** and code paths in the pull request
3. **Focus on changes** - prioritize testing:
   - New functions added in the PR
   - Modified logic and behavior changes
   - New error handling paths
   - State machine transitions
   - Resource management changes
4. **Generate comprehensive test cases** following MsQuic test patterns:
   - Use test patterns from `src/test/lib/` (helper classes) and `src/test/bin/` (functional tests)
   - Follow C++ wrapper patterns like `TestConnection`, `TestStream`, `TestListener`
   - Use `TEST_QUIC_SUCCEEDED()` and `TEST_TRUE()` macros for assertions
5. **Cover edge cases** for the modified code:
   - Null/empty inputs
   - Boundary conditions
   - Error paths introduced or modified
   - State transitions affected by changes
   - Resource cleanup for new allocations
6. **Create a PR** with all generated test files, including the workflow run ID in the title

## MsQuic Test Conventions

- Tests are located in `src/test/lib/` (helper classes) and `src/test/bin/` (functional tests)
- Use C++ wrappers around C API for convenience
- Follow existing patterns like `TestConnection`, `TestStream`, `TestListener`
- Use `TEST_QUIC_SUCCEEDED()` and `TEST_TRUE()` macros for assertions
- Memory management: Use RAII patterns with auto-cleanup callbacks

## Safe Outputs

When successfully complete:
- If tests were generated: Use `create-pull-request` with the generated test code. The PR title will automatically include the run ID and source PR number.
- **If DeepTest agent is unavailable or failed**: Call the `noop` safe output explaining the failure

## Example Diff Analysis

If the diff shows a new function `QuicConnValidateSettings`:
- Create tests for valid settings (normal case)
- Create tests for invalid settings (error cases)
- Test boundary values for numeric settings
- Test null pointer handling
- Test combinations of settings flags
