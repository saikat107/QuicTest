---
name: patch-validating-test
description: This skill generates unit tests that validate code patches by exercising modified lines. Tests must fail before the patch and pass after applying it.
---

You are generating patch-validating tests for changes in {{component}}. Your task is to create unit tests that exercise the modified code paths, ensuring the tests fail without the patch and pass with it. Feel free to use other available skills if needed, specially 
1. "semantic-indexer" and "query-repo" for generating and querying comprehensive summary of any source code
2. "unit-test" and "component-test" to create test cases
3. "test-quality-checker" for checking the quality of the tests, 
4. "coverage-analysis" if there is no coverage tool available, of the coverage tool does not run properly. 

# Step 1: Setup Test Environment

You are provided with two project directories and a list of changed files:
- **Pre-PR (unpatched)**: `{{pre_pr_path}}` - the project at the base commit
- **Post-PR (patched)**: `{{post_pr_path}}` - the project after the PR changes
- **Changed files**: `{{changed_files}}` - a text file listing relative paths of all changed files

Generate a patch file by diffing only the changed files between the two directories:

```powershell
# Generate patch from the two directories using git diff --no-index
# Only diff files listed in the changed_files list
$changedFiles = Get-Content {{changed_files}}
$diffOutput = @()
foreach ($file in $changedFiles) {
    $prePath = Join-Path {{pre_pr_path}} $file
    $postPath = Join-Path {{post_pr_path}} $file
    $diffOutput += git -c core.safecrlf=false -c core.autocrlf=false diff --no-index $prePath $postPath 2>$null
}
$diffOutput | Out-File -FilePath .deeptest/patch_analysis/generated.patch -Encoding utf8
$PATCH_FILE = ".deeptest/patch_analysis/generated.patch"
```

# Step 2: Analyze the Patch

Use the provided scripts to parse and analyze the patch:

```bash
# Parse the patch file to extract changed files, hunks, and line information
python scripts/patch_parser.py parse "$PATCH_FILE" --json .deeptest/patch_analysis/patch_info.json

# Analyze the patch to identify affected functions and code paths
python scripts/patch_analyzer.py analyze "$PATCH_FILE" --source-root {{pre_pr_path}} --json .deeptest/patch_analysis/analysis.json --md .deeptest/patch_analysis/report.md
```

The analysis provides:
- Changed files and line numbers
- Affected functions and their boundaries
- Distinct code paths introduced or modified by the patch

# Step 3: Identify Code Paths

For each modified function, identify the distinct code paths that the patch introduces or changes. Each code path should have exactly **one test**.

A code path is a unique execution trace through the modified code, determined by:
- Conditional branches (if/else, switch)
- Loop conditions (enter/skip, iterations)
- Early returns or error handling

Document each path:
- **Path ID**: Unique identifier (e.g., `path_1`, `path_2`)
- **Conditions**: The sequence of branch decisions to reach this path
- **Modified lines exercised**: Which changed lines this path covers
- **Expected outcome**: Return value, state change, or side effect

# Step 4: Generate Unit Tests

Create **one test per code path** that:
1. Exercises the specific modified lines for that path
2. Sets up inputs to trigger the exact branch conditions
3. Asserts on the expected outcome

**CRITICAL INVARIANT**: Each test must satisfy:
- ❌ **FAIL** when run against `{{pre_pr_path}}` (unpatched)
- ✅ **PASS** when run against `{{post_pr_path}}` (patched)

This invariant ensures the test is truly validating the patch behavior.

# Step 5: Validate the Invariant

For each generated test, verify the invariant holds:

```bash
# Run tests against UNPATCHED code - should FAIL
cd {{pre_pr_path}}
{{build}}
{{test}}  # Expect failures

# Run tests against PATCHED code - should PASS
cd {{post_pr_path}}
{{build}}
{{test}}  # Expect all pass
```

If a test passes on unpatched code, it does not validate the patch—revise the test to target the actual change.

# Step 6: Verify Coverage

Confirm the tests cover the modified lines:

```bash
cd {{post_pr_path}}
{{coverage}}
```

Ensure:
- [ ] All added lines are covered by at least one test
- [ ] Each distinct code path has exactly one test
- [ ] No test is redundant (covers the same path as another)

# Step 7: Finalize

1. Add the validated tests to the test suite in `{{post_pr_path}}`
2. Document which test covers which code path

**Store patch analysis in .deeptest/patch_analysis folder**

{{#if build}} Build command: {{build}} {{/if}}
{{#if test}} Test command: {{test}} {{/if}}
{{#if coverage}} Coverage command: {{coverage}} {{/if}}
{{#if pre_pr_path}} Pre-PR path (base commit): {{pre_pr_path}} {{/if}}
{{#if post_pr_path}} Post-PR path (after changes): {{post_pr_path}} {{/if}}
{{#if changed_files}} Changed files list: {{changed_files}} {{/if}}
