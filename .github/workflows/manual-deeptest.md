---
description: Manually trigger DeepTest agent to generate tests for a specified component
on:
  workflow_dispatch:
    inputs:
      component:
        description: 'Component name to test'
        required: true
        type: string
      focal:
        description: 'Specific function to target (optional)'
        required: false
        type: string
        default: ""
      source:
        description: 'Path to source file'
        required: true
        type: string
      header:
        description: 'Path to header file (optional)'
        required: false
        type: string
        default: ""
      harness:
        description: 'Path to existing test harness (optional)'
        required: false
        type: string
        default: ""
      index_dir:
        description: 'Path to index directory'
        required: false
        type: string
        default: "./.deeptest"
      coverage_result:
        description: 'Path to store coverage result'
        required: false
        type: string
        default: "./artifacts/coverage/msquiccoverage.xml"
permissions:
  contents: read
  issues: read
  pull-requests: read
concurrency:
  group: "gh-aw-${{ inputs.component }}"
tools:
  bash: [":*"]
  edit:
  github:
env:
  COMPONENT: ${{ inputs.component }}
  FOCAL: ${{ inputs.focal }}
  SOURCE: ${{ inputs.source }}
  HEADER: ${{ inputs.header }}
  HARNESS: ${{ inputs.harness }}
  INDEX_DIR: ${{ inputs.index_dir }}
  COVERAGE_RESULT: ${{ inputs.coverage_result }}
  GH_AW_DIR: /tmp/gh-aw
timeout-minutes: 40
engine:
  id: copilot
  agent: DeepTest
safe-outputs:
  create-pull-request:
    title-prefix: "[Deep Test]"
    labels: [deeptest]
    draft: false
    expires: 1y
    reviewers: [saikat107, copilot]  
  noop:

steps:
  - name: Checkout repository
    uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6
    with:
      fetch-depth: 1
  - name: Prepare machine for code coverage
    run: pwsh scripts/prepare-machine.ps1 -InstallCodeCoverage
  - name: Create working directory
    run: mkdir -p ${{ env.GH_AW_DIR }}
post-steps:
  - name: Upload Coverage Result
    if: always()
    uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
    with:
      name: coverage-result
      path: ${{ env.COVERAGE_RESULT }}
      if-no-files-found: ignore
---

# DeepTest Manual Workflow

Generate comprehensive tests for the **${{ env.COMPONENT }}** component.

## Inputs

- **Component**: `${{ env.COMPONENT }}`
- **Source**: `${{ env.SOURCE }}`
- **Header**: `${{ env.HEADER }}`
- **Focal function**: `${{ env.FOCAL }}`
- **Test harness**: `${{ env.HARNESS }}`
- **Index directory**: `${{ env.INDEX_DIR }}`
- **Coverage output**: `${{ env.COVERAGE_RESULT }}`

## Instructions

You must never attempt to run `git push` as it is not supported in this environment.

1. Analyze the source file at `${{ env.SOURCE }}`{{#if env.HEADER}} and header at `${{ env.HEADER }}`{{/if}}.

2. {{#if env.FOCAL}}Target the specific function `${{ env.FOCAL }}` for test generation.{{else}}Generate tests for the entire component.{{/if}}

3. {{#if env.HARNESS}}Add tests to the existing harness at `${{ env.HARNESS }}`.{{else}}Determine the appropriate test file to add tests to, or create a new one if needed (update CMakeLists.txt accordingly).{{/if}}. Name the generated tests as `DeepTest*`, so that they can be run as `-Filter *DeepTest*` with GTest.

4. Iterate up to 5 times to improve coverage:
   - Generate high-quality tests using the **unit-test** skill (if focal function specified) or **component-test** skill. In the case of component-test, don't just write unit test, do your best to maximize coverage by generating integration tests as well. 
   - Compute coverage using `scripts/make-coverage.sh`. Make sure all the test pass and are of high quality. Feel free to use `test-quality-checker` skill for measuring quality of a test.
   - Stop early only if 100% coverage is achieved

5. Store the final coverage report at `${{ env.COVERAGE_RESULT }}`.

6. Prepare commit and create PR:
   a. Verify you have staged changes: run `git status --short` and print the output.
   b. Run `scripts/create-commit-for-safe-outputs.sh` to commit the changes.
   c. Print the commit summary: run `git log --oneline -1` and `git diff-tree --no-commit-id --name-only -r HEAD` to log the commit hash and changed files.
   d. Call the `create_pull_request` safe output tool with:
      - Title: "Tests for ${{ env.COMPONENT }}"
      - Body: Include the initial coverage percentage, final/updated coverage percentage, coverage improvement delta, number of tests added, and workflow run ${{ github.run_id }}
   e. Print the result of the `create_pull_request` tool call to confirm the PR was requested.

7. If no staged changes, use `noop` with message "No test changes generated for ${{ env.COMPONENT }}."

## Constraints

- Code changes must only happen within the `src/` folder. If you notice any changes outside, revert them with `git restore` and print warnings.
- You must complete at least 5 iterations if coverage is below 100%.
- Do NOT stop before 5 iterations even if coverage improvements seem minimal.
- Before committing, make sure the project build successfully and all the newly added tests pass. 
