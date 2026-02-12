# PR Diff Testing Workflow

## Overview

This GitHub Agentic Workflow automatically captures the unified diff of a pull request, stores it in a file, and runs the DeepTest-V0 agent to generate comprehensive tests for the modified code.

## Files

- **Workflow Definition**: `.github/workflows/pr-diff-test.md` - The main workflow file (editable)
- **Compiled Workflow**: `.github/workflows/pr-diff-test.lock.yml` - The compiled GitHub Actions workflow (auto-generated, do not edit)
- **Runtime Instructions**: `.github/agentics/pr-diff-test.md` - Agent instructions loaded at runtime (editable without recompilation)

## Triggers

### Automatic Trigger
The workflow runs automatically when:
- A pull request is opened
- A pull request is synchronized (new commits pushed)
- A pull request is reopened

### Manual Trigger
You can also trigger the workflow manually via `workflow_dispatch` with an optional `pr_number` input to analyze a specific PR.

## How It Works

1. **Fetch PR Diff**: The workflow uses `gh pr diff` to retrieve the unified diff for the pull request
2. **Store Diff**: The diff is saved to `pr-diffs/pr-{number}.diff`
3. **Invoke DeepTest**: The DeepTest-V0 agent analyzes the diff and generates tests for:
   - New functions added in the PR
   - Modified logic and behavior changes
   - New error handling paths
   - State machine transitions
   - Resource management changes

4. **Create Test PR**: DeepTest creates a new pull request with the generated test files

## Environment Variables

- `GH_TOKEN`: GitHub token (automatically provided)
- `COPILOT_GITHUB_TOKEN`: Copilot CLI token (must be configured as a secret)
- `PR_NUMBER`: The PR number being analyzed
- `RUN_ID`: The workflow run ID

## Test Generation

The DeepTest agent follows MsQuic test conventions:
- Tests are placed in `src/test/lib/` (helper classes) and `src/test/bin/` (functional tests)
- Uses C++ wrappers around C API
- Follows patterns like `TestConnection`, `TestStream`, `TestListener`
- Uses `TEST_QUIC_SUCCEEDED()` and `TEST_TRUE()` macros for assertions

## Modifying the Workflow

### Editing Agent Instructions (No Recompilation Needed)
Edit `.github/agentics/pr-diff-test.md` to change:
- Agent instructions and task descriptions
- Test generation guidelines
- Output formatting

Changes take effect on the next workflow run without recompilation.

### Editing Workflow Configuration (Recompilation Required)
Edit `.github/workflows/pr-diff-test.md` frontmatter (YAML between `---` markers) to change:
- Triggers, permissions, tools
- Environment variables
- Safe outputs configuration

After editing, run:
```bash
gh aw compile pr-diff-test
```

## Permissions

The workflow has read-only permissions:
- `contents: read` - Read repository contents
- `pull-requests: read` - Read PR information
- `issues: read` - Read issue information

Write operations (creating PRs) are performed through safe outputs.

## Safe Outputs

The workflow uses safe outputs to create pull requests:
- PR title includes: `[DeepTest PR #{source_pr} Run #{run_id}]`
- Labels: `automation`, `tests`, `pr-diff-analysis`

## Requirements

- GitHub CLI (`gh`) installed in the workflow environment
- GitHub Copilot CLI extension installed
- `COPILOT_GITHUB_TOKEN` secret configured in the repository
- DeepTest agent available in the Copilot CLI
