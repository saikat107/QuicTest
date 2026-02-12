---
description: Creates diff of PR changes, summarizes it in natural language, and builds the repository
on:
  pull_request:
    types: [opened, synchronize]
  workflow_dispatch:
permissions:
  contents: read
  pull-requests: read
  issues: read
tools:
  github:
    toolsets: [default]
safe-outputs:
  add-comment:
    max: 1
post-steps:
  - name: Upload PR Diff
    uses: actions/upload-artifact@v4
    with:
      name: pr-diff
      path: pr-*-diff.patch
      if-no-files-found: ignore
  - name: Upload PR Summary
    uses: actions/upload-artifact@v4
    with:
      name: pr-summary
      path: pr-*-summary.md
      if-no-files-found: ignore
  - name: Upload Build Result
    uses: actions/upload-artifact@v4
    with:
      name: build-result
      path: pr-*-build-result.txt
      if-no-files-found: ignore
---

# PR Diff Summary and Build Workflow

You are an AI agent that analyzes pull request changes, summarizes them in natural language, and triggers a build.

## Your Task

For this pull request (#${{ github.event.pull_request.number }}), perform the following tasks in order:

### 1. Generate and Upload PR Diff

1. Use `git diff` to generate the complete diff of the changes in this PR compared to the base commit (`${{ github.event.pull_request.base.sha }}`).
2. Save the diff to a file named `pr-${{ github.event.pull_request.number }}-diff.patch` in the current working directory.

### 2. Summarize the Diff

1. Analyze the diff you generated.
2. Write a clear, concise natural language summary of the changes. The summary should include:
   - **Overview**: A brief description of what the PR accomplishes.
   - **Files Changed**: List the files that were modified, added, or deleted.
   - **Key Changes**: Describe the most significant changes in the code.
   - **Potential Impact**: Note any areas that might need attention during review.
3. Save the summary to a file named `pr-${{ github.event.pull_request.number }}-summary.md` in the current working directory.

### 3. Build the Repository

1. Run the build inside the MsQuic build container using Docker:
   ```bash
   docker run --rm -v $(pwd):/src -w /src ghcr.io/microsoft/msquic/linux-build-xcomp:ubuntu-22.04-cross pwsh ./scripts/build.ps1
   ```
2. Capture the build output (both stdout and stderr).
3. Create a build report file named `pr-${{ github.event.pull_request.number }}-build-result.txt` in the current working directory containing:
   - Build status (success or failure)
   - Build output/logs
   - Any errors or warnings encountered

### 4. Post Summary Comment

After completing all tasks, post a comment on the PR using the `add-comment` safe output, summarizing:
- Confirmation that the diff was generated
- A brief version of the change summary
- Build status (success/failure)
- Note that artifacts are available for download from the workflow run

## Guidelines

- Execute tasks sequentially in the order specified.
- If the build fails, still create the build result file with the error information.
- Keep the PR comment concise but informative.
- Use Docker to run the build inside the `ghcr.io/microsoft/msquic/linux-build-xcomp:ubuntu-22.04-cross` container.
- All output files must be created in the current working directory so post-steps can upload them as artifacts.

## Safe Outputs

- Use `add-comment` to post the final summary comment on the PR.
- If any step fails, still attempt to complete the remaining steps and report all results in the comment.
