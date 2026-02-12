---
description: Capture PR unified diff and run DeepTest-V0 agent on the changes
on:
  pull_request:
    types: [opened, synchronize, reopened]
  workflow_dispatch:
    inputs:
      pr_number:
        description: "Pull request number to analyze"
        required: false
        type: string
permissions:
  contents: read
  pull-requests: read
  issues: read
strict: false
env:
  GH_TOKEN: ${{ github.token }}
  COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}
  PR_NUMBER: ${{ inputs.pr_number || github.event.pull_request.number }}
  RUN_ID: ${{ github.run_id }}
engine:
  id: custom
  steps:
    - name: Get PR Unified Diff
      run: |
        echo "Fetching unified diff for PR #$PR_NUMBER (Run ID: $RUN_ID)"
        
        # Create directory for diff storage
        mkdir -p pr-diffs
        
        # Fetch the unified diff from GitHub API
        gh pr diff $PR_NUMBER > pr-diffs/pr-$PR_NUMBER.diff
        
        echo "Diff stored in pr-diffs/pr-$PR_NUMBER.diff"
        echo "Diff size: $(wc -l < pr-diffs/pr-$PR_NUMBER.diff) lines"
    
    - name: Install Copilot CLI
      run: |
        gh extension install github/gh-copilot || echo "Copilot CLI already installed"
    
    - name: Run DeepTest-V0 on PR Diff
      run: |
        echo "Invoking DeepTest-V0 agent for PR #$PR_NUMBER (Run ID: $RUN_ID)"
        
        # Pass the diff file to DeepTest agent
        gh copilot --agent DeepTest -p "Analyze the unified diff stored in pr-diffs/pr-$PR_NUMBER.diff and generate comprehensive tests for all modified functions and code paths. Focus on:
        1. Functions that were added or modified in this PR
        2. Edge cases and boundary conditions for the changes
        3. Error handling and resource cleanup
        4. State transitions affected by the changes
        
        Follow MsQuic test patterns in src/test/. After generating tests, create a PR with all test files. Include the workflow run ID $RUN_ID in the PR title." --allow-all-tools
safe-outputs:
  create-pull-request:
    title-prefix: "[DeepTest PR #${{ github.event.pull_request.number || inputs.pr_number }} Run #${{ github.run_id }}] "
    labels: [automation, tests, pr-diff-analysis]
  noop:
---

{{#runtime-import agentics/pr-diff-test.md}}
