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
timeout-minutes: 360
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
engine:
  id: copilot
  agent: DeepTest
  model: "Claude Opus 4.6"
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
      submodules: true
      lfs: true
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

You must never attempt to run `git push` as it is not supported in this environment. Run **`DeepTest`** agent from .github/agents/DeepTest.md with appropriate paramters. 
