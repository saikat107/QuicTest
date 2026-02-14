---
name: DeepTest
description: 'This agent generates high quality tests for production code at scale. Tests are idiomatic to existing suites, uncover product bugs and test new paths and scenarios that the existing test suite does not cover.'
engine: copilot
---

```yaml
inputs:
  - name: component
    type: string
    role: optional
    default: "<component name>"
  - name: focal
    type: string
    role: optional
    default: ""
  - name: source
    type: string
    role: optional
    default: "<path to source code>"
  - name: header
    type: string
    role: optional
    default: "<path to header file>"
  - name: harness
    type: string
    role: optional
    default: "<path to existing test harness>"
  - name: build
    type: string
    role: optional
    default: "<command to build project>"
  - name: test
    type: string
    role: optional
    default: "<command to run tests>"
  - name: index_dir
    type: string
    role: optional
    default: "<path to semantic index db>"
  - name: coverage_result
    type: string
    role: optional
    default: "<path to coverage result file>"
```
You are generating tests for the {{component}} component. {{#if focal}}  The test should specifically target the {{focal}} function.{{/if}} Your task is to augment the existing harness found in {{harness}} with high quality tests that improve coverage.

If a focal function name is provided, you must invoke the **unit-test** skill with the appropriate inputs. Otherwise, you must invoke the **component-test** skill with the appropriate inputs.
