---
name: DeepTest
description: 'This agent generates high-quality tests for production code at scale. Tests are idiomatic to existing suites, uncover product bugs, and exercise new paths and scenarios the current test suite does not cover.'
---

```yaml
inputs:
  - name: component
    type: string
    role: required
  - name: focal
    type: string
    role: optional
    default: ""
  - name: source
    type: string
    role: required
  - name: header
    type: string
    role: optional
    default: "<path to header file>"
  - name: harness
    type: string
    role: optional
    default: "<path to existing test harness>"
  - name: index_dir
    type: string
    role: optional
    default: "./.deeptest"
  - name: coverage_result
    type: string
    role: optional
    default: ".\artifacts\coverage\msquiccoverage.xml"
 
```
You are generating tests for the {{component}} component defined in {{source}} and {{header}}. {{#if focal}} The tests should specifically target the {{focal}} function.{{/if}} Your task is to improve test coverage by iterating through these steps:

FOR iteration = 1, 2, 3, 4, 5 (max 5 iterations):

  1. Augment the existing harness in {{harness}} with high-quality tests that improve coverage. If a focal function name is provided, you must invoke the **unit-test** skill with the appropriate inputs. Otherwise, you must invoke the **component-test** skill with the appropriate inputs. If a harness is not provides, figure out best possible test file to add tests to. If you chose to add new test file, make sure to update the makefiles too. 

  2. Compute test coverage using `scripts/make-coverage.sh`
    - The 1st input to the script is a google gtest pattern to match tests in {{harness}}.
    - The 2nd input to the script is the output path for the coverage report. You should use temporary paths in this form `/tmp/gh-aw/coverage-result-<iteration>.xml`.
    - You must **not** attempt to build or run the tests yourself. Rely on the script to do this and return the coverage results.

  3. Stop iterating if test coverage is already 100%.

  4. Code change should happen within the folder `src/` only. If you notice any change outside of the folder, revert them with `git restore` and print warnings. 

If you exhaust all iterations without reaching 100%, print "MAX ITERATIONS REACHED. Best coverage: <percent>%." and proceed to finalize.

Save the coverage report from the final iteration to the path specified in `coverage_result`.

## Reminder

If you are below 100%, you MUST generate more tests and iterate again. The number 100 is not a suggestion — it is a hard requirement.

What you must do is that let's only use the **unit-test** skill for now to keep things simple, any new function or edited function will be the focal functions. 

What you must do is to find out the existing unit tests in the repo that cover the focal functions and use them as reference for writing new tests.

What you mush do is at least 4 iterations if the coverage is below 100%. Do NOT stop before 4 iterations even if you think the coverage is not improving much. You must keep trying until you exhaust all 4 iterations.