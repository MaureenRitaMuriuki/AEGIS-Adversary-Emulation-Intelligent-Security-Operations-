# AEGIS Detection Engineering Methodology

## Purpose

A detection is a testable hypothesis about observable behaviour. AEGIS records the source events, rule identifier, severity and ATT&CK technique associated with each generated alert so an analyst can validate the result.

## Detection lifecycle

1. Define the behaviour and defensive objective.
2. Identify the telemetry required to observe it.
3. Map the behaviour to a relevant MITRE ATT&CK technique where appropriate.
4. Implement a deterministic rule with explicit match conditions.
5. Add positive fixtures that should trigger the rule.
6. Add negative fixtures that should not trigger the rule.
7. Run the automated test suite.
8. Document known limitations, false-positive considerations and investigation steps.
9. Validate against authorized lab telemetry before describing the rule as operationally effective.

## Rule quality requirements

Every production-intended AEGIS rule should include:

- Stable rule identifier and human-readable title.
- Severity and rationale.
- Required event source and fields.
- Match conditions and exclusions.
- ATT&CK technique mapping, only when justified.
- Positive and negative test fixtures.
- Analyst investigation guidance.
- Known blind spots and tuning notes.

## Evaluation metrics

AEGIS will report metrics only from a named, reproducible test set:

- True positives: malicious or simulated test cases correctly detected.
- False positives: benign test cases incorrectly alerted.
- False negatives: test cases that should have alerted but did not.
- Precision: TP / (TP + FP).
- Recall: TP / (TP + FN).

A high alert count is not evidence of good detection. Results must include the test-set size, scenario definitions and limitations.

## Current limitations

The initial rules are deliberately narrow demonstrations. Command-line string matching is not behavioural proof, and authentication correlation requires time-windowing and source-aware grouping before it should be used for operational monitoring. These limitations are tracked in the project roadmap.
