# Rule Dependency Map

This table describes how the inference rules in LaDeRR depend on each other, ensuring the correct execution order.

| **Rule ID**                  | **Type**         | **Depends on**                         | **Provides for**                  | **Explanation** |
|------------------------------|-----------------|----------------------------------------|-----------------------------------|----------------|
| **rule_disabled_state**       | derivation      | None                                  | **All rules that depend on state** | Establishes whether dispositions are enabled or disabled, affecting multiple rules. |
| **rule_protects**             | derivation      | None                                  | None                              | Independent rule that defines the `protects` relation. |
| **rule_inhibits**             | derivation      | None                                  | None                              | Independent rule that defines the `inhibits` relation. |
| **rule_threatens**            | derivation      | None                                  | None                              | Independent rule that defines the `threatens` relation. |
| **rule_resilience**           | instantiation   | **rule_disabled_state**               | None                              | Needs to check whether vulnerabilities or capabilities are disabled before inferring resilience. |
| **rule_succeed_to_damage**    | derivation      | **rule_disabled_state**               | **rule_scenario_resilient**       | Needs enabled capabilities/vulnerabilities to infer `succeededToDamage`. Impacts `rule_scenario_resilient`. |
| **rule_failed_to_damage**     | derivation      | **rule_disabled_state**               | None                              | Needs to verify if vulnerabilities are disabled before inferring `failedToDamage`. |
| **rule_scenario_resilient**   | derivation      | **rule_disabled_state**, **rule_succeed_to_damage** | None | Needs to determine if any vulnerability is still enabled and whether `succeededToDamage` was inferred. |

