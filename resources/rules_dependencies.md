# Rule Dependency Map

This table describes how the inference rules in LaDeRR depend on each other, ensuring correct execution order.

| **Rule ID**                    | **Type**         | **Depends on**                         | **Provides for**                  | **Explanation** |
|------------------|------------|----------------|------------------|------------------|
| **rule_protects**           | derivation  | None                                | None                            | Independent derivation rule — defines the `protects` relation. |
| **rule_inhibits**           | derivation  | None                                | None                            | Independent derivation rule — defines the `inhibits` relation. |
| **rule_threatens**          | derivation  | None                                | None                            | Independent derivation rule — defines the `threatens` relation. |
| **rule_resilience**         | instantiation| **rule_disabled_state**             | None                            | Needs to know if capabilities or vulnerabilities are **disabled**, so it depends on `rule_disabled_state`. |
| **rule_succeed_to_damage**  | derivation  | **rule_disabled_state**             | **rule_scenario_not_resilient** | Needs enabled capabilities/vulnerabilities — so it depends on `rule_disabled_state`. It also defines `succeededToDamage`, which is required by `rule_scenario_not_resilient`. |
| **rule_scenario_not_resilient** | derivation | **rule_succeed_to_damage**   | None                            | Depends directly on `succeededToDamage`, so it must run after `rule_succeed_to_damage`. |
| **rule_failed_to_damage**   | derivation  | **rule_disabled_state**             | None                            | Needs `state` information from `rule_disabled_state` to check if vulnerabilities are disabled. |
| **rule_scenario_resilient** | derivation  | **rule_disabled_state** and existing scenario = INCIDENT | None | Needs to know the state of vulnerabilities (from `rule_disabled_state`) and the current scenario (`scenario = INCIDENT`) to trigger. |
| **rule_disabled_state**     | derivation  | None                                | All rules that depend on state | Core rule — establishes the enabled/disabled state for dispositions, which affects many other rules. |
