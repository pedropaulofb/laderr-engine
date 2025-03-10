import pytest
from rdflib import Graph, Namespace, URIRef, RDF

from tests.aux import EXAMPLE

LADERR = Namespace("https://w3id.org/laderr#")

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed


@pytest.fixture
def laderr_graph_with_incident_scenario():
    """
    Creates an RDF graph with a LaderrSpecification in an INCIDENT scenario
    and constructs containing entities with vulnerabilities.
    """
    g = Graph()

    spec = EXAMPLE.specification
    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2

    capability1 = EXAMPLE.capability1
    capability2 = EXAMPLE.capability2

    vulnerability1 = EXAMPLE.vulnerability1
    vulnerability2 = EXAMPLE.vulnerability2

    # Specification setup
    g.add((spec, RDF.type, LADERR.LaderrSpecification))
    g.add((spec, LADERR.scenario, LADERR.incident))
    g.add((spec, LADERR.constructs, entity1))
    g.add((spec, LADERR.constructs, entity2))

    # Entity 1 setup
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))

    # Entity 2 setup
    g.add((entity2, LADERR.capabilities, capability2))
    g.add((entity2, LADERR.vulnerabilities, vulnerability2))

    return g, spec, entity1, entity2, capability1, capability2, vulnerability1, vulnerability2


def test_scenario_resilient_inferred_when_all_vulnerabilities_disabled(laderr_graph_with_incident_scenario):
    """
    Tests that the scenario becomes RESILIENT when all vulnerabilities are DISABLED.
    """
    g, spec, entity1, entity2, _, _, vulnerability1, vulnerability2 = laderr_graph_with_incident_scenario

    # Disable all vulnerabilities
    g.add((vulnerability1, LADERR.state, LADERR.disabled))
    g.add((vulnerability2, LADERR.state, LADERR.disabled))

    InferenceRules.execute_rule_scenario_resilient(g)

    assert (spec, LADERR.scenario, LADERR.resilient) in g, \
        "Scenario should be set to RESILIENT when all vulnerabilities are DISABLED."


def test_scenario_resilient_inferred_when_all_vulnerabilities_exploited(laderr_graph_with_incident_scenario):
    """
    Tests that the scenario becomes RESILIENT when all vulnerabilities are exploited by some capability.
    """
    g, spec, entity1, entity2, capability1, capability2, vulnerability1, vulnerability2 = laderr_graph_with_incident_scenario

    # Ensure vulnerabilities are enabled
    g.add((vulnerability1, LADERR.state, LADERR.enabled))
    g.add((vulnerability2, LADERR.state, LADERR.enabled))

    # Make capabilities exploit vulnerabilities
    g.add((capability1, LADERR.exploits, vulnerability1))
    g.add((capability2, LADERR.exploits, vulnerability2))

    InferenceRules.execute_rule_scenario_resilient(g)

    assert (spec, LADERR.scenario, LADERR.resilient) in g, \
        "Scenario should be set to RESILIENT when all vulnerabilities are exploited."


@pytest.mark.parametrize("vulnerability_state, expected_scenario", [
    ("enabled", LADERR.incident),  # At least one vulnerability is enabled → scenario remains INCIDENT
    ("disabled", LADERR.resilient),  # All vulnerabilities disabled → scenario becomes RESILIENT
    ("exploited", LADERR.resilient)  # All vulnerabilities exploited → scenario becomes RESILIENT
])
def test_scenario_resilient_various_cases(laderr_graph_with_incident_scenario, vulnerability_state, expected_scenario):
    """
    Tests different combinations of vulnerabilities being enabled, disabled, or exploited.
    """
    g, spec, entity1, entity2, capability1, capability2, vulnerability1, vulnerability2 = laderr_graph_with_incident_scenario

    if vulnerability_state == "enabled":
        g.add((vulnerability1, LADERR.state, LADERR.enabled))
        g.add((vulnerability2, LADERR.state, LADERR.enabled))
    elif vulnerability_state == "disabled":
        g.add((vulnerability1, LADERR.state, LADERR.disabled))
        g.add((vulnerability2, LADERR.state, LADERR.disabled))
    elif vulnerability_state == "exploited":
        g.add((vulnerability1, LADERR.state, LADERR.enabled))
        g.add((vulnerability2, LADERR.state, LADERR.enabled))
        g.add((capability1, LADERR.exploits, vulnerability1))
        g.add((capability2, LADERR.exploits, vulnerability2))

    InferenceRules.execute_rule_scenario_resilient(g)

    assert (spec, LADERR.scenario, expected_scenario) in g, \
        f"Scenario should be {expected_scenario} when vulnerability state is '{vulnerability_state}'."


def test_scenario_resilient_not_inferred_when_already_resilient(laderr_graph_with_incident_scenario):
    """
    Tests that the scenario does NOT change if it is already RESILIENT.
    """
    g, spec, entity1, _, _, _, _, _ = laderr_graph_with_incident_scenario

    # Set scenario to RESILIENT before execution
    g.set((spec, LADERR.scenario, LADERR.resilient))

    InferenceRules.execute_rule_scenario_resilient(g)

    assert (spec, LADERR.scenario, LADERR.resilient) in g, \
        "Scenario should remain RESILIENT if it was already set as RESILIENT."


def test_scenario_resilient_not_inferred_if_not_incident(laderr_graph_with_incident_scenario):
    """
    Tests that the scenario remains unchanged if it is NOT INCIDENT.
    """
    g, spec, entity1, _, _, _, _, _ = laderr_graph_with_incident_scenario

    # Set scenario to something other than INCIDENT
    g.set((spec, LADERR.scenario, LADERR.operational))

    InferenceRules.execute_rule_scenario_resilient(g)

    assert (spec, LADERR.scenario, LADERR.operational) in g, \
        "Scenario should remain OPERATIONAL if it was not INCIDENT."

def test_scenario_remains_incident_when_mixed_vulnerability_states(laderr_graph_with_incident_scenario):
    """
    Tests that the scenario remains INCIDENT when at least one vulnerability is enabled and NOT exploited,
    even if others are disabled or exploited.
    """
    g, spec, entity1, entity2, capability1, capability2, vulnerability1, vulnerability2 = laderr_graph_with_incident_scenario

    # One vulnerability is disabled, the other is enabled but NOT exploited
    g.add((vulnerability1, LADERR.state, LADERR.disabled))
    g.add((vulnerability2, LADERR.state, LADERR.enabled))

    InferenceRules.execute_rule_scenario_resilient(g)

    assert (spec, LADERR.scenario, LADERR.incident) in g, \
        "Scenario should remain INCIDENT when at least one vulnerability is enabled and not exploited."

def test_scenario_resilient_ignores_non_entities(laderr_graph_with_incident_scenario):
    """
    Ensures that the scenario only considers vulnerabilities of actual entities,
    ignoring other constructs that are not explicitly marked as entities.
    """
    g, spec, entity1, entity2, _, _, vulnerability1, vulnerability2 = laderr_graph_with_incident_scenario

    # Add a non-entity construct with a vulnerability
    non_entity_construct = EXAMPLE.nonEntityConstruct
    g.add((spec, LADERR.constructs, non_entity_construct))
    g.add((non_entity_construct, LADERR.vulnerabilities, vulnerability1))
    g.add((vulnerability1, LADERR.state, LADERR.enabled))

    InferenceRules.execute_rule_scenario_resilient(g)

    assert (spec, LADERR.scenario, LADERR.incident) in g, \
        "Scenario should not become RESILIENT if a non-entity construct has an enabled vulnerability."

