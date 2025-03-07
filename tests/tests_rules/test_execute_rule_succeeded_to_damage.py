import pytest
from icecream import ic
from rdflib import Graph, Namespace, URIRef, Literal, RDF

LADERR = Namespace("https://w3id.org/laderr#")

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed

@pytest.fixture
def laderr_graph_with_valid_succeeded_to_damage_case():
    g = Graph()

    spec = URIRef("https://example.org/specification")
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

    # Specification setup
    g.add((spec, RDF.type, LADERR.LaderrSpecification))
    g.add((spec, LADERR.scenario, LADERR.incident))
    g.add((spec, LADERR.composedOf, entity1))
    g.add((spec, LADERR.composedOf, entity2))

    # Relationships for entity1
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))

    # Relationships for entity2
    g.add((entity2, LADERR.capabilities, capability2))

    # Exploitation relation
    g.add((capability2, LADERR.exploits, vulnerability1))

    # States (both enabled)
    g.add((capability2, LADERR.state, LADERR.enabled))
    g.add((vulnerability1, LADERR.state, LADERR.enabled))

    return g, spec, entity1, entity2


def test_succeeded_to_damage_inferred(laderr_graph_with_valid_succeeded_to_damage_case):
    g, spec, entity1, entity2 = laderr_graph_with_valid_succeeded_to_damage_case

    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage, entity1) in g, \
        "Expected succeededToDamage relationship was not inferred."

    assert (spec, LADERR.scenario, LADERR.not_resilient) in g, \
        "Expected scenario to change to NOT_RESILIENT."


def test_succeeded_to_damage_not_inferred_without_exploit():
    g = Graph()

    spec = URIRef("https://example.org/specification")
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

    g.add((spec, LADERR.scenario, LADERR.incident))
    g.add((spec, LADERR.composedOf, entity1))
    g.add((spec, LADERR.composedOf, entity2))

    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))

    g.add((entity2, LADERR.capabilities, capability2))

    # States (both enabled)
    g.add((capability2, LADERR.state, LADERR.enabled))
    g.add((vulnerability1, LADERR.state, LADERR.enabled))

    # Missing the exploitation link
    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage, entity1) not in g, \
        "No succeededToDamage should be inferred without exploitation."


def test_succeeded_to_damage_not_inferred_without_exposes():
    g = Graph()

    spec = URIRef("https://example.org/specification")
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

    g.add((spec, LADERR.scenario, LADERR.incident))
    g.add((spec, LADERR.composedOf, entity1))
    g.add((spec, LADERR.composedOf, entity2))

    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))

    g.add((entity2, LADERR.capabilities, capability2))
    g.add((capability2, LADERR.exploits, vulnerability1))

    # States (both enabled)
    g.add((capability2, LADERR.state, LADERR.enabled))
    g.add((vulnerability1, LADERR.state, LADERR.enabled))

    # Missing the exposes link
    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage, entity1) not in g, \
        "No succeededToDamage should be inferred without exposure link."


def test_succeeded_to_damage_not_inferred_if_already_exists(laderr_graph_with_valid_succeeded_to_damage_case):
    g, spec, entity1, entity2 = laderr_graph_with_valid_succeeded_to_damage_case

    # Pre-existing relationship
    g.add((entity2, LADERR.succeededToDamage, entity1))

    InferenceRules.execute_rule_succeeded_to_damage(g)

    # Relationship should still exist, but not duplicated
    assert len(list(g.triples((entity2, LADERR.succeededToDamage, entity1)))) == 1, \
        "succeededToDamage should not be duplicated."

    # Scenario must still change to NOT_RESILIENT if all conditions hold
    assert (spec, LADERR.scenario, LADERR.not_resilient) in g, \
        "Scenario should be set to NOT_RESILIENT."


def test_succeeded_to_damage_not_inferred_when_states_are_disabled():
    g = Graph()

    spec = URIRef("https://example.org/specification")
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

    g.add((spec, LADERR.scenario, LADERR.incident))
    g.add((spec, LADERR.composedOf, entity1))
    g.add((spec, LADERR.composedOf, entity2))

    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))

    g.add((entity2, LADERR.capabilities, capability2))
    g.add((capability2, LADERR.exploits, vulnerability1))

    # Both states disabled
    g.add((capability2, LADERR.state, LADERR.disabled))
    g.add((vulnerability1, LADERR.state, LADERR.disabled))

    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage, entity1) not in g, \
        "succeededToDamage should not be inferred if states are disabled."

    # Scenario should remain INCIDENT (no damage happened)
    assert (spec, LADERR.scenario, LADERR.incident) in g, \
        "Scenario should not change if no succeededToDamage is inferred."

def test_succeeded_to_damage_not_inferred_without_specification():
    g = Graph()

    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))

    g.add((entity2, LADERR.capabilities, capability2))
    g.add((capability2, LADERR.exploits, vulnerability1))

    # Both states enabled
    g.add((capability2, LADERR.state, LADERR.enabled))
    g.add((vulnerability1, LADERR.state, LADERR.enabled))

    # Missing LaderrSpecification entirely
    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage, entity1) not in g, \
        "succeededToDamage should not be inferred without a LaderrSpecification."

def test_succeeded_to_damage_not_inferred_with_non_incident_scenario():
    g = Graph()

    spec = URIRef("https://example.org/specification")
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

    # Specification setup with scenario = operational (instead of incident)
    g.add((spec, RDF.type, LADERR.LaderrSpecification))
    g.add((spec, LADERR.scenario, LADERR.operational))  # 👈 Not incident
    g.add((spec, LADERR.composedOf, entity1))
    g.add((spec, LADERR.composedOf, entity2))

    # Valid relationships between entities, capabilities, and vulnerabilities
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))

    g.add((entity2, LADERR.capabilities, capability2))
    g.add((capability2, LADERR.exploits, vulnerability1))

    # Both states enabled
    g.add((capability2, LADERR.state, LADERR.enabled))
    g.add((vulnerability1, LADERR.state, LADERR.enabled))

    # Run inference rule (should do nothing because scenario is not INCIDENT)
    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage, entity1) not in g, \
        "succeededToDamage should NOT be inferred when scenario is not INCIDENT."

    assert (spec, LADERR.scenario, LADERR.operational) in g, \
        "Scenario should remain unchanged if rule does not trigger."
