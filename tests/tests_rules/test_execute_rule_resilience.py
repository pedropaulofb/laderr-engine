import pytest
from rdflib import Namespace

from tests.utils import EXAMPLE

LADERR = Namespace("https://w3id.org/laderr#")


@pytest.fixture
def laderr_graph_with_valid_resilience_case():
    """
    Creates an RDF graph that satisfies the resilience inference rule.
    """
    g = Graph()

    # Entities
    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2
    entity3 = EXAMPLE.entity3

    # Capabilities
    capability1 = EXAMPLE.capability1  # belongs to entity1
    capability2 = EXAMPLE.capability2  # belongs to entity2 (disabling capability)
    capability3 = EXAMPLE.capability3  # belongs to entity3 (exploiting capability)

    # Vulnerability
    vulnerability1 = EXAMPLE.vulnerability1

    # Assign types
    g.add((entity1, RDF.type, LADERR.Entity))
    g.add((entity2, RDF.type, LADERR.Entity))
    g.add((entity3, RDF.type, LADERR.Entity))
    g.add((capability1, RDF.type, LADERR.Capability))
    g.add((capability2, RDF.type, LADERR.Capability))
    g.add((capability3, RDF.type, LADERR.Capability))
    g.add((vulnerability1, RDF.type, LADERR.Vulnerability))

    # Link capabilities to entities
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity2, LADERR.capabilities, capability2))
    g.add((entity3, LADERR.capabilities, capability3))

    # Link vulnerability to entity1
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))

    # Capability2 disables vulnerability1
    g.add((capability2, LADERR.disables, vulnerability1))

    # Vulnerability exposes capability1
    g.add((vulnerability1, LADERR.exposes, capability1))

    # Capability3 exploits vulnerability1
    g.add((capability3, LADERR.exploits, vulnerability1))

    # Capability2 is enabled
    g.add((capability2, LADERR.state, LADERR.enabled))

    return g, entity1, capability1, capability2, capability3, vulnerability1


def test_resilience_inferred(laderr_graph_with_valid_resilience_case):
    """
    Tests that a resilience instance is inferred when all required conditions are met.
    """
    g, entity1, capability1, capability2, capability3, vulnerability1 = laderr_graph_with_valid_resilience_case

    InferenceRules.execute_rule_resilience_participants(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(resilience_instances) == 1, "Expected exactly one inferred Resilience instance."

    resilience = resilience_instances[0]

    # Check label exists and is non-empty
    label = g.value(resilience, RDFS.label)
    assert label is not None and len(str(label)) > 0, "Inferred Resilience should have a non-empty label."

    # Check expected relationships
    assert (entity1, LADERR.resiliences, resilience) in g
    assert (resilience, LADERR.preserves, capability1) in g
    assert (resilience, LADERR.preservesAgainst, capability3) in g
    assert (resilience, LADERR.preservesDespite, vulnerability1) in g
    assert (capability2, LADERR.sustains, resilience) in g


def test_resilience_inferred_without_enabled_capability2(laderr_graph_with_valid_resilience_case):
    """
    Tests that resilience is inferred even if the disabling capability is initially disabled.
    This happens because execute_rule_disabled_state ensures that any disabling capability
    is always set to enabled.
    """
    g, entity1, capability1, capability2, capability3, vulnerability1 = laderr_graph_with_valid_resilience_case

    # Explicitly set capability2 to disabled before running the rules
    g.remove((capability2, LADERR.state, LADERR.enabled))
    g.add((capability2, LADERR.state, LADERR.disabled))

    # First, enforce the disabled state rule, which should re-enable capability2
    InferenceRules.execute_rule_disposition_state(g)

    # Then, check if resilience is inferred as expected
    InferenceRules.execute_rule_resilience_participants(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(
        resilience_instances) == 1, "Resilience should be inferred even if the disabling capability is not enabled."


def test_resilience_not_inferred_with_same_entity_capabilities():
    """
    Tests that resilience is not inferred when all capabilities belong to the same entity.
    """
    g = Graph()

    entity1 = EXAMPLE.entity1

    capability1 = EXAMPLE.capability1
    capability2 = EXAMPLE.capability2
    capability3 = EXAMPLE.capability3

    vulnerability1 = EXAMPLE.vulnerability1

    g.add((entity1, RDF.type, LADERR.Entity))
    g.add((capability1, RDF.type, LADERR.Capability))
    g.add((capability2, RDF.type, LADERR.Capability))
    g.add((capability3, RDF.type, LADERR.Capability))
    g.add((vulnerability1, RDF.type, LADERR.Vulnerability))

    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.capabilities, capability2))
    g.add((entity1, LADERR.capabilities, capability3))

    g.add((entity1, LADERR.vulnerabilities, vulnerability1))

    g.add((capability2, LADERR.disables, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))
    g.add((capability3, LADERR.exploits, vulnerability1))

    g.add((capability2, LADERR.state, LADERR.enabled))

    InferenceRules.execute_rule_resilience_participants(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(
        resilience_instances) == 0, "No Resilience should be inferred if all capabilities belong to the same entity."


import pytest
from rdflib import Graph, Namespace, URIRef, RDF, RDFS
from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed

LADERR = Namespace("https://w3id.org/laderr#")


@pytest.mark.parametrize("missing_relation", ["disables", "exposes", "exploits"])
def test_resilience_not_inferred_with_missing_relationships(laderr_graph_with_valid_resilience_case, missing_relation):
    """
    Tests that resilience is NOT inferred when a required relationship is missing.
    This ensures that each component (disables, exposes, exploits) is necessary.
    """
    g, entity1, capability1, capability2, capability3, vulnerability1 = laderr_graph_with_valid_resilience_case

    if missing_relation == "disables":
        g.remove((capability2, LADERR.disables, vulnerability1))
    elif missing_relation == "exposes":
        g.remove((vulnerability1, LADERR.exposes, capability1))
    elif missing_relation == "exploits":
        g.remove((capability3, LADERR.exploits, vulnerability1))

    InferenceRules.execute_rule_resilience_participants(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(resilience_instances) == 0, f"Resilience should NOT be inferred when '{missing_relation}' is missing."


@pytest.mark.parametrize("missing_capability, entity", [
    ("capability1", "entity1"),  # Missing preserved capability
    ("capability2", "entity2"),  # Missing disabling capability
    ("capability3", "entity3")  # Missing exploiting capability
])
def test_resilience_not_inferred_with_missing_capabilities(laderr_graph_with_valid_resilience_case, missing_capability,
                                                           entity):
    """
    Tests that resilience is NOT inferred when a required capability is missing.
    This ensures that each capability (preserved, disabling, exploiting) is necessary.
    """
    g, entity1, capability1, capability2, capability3, vulnerability1 = laderr_graph_with_valid_resilience_case

    entity_uri = URIRef(f"https://example.org/{entity}")
    capability_uri = URIRef(f"https://example.org/{missing_capability}")

    g.remove((entity_uri, LADERR.capabilities, capability_uri))  # Remove from the correct entity

    # Also remove related relationships
    if missing_capability == "capability1":
        g.remove((vulnerability1, LADERR.exposes, capability1))
    elif missing_capability == "capability2":
        g.remove((capability2, LADERR.disables, vulnerability1))
    elif missing_capability == "capability3":
        g.remove((capability3, LADERR.exploits, vulnerability1))

    InferenceRules.execute_rule_resilience_participants(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(resilience_instances) == 0, f"Resilience should NOT be inferred when '{missing_capability}' is missing."


def test_resilience_inferred_with_multiple_vulnerabilities(laderr_graph_with_valid_resilience_case):
    """
    Tests that resilience is only inferred when at least one vulnerability meets the required conditions.
    """
    g, entity1, capability1, capability2, capability3, vulnerability1 = laderr_graph_with_valid_resilience_case

    # Add a second vulnerability (should not interfere with the first)
    vulnerability2 = EXAMPLE.vulnerability2
    g.add((entity1, LADERR.vulnerabilities, vulnerability2))
    g.add((capability2, LADERR.disables, vulnerability2))  # This one is also disabled
    g.add((capability3, LADERR.exploits, vulnerability2))

    InferenceRules.execute_rule_resilience_participants(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(
        resilience_instances) == 1, "Resilience should still be inferred when there are multiple vulnerabilities."


def test_resilience_inferred_with_multiple_disabling_capabilities(laderr_graph_with_valid_resilience_case):
    """
    Tests that resilience is inferred when multiple capabilities disable the same vulnerability.
    """
    g, entity1, capability1, capability2, capability3, vulnerability1 = laderr_graph_with_valid_resilience_case

    # Add a second disabling capability
    capability4 = EXAMPLE.capability4
    entity4 = EXAMPLE.entity4
    g.add((entity4, LADERR.capabilities, capability4))
    g.add((capability4, LADERR.disables, vulnerability1))
    g.add((capability4, LADERR.state, LADERR.enabled))  # Also enabled

    InferenceRules.execute_rule_resilience_participants(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(
        resilience_instances) == 2, "Resilience should still be inferred even if multiple capabilities disable the same vulnerability."


def test_resilience_not_inferred_when_other_vulnerability_is_not_disabled(laderr_graph_with_valid_resilience_case):
    """
    Tests that resilience is NOT inferred when an entity has multiple vulnerabilities,
    but only one of them is disabled.
    """
    g, entity1, capability1, capability2, capability3, vulnerability1 = laderr_graph_with_valid_resilience_case

    # Add a second vulnerability that is NOT disabled
    vulnerability2 = EXAMPLE.vulnerability2
    g.add((entity1, LADERR.vulnerabilities, vulnerability2))
    g.add((capability3, LADERR.exploits, vulnerability2))  # Exploited but NOT disabled

    InferenceRules.execute_rule_resilience_participants(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(
        resilience_instances) == 1, "Resilience should NOT be inferred for the second vulnerability, but the first should still hold."
