import pytest
from icecream import ic
from rdflib import Graph, Namespace, URIRef, RDF, RDFS

from laderr_engine.laderr_lib.services.graph import GraphHandler
from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed

LADERR = Namespace("https://w3id.org/laderr#")


@pytest.fixture
def laderr_graph_with_valid_resilience_case():
    """
    Creates an RDF graph that satisfies the resilience inference rule.
    """
    g = Graph()

    # Entities
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")
    entity3 = URIRef("https://example.org/entity3")

    # Capabilities
    capability1 = URIRef("https://example.org/capability1")  # belongs to entity1
    capability2 = URIRef("https://example.org/capability2")  # belongs to entity2 (disabling capability)
    capability3 = URIRef("https://example.org/capability3")  # belongs to entity3 (exploiting capability)

    # Vulnerability
    vulnerability1 = URIRef("https://example.org/vulnerability1")

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

    InferenceRules.execute_rule_resilience(g)

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
    assert (resilience, LADERR.state, LADERR.enabled) in g


@pytest.mark.parametrize("missing_relation", ["disables",  # Missing disables relation
    "exposes",  # Missing exposes relation
    "exploits"  # Missing exploits relation
])
def test_resilience_not_inferred_with_missing_relationships(missing_relation):
    """
    Tests that no resilience instance is inferred if a critical relationship is missing.
    """
    g = Graph()
    g.bind("", "https://example.org/")

    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")
    entity3 = URIRef("https://example.org/entity3")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")
    capability3 = URIRef("https://example.org/capability3")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

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

    if missing_relation != "disables":
        g.add((capability2, LADERR.disables, vulnerability1))

    if missing_relation != "exposes":
        g.add((vulnerability1, LADERR.exposes, capability1))

    if missing_relation != "exploits":
        g.add((capability3, LADERR.exploits, vulnerability1))

    g.add((capability2, LADERR.state, LADERR.enabled))

    InferenceRules.execute_rule_resilience(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(resilience_instances) == 0, f"No Resilience should be inferred when '{missing_relation}' is missing."


def test_resilience_inferred_without_enabled_capability2(laderr_graph_with_valid_resilience_case):
    """
    Tests that resilience is inferred even if the disabling capability is initially disabled.
    This happens because execute_rule_disabled_state ensures that any disabling capability
    is always set to enabled.
    """
    g, entity1, capability1, capability2, capability3, vulnerability1 = laderr_graph_with_valid_resilience_case

    ic(GraphHandler.get_base_prefix(g))
    ic(g.serialize())

    # Explicitly set capability2 to disabled before running the rules
    g.remove((capability2, LADERR.state, LADERR.enabled))
    g.add((capability2, LADERR.state, LADERR.disabled))

    # First, enforce the disabled state rule, which should re-enable capability2
    InferenceRules.execute_rule_disabled_state(g)

    # Then, check if resilience is inferred as expected
    InferenceRules.execute_rule_resilience(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(
        resilience_instances) == 1, "Resilience should be inferred even if the disabling capability is not enabled."


def test_resilience_not_inferred_with_same_entity_capabilities():
    """
    Tests that resilience is not inferred when all capabilities belong to the same entity.
    """
    g = Graph()

    entity1 = URIRef("https://example.org/entity1")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")
    capability3 = URIRef("https://example.org/capability3")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

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

    InferenceRules.execute_rule_resilience(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(
        resilience_instances) == 0, "No Resilience should be inferred if all capabilities belong to the same entity."
