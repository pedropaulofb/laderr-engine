import pytest
from rdflib import Graph, Namespace, URIRef

LADERR = Namespace("https://w3id.org/laderr#")

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust the import if needed

@pytest.fixture
def laderr_graph_with_inhibiting_capability():
    g = Graph()

    # Entities
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    # Capabilities
    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")

    # Set up capabilities belonging to entities
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity2, LADERR.capabilities, capability2))

    # Capability2 disables capability1
    g.add((capability2, LADERR.disables, capability1))

    return g, entity1, entity2

def test_execute_rule_inhibits(laderr_graph_with_inhibiting_capability):
    g, entity1, entity2 = laderr_graph_with_inhibiting_capability

    # Execute the inference rule
    InferenceRules.execute_rule_inhibits(g)

    # Assert that the inhibits relationship was inferred
    assert (entity2, LADERR.inhibits, entity1) in g, \
        "Expected inhibits relationship was not inferred."

def test_no_disables_no_inhibits_inferred():
    g = Graph()
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    # Capabilities but no "disables"
    g.add((entity1, LADERR.capabilities, URIRef("https://example.org/capability1")))
    g.add((entity2, LADERR.capabilities, URIRef("https://example.org/capability2")))

    InferenceRules.execute_rule_inhibits(g)

    assert (entity2, LADERR.inhibits, entity1) not in g, \
        "No disables defined, so no inhibits should be inferred."


def test_inhibits_already_exists():
    g = Graph()
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")

    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity2, LADERR.capabilities, capability2))

    g.add((capability2, LADERR.disables, capability1))

    # Manually state the inhibits relation
    g.add((entity2, LADERR.inhibits, entity1))

    InferenceRules.execute_rule_inhibits(g)

    assert len(list(g.triples((entity2, LADERR.inhibits, entity1)))) == 1, \
        "inhibits relationship should not be duplicated."
