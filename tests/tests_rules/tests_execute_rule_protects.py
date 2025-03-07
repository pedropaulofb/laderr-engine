import pytest
from rdflib import Graph, Namespace, URIRef

LADERR = Namespace("https://w3id.org/laderr#")

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed

@pytest.fixture
def laderr_graph_with_disabling_capability():
    g = Graph()

    # Entities
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")
    g.add((entity1, LADERR.capabilities, URIRef("https://example.org/capability1")))
    g.add((entity2, LADERR.vulnerabilities, URIRef("https://example.org/vulnerability1")))

    # Capability and Vulnerability
    capability = URIRef("https://example.org/capability1")
    vulnerability = URIRef("https://example.org/vulnerability1")

    # Capability disables the vulnerability
    g.add((capability, LADERR.disables, vulnerability))

    return g, entity1, entity2

def test_execute_rule_protects(laderr_graph_with_disabling_capability):
    g, entity1, entity2 = laderr_graph_with_disabling_capability

    # Execute the inference rule
    InferenceRules.execute_rule_protects(g)

    # Assert that the protects relationship was inferred
    assert (entity1, LADERR.protects, entity2) in g, \
        "Expected protects relationship was not inferred."

def test_no_disables_no_protects_inferred():
    g = Graph()
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    # Capabilities and vulnerabilities, but no "disables"
    g.add((entity1, LADERR.capabilities, URIRef("https://example.org/capability1")))
    g.add((entity2, LADERR.vulnerabilities, URIRef("https://example.org/vulnerability1")))

    InferenceRules.execute_rule_protects(g)

    assert (entity1, LADERR.protects, entity2) not in g, \
        "No disables defined, so no protects should be inferred."


def test_protects_already_exists():
    g = Graph()
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    capability = URIRef("https://example.org/capability1")
    vulnerability = URIRef("https://example.org/vulnerability1")

    g.add((entity1, LADERR.capabilities, capability))
    g.add((entity2, LADERR.vulnerabilities, vulnerability))
    g.add((capability, LADERR.disables, vulnerability))

    # Manually state the protects relation
    g.add((entity1, LADERR.protects, entity2))

    InferenceRules.execute_rule_protects(g)

    assert len(list(g.triples((entity1, LADERR.protects, entity2)))) == 1, \
        "protects relationship should not be duplicated."

