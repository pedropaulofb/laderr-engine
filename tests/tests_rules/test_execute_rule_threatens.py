import pytest
from rdflib import Graph, Namespace, URIRef

from tests.utils import EXAMPLE

LADERR = Namespace("https://w3id.org/laderr#")

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if necessary

@pytest.fixture
def laderr_graph_with_exploiting_capability():
    g = Graph()

    # Entities
    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2

    # Capability and Vulnerability
    capability = EXAMPLE.capability1
    vulnerability = EXAMPLE.vulnerability1

    # Link capabilities and vulnerabilities to entities
    g.add((entity1, LADERR.capabilities, capability))
    g.add((entity2, LADERR.vulnerabilities, vulnerability))

    # Capability exploits the vulnerability
    g.add((capability, LADERR.exploits, vulnerability))

    return g, entity1, entity2

def test_execute_rule_threatens(laderr_graph_with_exploiting_capability):
    g, entity1, entity2 = laderr_graph_with_exploiting_capability

    # Execute the inference rule
    InferenceRules.execute_rule_threatens(g)

    # Assert that the threatens relationship was inferred
    assert (entity1, LADERR.threatens, entity2) in g, \
        "Expected threatens relationship was not inferred."

def test_no_exploits_no_threatens_inferred():
    g = Graph()
    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2

    # Capabilities and vulnerabilities, but no "exploits" relation
    g.add((entity1, LADERR.capabilities, EXAMPLE.capability1))
    g.add((entity2, LADERR.vulnerabilities, EXAMPLE.vulnerability1))

    InferenceRules.execute_rule_threatens(g)

    assert (entity1, LADERR.threatens, entity2) not in g, \
        "No exploits defined, so no threatens should be inferred."

def test_threatens_already_exists():
    g = Graph()
    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2

    capability = EXAMPLE.capability1
    vulnerability = EXAMPLE.vulnerability1

    g.add((entity1, LADERR.capabilities, capability))
    g.add((entity2, LADERR.vulnerabilities, vulnerability))
    g.add((capability, LADERR.exploits, vulnerability))

    # Manually add the threatens relation
    g.add((entity1, LADERR.threatens, entity2))

    InferenceRules.execute_rule_threatens(g)

    assert len(list(g.triples((entity1, LADERR.threatens, entity2)))) == 1, \
        "threatens relationship should not be duplicated."
