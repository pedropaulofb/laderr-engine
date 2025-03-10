import pytest
from rdflib import Graph, Namespace

from tests.utils import EXAMPLE

LADERR = Namespace("https://w3id.org/laderr#")

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed


@pytest.fixture
def laderr_graph_with_disabling_capability():
    g = Graph()

    # Entities
    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2
    g.add((entity1, LADERR.capabilities, EXAMPLE.capability1))
    g.add((entity2, LADERR.vulnerabilities, EXAMPLE.vulnerability1))

    # Capability and Vulnerability
    capability = EXAMPLE.capability1
    vulnerability = EXAMPLE.vulnerability1

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
    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2

    # Capabilities and vulnerabilities, but no "disables"
    g.add((entity1, LADERR.capabilities, EXAMPLE.capability1))
    g.add((entity2, LADERR.vulnerabilities, EXAMPLE.vulnerability1))

    InferenceRules.execute_rule_protects(g)

    assert (entity1, LADERR.protects, entity2) not in g, \
        "No disables defined, so no protects should be inferred."


def test_protects_already_exists():
    g = Graph()
    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2

    capability = EXAMPLE.capability1
    vulnerability = EXAMPLE.vulnerability1

    g.add((entity1, LADERR.capabilities, capability))
    g.add((entity2, LADERR.vulnerabilities, vulnerability))
    g.add((capability, LADERR.disables, vulnerability))

    # Manually state the protects relation
    g.add((entity1, LADERR.protects, entity2))

    InferenceRules.execute_rule_protects(g)

    assert len(list(g.triples((entity1, LADERR.protects, entity2)))) == 1, \
        "protects relationship should not be duplicated."
