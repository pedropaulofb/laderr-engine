import pytest
from rdflib import Graph, Namespace, RDF

from tests.utils import EXAMPLE

LADERR = Namespace("https://w3id.org/laderr#")

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed


@pytest.fixture
def laderr_graph_with_inhibiting_capability():
    """
    Creates an RDF graph where:
    - Entity1 has Capability1
    - Entity2 has Capability2
    - Capability1 disables Vulnerability1
    - Capability2 exploits Vulnerability1
    - Expected result: Entity1 inhibits Entity2
    """
    g = Graph()

    # Entities
    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2

    # Capabilities
    capability1 = EXAMPLE.capability1
    capability2 = EXAMPLE.capability2

    # Vulnerability
    vulnerability1 = EXAMPLE.vulnerability1

    # Assign types
    g.add((entity1, RDF.type, LADERR.Entity))
    g.add((entity2, RDF.type, LADERR.Entity))
    g.add((capability1, RDF.type, LADERR.Capability))
    g.add((capability2, RDF.type, LADERR.Capability))
    g.add((vulnerability1, RDF.type, LADERR.Vulnerability))

    # Set up capability ownership
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity2, LADERR.capabilities, capability2))

    # Capability relationships
    g.add((capability1, LADERR.disables, vulnerability1))
    g.add((capability2, LADERR.exploits, vulnerability1))

    return g, entity1, entity2


def test_execute_rule_inhibits(laderr_graph_with_inhibiting_capability):
    """
    Tests whether the inhibition relationship is inferred correctly.
    """
    g, entity1, entity2 = laderr_graph_with_inhibiting_capability

    # Execute the inference rule
    InferenceRules.execute_rule_entity_inhibits(g)

    # Assert that the inhibits relationship was inferred
    assert (entity1, LADERR.inhibits, entity2) in g, "Expected inhibits relationship was not inferred."


@pytest.mark.parametrize("add_disables, add_exploits", [(False, False),  # No disables, No exploits
                                                        (False, True),  # No disables, Yes exploits
                                                        (True, False),  # Yes disables, No exploits
                                                        ])
def test_no_inhibits_inferred_when_conditions_not_met(add_disables, add_exploits):
    """
    Tests that no inhibition is inferred when conditions are not fully met.
    Cases:
    1. No disables and No exploits
    2. No disables and Yes exploits
    3. Yes disables and No exploits
    """

    g = Graph()

    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2
    capability1 = EXAMPLE.capability1
    capability2 = EXAMPLE.capability2
    vulnerability1 = EXAMPLE.vulnerability1

    # Assign types
    g.add((entity1, RDF.type, LADERR.Entity))
    g.add((entity2, RDF.type, LADERR.Entity))
    g.add((capability1, RDF.type, LADERR.Capability))
    g.add((capability2, RDF.type, LADERR.Capability))
    g.add((vulnerability1, RDF.type, LADERR.Vulnerability))

    # Set up capabilities
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity2, LADERR.capabilities, capability2))

    # Conditional relationships
    if add_disables:
        g.add((capability1, LADERR.disables, vulnerability1))
    if add_exploits:
        g.add((capability2, LADERR.exploits, vulnerability1))

    # Execute inference rule
    InferenceRules.execute_rule_entity_inhibits(g)

    # Assert that no inhibition is inferred
    assert (entity1, LADERR.inhibits,
            entity2) not in g, f"Inhibits relationship was incorrectly inferred for disables={add_disables}, exploits={add_exploits}."


def test_inhibits_already_exists():
    """
    Tests that the inference rule does not duplicate existing inhibits relationships.
    """
    g = Graph()

    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2
    capability1 = EXAMPLE.capability1
    capability2 = EXAMPLE.capability2
    vulnerability1 = EXAMPLE.vulnerability1

    # Assign types
    g.add((entity1, RDF.type, LADERR.Entity))
    g.add((entity2, RDF.type, LADERR.Entity))
    g.add((capability1, RDF.type, LADERR.Capability))
    g.add((capability2, RDF.type, LADERR.Capability))
    g.add((vulnerability1, RDF.type, LADERR.Vulnerability))

    # Set up capabilities
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity2, LADERR.capabilities, capability2))

    # Capability relationships
    g.add((capability1, LADERR.disables, vulnerability1))
    g.add((capability2, LADERR.exploits, vulnerability1))

    # Manually state the inhibits relation
    g.add((entity1, LADERR.inhibits, entity2))

    InferenceRules.execute_rule_entity_inhibits(g)

    # Ensure there is only ONE inhibits relationship (not duplicated)
    assert len(
        list(g.triples((entity1, LADERR.inhibits, entity2)))) == 1, "inhibits relationship should not be duplicated."


def test_self_inhibition_not_inferred():
    """
    Ensures that entities do not inhibit themselves.
    """
    g = Graph()

    entity1 = EXAMPLE.entity1
    capability1 = EXAMPLE.capability1
    vulnerability1 = EXAMPLE.vulnerability1

    # Assign types
    g.add((entity1, RDF.type, LADERR.Entity))
    g.add((capability1, RDF.type, LADERR.Capability))
    g.add((vulnerability1, RDF.type, LADERR.Vulnerability))

    # Set up capability
    g.add((entity1, LADERR.capabilities, capability1))

    # Capability relationships (self-inhibiting case)
    g.add((capability1, LADERR.disables, vulnerability1))
    g.add((capability1, LADERR.exploits, vulnerability1))  # Exploiting the same vulnerability

    InferenceRules.execute_rule_entity_inhibits(g)

    assert (entity1, LADERR.inhibits, entity1) not in g, "Entities should not inhibit themselves."
