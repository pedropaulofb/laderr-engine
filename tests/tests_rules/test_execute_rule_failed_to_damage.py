import pytest
from rdflib import Graph, Namespace, RDF

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed
from tests.utils import EXAMPLE

LADERR = Namespace("https://w3id.org/laderr#")


@pytest.fixture
def laderr_graph_with_valid_failed_to_damage_case():
    """
    Creates a valid RDF graph where failedToDamage should be inferred.
    """
    g = Graph()

    entity1 = EXAMPLE.entity1
    entity2 = EXAMPLE.entity2

    capability1 = EXAMPLE.capability1  # Preserved capability
    capability2 = EXAMPLE.capability2  # Exploiting capability

    vulnerability1 = EXAMPLE.vulnerability1

    # Define entities
    g.add((entity1, RDF.type, LADERR.Entity))
    g.add((entity2, RDF.type, LADERR.Entity))

    # Define capabilities & vulnerabilities
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))  # v1 exposes c1

    g.add((entity2, LADERR.capabilities, capability2))
    g.add((capability2, LADERR.exploits, vulnerability1))  # c2 exploits v1

    # Define states
    g.add((capability2, LADERR.state, LADERR.enabled))  # Attacking capability enabled
    g.add((vulnerability1, LADERR.state, LADERR.disabled))  # Vulnerability disabled

    return g, entity1, entity2


def test_failed_to_damage_inferred(laderr_graph_with_valid_failed_to_damage_case):
    """
    Tests that failedToDamage is inferred correctly when all required conditions hold.
    """
    g, entity1, entity2 = laderr_graph_with_valid_failed_to_damage_case

    InferenceRules.execute_rule_entity_damage_negative(g)

    assert (entity2, LADERR.failedToDamage, entity1) in g, \
        "Expected failedToDamage relationship was not inferred."


@pytest.mark.parametrize("missing_relation", ["exploits", "exposes"])
def test_failed_to_damage_not_inferred_without_necessary_relation(laderr_graph_with_valid_failed_to_damage_case,
                                                                  missing_relation):
    """
    Tests that failedToDamage is NOT inferred when a required relationship is missing.
    """
    g, entity1, entity2 = laderr_graph_with_valid_failed_to_damage_case

    if missing_relation == "exploits":
        g.remove((EXAMPLE.capability2, LADERR.exploits, EXAMPLE.vulnerability1))
    elif missing_relation == "exposes":
        g.remove((EXAMPLE.vulnerability1, LADERR.exposes, EXAMPLE.capability1))

    InferenceRules.execute_rule_entity_damage_negative(g)

    assert (entity2, LADERR.failedToDamage, entity1) not in g, \
        f"failedToDamage should not be inferred when '{missing_relation}' is missing."


@pytest.mark.parametrize("invalid_state", ["vulnerability_enabled", "capability_disabled"])
def test_failed_to_damage_not_inferred_with_invalid_states(laderr_graph_with_valid_failed_to_damage_case,
                                                           invalid_state):
    """
    Tests that failedToDamage is NOT inferred when vulnerability is not disabled
    or the exploiting capability is not enabled.
    """
    g, entity1, entity2 = laderr_graph_with_valid_failed_to_damage_case

    if invalid_state == "vulnerability_enabled":
        g.set((EXAMPLE.vulnerability1, LADERR.state, LADERR.enabled))
    elif invalid_state == "capability_disabled":
        g.set((EXAMPLE.capability2, LADERR.state, LADERR.disabled))

    InferenceRules.execute_rule_entity_damage_negative(g)

    assert (entity2, LADERR.failedToDamage, entity1) not in g, \
        f"failedToDamage should not be inferred when '{invalid_state}' is incorrect."


def test_failed_to_damage_not_inferred_if_already_exists(laderr_graph_with_valid_failed_to_damage_case):
    """
    Tests that failedToDamage is NOT inferred again if it already exists.
    """
    g, entity1, entity2 = laderr_graph_with_valid_failed_to_damage_case

    # Pre-existing failedToDamage relation
    g.add((entity2, LADERR.failedToDamage, entity1))

    InferenceRules.execute_rule_entity_damage_negative(g)

    assert len(list(g.triples((entity2, LADERR.failedToDamage, entity1)))) == 1, \
        "failedToDamage should not be duplicated."


@pytest.mark.parametrize("missing_capability", ["capability1", "capability2"])
def test_failed_to_damage_not_inferred_with_missing_capabilities(laderr_graph_with_valid_failed_to_damage_case,
                                                                 missing_capability):
    """
    Tests that failedToDamage is NOT inferred if one of the required capabilities is missing.
    """
    g, entity1, entity2 = laderr_graph_with_valid_failed_to_damage_case

    if missing_capability == "capability1":
        g.remove((entity1, LADERR.capabilities, EXAMPLE.capability1))
    elif missing_capability == "capability2":
        g.remove((entity2, LADERR.capabilities, EXAMPLE.capability2))

    InferenceRules.execute_rule_entity_damage_negative(g)

    assert (entity2, LADERR.failedToDamage, entity1) not in g, \
        f"failedToDamage should not be inferred when '{missing_capability}' is missing."


def test_failed_to_damage_not_inferred_with_only_one_entity():
    """
    Tests that failedToDamage is NOT inferred when there's only one entity in the graph.
    """
    g = Graph()

    entity1 = EXAMPLE.entity1
    capability1 = EXAMPLE.capability1
    vulnerability1 = EXAMPLE.vulnerability1

    # Define a single entity with capability & vulnerability
    g.add((entity1, RDF.type, LADERR.Entity))
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))

    # Define states
    g.add((vulnerability1, LADERR.state, LADERR.disabled))
    g.add((capability1, LADERR.state, LADERR.enabled))

    InferenceRules.execute_rule_entity_damage_negative(g)

    assert len(list(g.subjects(RDF.type, LADERR.failedToDamage))) == 0, \
        "failedToDamage should not be inferred with only one entity."
