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
    g.add((spec, LADERR.constructs, entity1))
    g.add((spec, LADERR.constructs, entity2))

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

    assert (
           entity2, LADERR.succeededToDamage, entity1) in g, "Expected succeededToDamage relationship was not inferred."

    assert (spec, LADERR.scenario, LADERR.not_resilient) in g, "Expected scenario to change to NOT_RESILIENT."


def test_succeeded_to_damage_not_inferred_if_already_exists(laderr_graph_with_valid_succeeded_to_damage_case):
    g, spec, entity1, entity2 = laderr_graph_with_valid_succeeded_to_damage_case

    # Pre-existing relationship
    g.add((entity2, LADERR.succeededToDamage, entity1))

    InferenceRules.execute_rule_succeeded_to_damage(g)

    # Ensure succeededToDamage is still present
    assert (entity2, LADERR.succeededToDamage, entity1) in g, "succeededToDamage should still be present."

    # Scenario should still be NOT_RESILIENT
    assert (spec, LADERR.scenario,
            LADERR.not_resilient) in g, "Scenario should still be NOT_RESILIENT if conditions hold."


@pytest.mark.parametrize("disabled_state", ["capability", "vulnerability", "both"])
def test_succeeded_to_damage_not_inferred_when_any_state_is_disabled(laderr_graph_with_valid_succeeded_to_damage_case, disabled_state):
    """
    Tests that succeededToDamage is NOT inferred when any required state is disabled.
    """
    g, spec, entity1, entity2 = laderr_graph_with_valid_succeeded_to_damage_case

    if disabled_state == "capability":
        g.set((URIRef("https://example.org/capability2"), LADERR.state, LADERR.disabled))
    elif disabled_state == "vulnerability":
        g.set((URIRef("https://example.org/vulnerability1"), LADERR.state, LADERR.disabled))
    elif disabled_state == "both":
        g.set((URIRef("https://example.org/capability2"), LADERR.state, LADERR.disabled))
        g.set((URIRef("https://example.org/vulnerability1"), LADERR.state, LADERR.disabled))

    # Run inference
    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage, entity1) not in g, \
        f"succeededToDamage should not be inferred when '{disabled_state}' is disabled."



def test_succeeded_to_damage_not_inferred_without_specification(laderr_graph_with_valid_succeeded_to_damage_case):
    """
    Tests that succeededToDamage is NOT inferred when no LaderrSpecification is present.
    """
    g, spec, entity1, entity2 = laderr_graph_with_valid_succeeded_to_damage_case

    # Remove the LaderrSpecification
    g.remove((spec, RDF.type, LADERR.LaderrSpecification))

    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage, entity1) not in g, \
        "succeededToDamage should not be inferred without a LaderrSpecification."



def test_succeeded_to_damage_not_inferred_with_non_incident_scenario(laderr_graph_with_valid_succeeded_to_damage_case):
    """
    Tests that succeededToDamage is NOT inferred if scenario != INCIDENT,
    unless it was missing.
    """
    g, spec, entity1, entity2 = laderr_graph_with_valid_succeeded_to_damage_case

    # Change scenario to OPERATIONAL instead of INCIDENT
    g.set((spec, LADERR.scenario, LADERR.operational))

    InferenceRules.execute_rule_succeeded_to_damage(g)

    if (entity2, LADERR.succeededToDamage, entity1) in g:
        # If it was already inferred, scenario should be NOT_RESILIENT
        assert (spec, LADERR.scenario, LADERR.not_resilient) in g, \
            "Scenario should change to NOT_RESILIENT if succeededToDamage exists."
    else:
        # If succeededToDamage was missing, scenario should remain OPERATIONAL
        assert (spec, LADERR.scenario, LADERR.operational) in g, \
            "Scenario should remain OPERATIONAL if succeededToDamage was missing."



@pytest.mark.parametrize("missing_relation", ["exploits", "exposes"])
def test_succeeded_to_damage_not_inferred_without_necessary_relation(laderr_graph_with_valid_succeeded_to_damage_case,
                                                                     missing_relation):
    """
    Tests that succeededToDamage is NOT inferred when a required relationship is missing.
    """
    g, spec, entity1, entity2 = laderr_graph_with_valid_succeeded_to_damage_case

    if missing_relation == "exploits":
        g.remove(
            (URIRef("https://example.org/capability2"), LADERR.exploits, URIRef("https://example.org/vulnerability1")))
    elif missing_relation == "exposes":
        g.remove(
            (URIRef("https://example.org/vulnerability1"), LADERR.exposes, URIRef("https://example.org/capability1")))

    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage,
            entity1) not in g, f"succeededToDamage should not be inferred when '{missing_relation}' is missing."


def test_succeeded_to_damage_inferred_when_missing_but_not_incident(laderr_graph_with_valid_succeeded_to_damage_case):
    """
    Tests that succeededToDamage is inferred even if scenario != INCIDENT, as long as it was not inferred before.
    """
    g, spec, entity1, entity2 = laderr_graph_with_valid_succeeded_to_damage_case

    # Ensure succeededToDamage is first inferred in an INCIDENT scenario
    InferenceRules.execute_rule_succeeded_to_damage(g)
    assert (entity2, LADERR.succeededToDamage, entity1) in g, \
        "Precondition failed: succeededToDamage should be inferred in the INCIDENT scenario."

    # Change scenario to OPERATIONAL
    g.set((spec, LADERR.scenario, LADERR.operational))

    # Remove succeededToDamage to test inference in non-incident cases
    g.remove((entity2, LADERR.succeededToDamage, entity1))

    InferenceRules.execute_rule_succeeded_to_damage(g)

    assert (entity2, LADERR.succeededToDamage, entity1) in g, \
        "succeededToDamage should be inferred even if scenario is not INCIDENT, as long as it was missing."

    assert (spec, LADERR.scenario, LADERR.not_resilient) in g, \
        "Scenario should still change to NOT_RESILIENT if succeededToDamage is inferred."
