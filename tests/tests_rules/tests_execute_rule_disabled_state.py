import pytest
from rdflib import Graph, Namespace, URIRef, RDF

LADERR = Namespace("https://w3id.org/laderr#")

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed

@pytest.fixture
def laderr_graph_with_disabling_relation():
    g = Graph()

    disposition1 = URIRef("https://example.org/disposition1")
    disposition2 = URIRef("https://example.org/disposition2")

    g.add((disposition1, RDF.type, LADERR.Disposition))
    g.add((disposition2, RDF.type, LADERR.Disposition))

    g.add((disposition1, LADERR.state, LADERR.enabled))
    g.add((disposition2, LADERR.state, LADERR.enabled))

    g.add((disposition1, LADERR.disables, disposition2))

    return g, disposition1, disposition2


def test_execute_rule_disabled_state_applies_rule(laderr_graph_with_disabling_relation):
    g, disposition1, disposition2 = laderr_graph_with_disabling_relation

    InferenceRules.execute_rule_disabled_state(g)

    assert (disposition2, LADERR.state, LADERR.disabled) in g, \
        "Disposition2 should have been disabled."

    assert (disposition2, LADERR.state, LADERR.enabled) not in g, \
        "Disposition2 should no longer be enabled."


def test_execute_rule_disabled_state_no_dispositions():
    g = Graph()

    InferenceRules.execute_rule_disabled_state(g)

    # Graph should remain empty (no dispositions exist to process)
    assert len(list(g)) == 0


def test_execute_rule_disabled_state_c1_not_enabled():
    g = Graph()

    disposition1 = URIRef("https://example.org/disposition1")
    disposition2 = URIRef("https://example.org/disposition2")

    g.add((disposition1, RDF.type, LADERR.Disposition))
    g.add((disposition2, RDF.type, LADERR.Disposition))

    # c1 is not enabled
    g.add((disposition2, LADERR.state, LADERR.enabled))

    g.add((disposition1, LADERR.disables, disposition2))

    InferenceRules.execute_rule_disabled_state(g)

    # disposition2 should still be enabled
    assert (disposition2, LADERR.state, LADERR.enabled) in g
    assert (disposition2, LADERR.state, LADERR.disabled) not in g


def test_execute_rule_disabled_state_c2_not_enabled():
    g = Graph()

    disposition1 = URIRef("https://example.org/disposition1")
    disposition2 = URIRef("https://example.org/disposition2")

    g.add((disposition1, RDF.type, LADERR.Disposition))
    g.add((disposition2, RDF.type, LADERR.Disposition))

    g.add((disposition1, LADERR.state, LADERR.enabled))
    g.add((disposition2, LADERR.state, LADERR.disabled))  # c2 is already disabled

    g.add((disposition1, LADERR.disables, disposition2))

    InferenceRules.execute_rule_disabled_state(g)

    # disposition2 should remain disabled (no transition needed)
    assert (disposition2, LADERR.state, LADERR.disabled) in g
    assert (disposition2, LADERR.state, LADERR.enabled) not in g


def test_execute_rule_disabled_state_no_disables_relation():
    g = Graph()

    disposition1 = URIRef("https://example.org/disposition1")
    disposition2 = URIRef("https://example.org/disposition2")

    g.add((disposition1, RDF.type, LADERR.Disposition))
    g.add((disposition2, RDF.type, LADERR.Disposition))

    g.add((disposition1, LADERR.state, LADERR.enabled))
    g.add((disposition2, LADERR.state, LADERR.enabled))

    # No disables relation between them
    InferenceRules.execute_rule_disabled_state(g)

    # Neither disposition should change state
    assert (disposition1, LADERR.state, LADERR.enabled) in g
    assert (disposition2, LADERR.state, LADERR.enabled) in g
    assert (disposition1, LADERR.state, LADERR.disabled) not in g
    assert (disposition2, LADERR.state, LADERR.disabled) not in g
