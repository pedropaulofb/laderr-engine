import pytest
from icecream import ic
from owlrl import DeductiveClosure, RDFS_Semantics
from rdflib import Graph, Namespace, URIRef, RDF

from laderr_engine.laderr_lib.services.graph import GraphHandler
from tests.aux import EXAMPLE

LADERR = Namespace("https://w3id.org/laderr#")

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed


@pytest.fixture
def laderr_graph_with_disabling_relation():
    """
    Creates a test RDF graph where disposition1 disables disposition2.

    :return: RDF graph, disposition1 URIRef, disposition2 URIRef
    :rtype: Tuple[Graph, URIRef, URIRef]
    """
    g = Graph()

    disposition1 = EXAMPLE.disposition1
    disposition2 = EXAMPLE.disposition2

    g.add((disposition1, RDF.type, LADERR.Disposition))
    g.add((disposition2, RDF.type, LADERR.Disposition))

    g.add((disposition1, LADERR.state, LADERR.disabled))  # d1 starts as disabled
    g.add((disposition2, LADERR.state, LADERR.enabled))  # d2 starts as enabled

    g.add((disposition1, LADERR.disables, disposition2))

    return g, disposition1, disposition2


@pytest.mark.parametrize("type1, type2", [
    (LADERR.Disposition, LADERR.Disposition),
    (LADERR.Disposition, LADERR.Capability),
    (LADERR.Disposition, LADERR.Vulnerability),
    (LADERR.Capability, LADERR.Capability),
    (LADERR.Capability, LADERR.Vulnerability),
])
@pytest.mark.parametrize("state_d1, state_d2", [
    (LADERR.enabled, LADERR.enabled),
    (LADERR.disabled, LADERR.enabled),
    (LADERR.enabled, LADERR.disabled),
    (LADERR.disabled, LADERR.disabled),
])
def test_execute_rule_disabled_state_various_states(type1: URIRef, type2: URIRef, state_d1: URIRef, state_d2: URIRef):
    """
    Tests the rule under different initial states of dispositions and different types.

    :param type1: Type of disposition1.
    :param type2: Type of disposition2.
    :param state_d1: Initial state of disposition1.
    :param state_d2: Initial state of disposition2.
    """
    g = GraphHandler.load_laderr_schema()

    disposition1 = EXAMPLE.disposition1
    disposition2 = EXAMPLE.disposition2

    g.add((disposition1, RDF.type, type1))
    g.add((disposition2, RDF.type, type2))
    g.add((disposition1, LADERR.state, state_d1))
    g.add((disposition2, LADERR.state, state_d2))
    g.add((disposition1, LADERR.disables, disposition2))

    DeductiveClosure(RDFS_Semantics).expand(g)
    InferenceRules.execute_rule_disabled_state(g)

    # Ensure the expected state of d1 is present
    assert (disposition1, LADERR.state, LADERR.enabled) in g, \
        f"Disposition1 should be in state LADERR.enabled, but it is not."

    # Ensure the incorrect state of d1 is NOT in the graph
    assert not (disposition1, LADERR.state, LADERR.disabled) in g, \
        f"Incorrect state of disposition1 ({state_d1}) should not be in the graph."

    # Ensure the expected state of d2 is present
    assert (disposition2, LADERR.state, LADERR.disabled) in g, \
        f"Disposition2 should be in state LADERR.disabled, but it is not."

    # Ensure the incorrect state of d2 is NOT in the graph
    assert not (disposition2, LADERR.state, LADERR.enabled) in g, \
        f"Incorrect state of disposition1 ({state_d2}) should not be in the graph."

def test_execute_rule_with_missing_states():
    """
    Ensures the rule properly infers states even if they were missing.
    """
    g = Graph()
    disposition1 = EXAMPLE.disposition1
    disposition2 = EXAMPLE.disposition2

    g.add((disposition1, RDF.type, LADERR.Disposition))
    g.add((disposition2, RDF.type, LADERR.Disposition))
    g.add((disposition1, LADERR.disables, disposition2))

    # No initial states

    InferenceRules.execute_rule_disabled_state(g)

    assert (disposition1, LADERR.state, LADERR.enabled) in g, \
        "Disposition1 should be inferred as enabled."
    assert (disposition2, LADERR.state, LADERR.disabled) in g, \
        "Disposition2 should be inferred as disabled."

@pytest.fixture
def empty_laderr_graph():
    """
    Creates an empty RDF graph to test behavior when no dispositions exist.

    :return: RDF graph
    :rtype: Graph
    """
    return Graph()

def test_execute_rule_disabled_state_no_dispositions(empty_laderr_graph):
    """
    Ensures that execute_rule_disabled_state does nothing if no Dispositions exist in the graph.
    """
    initial_triples = set(empty_laderr_graph)  # Capture initial state of the graph

    InferenceRules.execute_rule_disabled_state(empty_laderr_graph)

    assert set(empty_laderr_graph) == initial_triples, \
        "Graph should remain unchanged when no dispositions exist."