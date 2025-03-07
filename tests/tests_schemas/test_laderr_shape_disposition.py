import pytest
from icecream import ic
from rdflib import Graph, Namespace, URIRef, Literal, RDF, OWL, RDFS
from pyshacl import validate

from laderr_engine.laderr_lib.constants import SHACL_FILES_PATH
from tests.aux_functions import find_file_by_partial_name

LADERR = Namespace("https://w3id.org/laderr#")

@pytest.fixture(scope="module")
def shape_graph():
    g = Graph()
    shape = find_file_by_partial_name(SHACL_FILES_PATH, "laderr-shape-disposition")
    g.parse(shape, format="turtle")
    return g

@pytest.fixture
def base_disposition():
    g = Graph()
    disposition = URIRef("https://example.org/disposition/0")
    g.add((disposition, RDF.type, LADERR.Disposition))

    # Add a valid default state (to fulfill minCount=1)
    g.add((disposition, LADERR.state, LADERR.enabled))

    # Adding ignored properties to avoid sh:closed violations
    g.add((disposition, OWL.sameAs, disposition))
    g.add((disposition, RDFS.label, Literal("Initial Disposition Label")))
    g.add((disposition, LADERR.description, Literal("Some description")))

    g.bind("laderr", LADERR)

    return g, disposition


# 1️⃣ - Valid and Invalid State Values
@pytest.mark.parametrize("state_value, should_pass", [
    (LADERR.enabled, True),
    (LADERR.disabled, True),
    (LADERR.unknownState, False),  # Invalid state
])
def test_disposition_state_value(shape_graph, base_disposition, state_value, should_pass):
    g, disposition = base_disposition

    # Clear existing 'state' to have a clean test
    g.remove((disposition, LADERR.state, None))

    # Add the test state
    g.add((disposition, LADERR.state, state_value))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass

# 2️⃣ - State Cardinality (Exactly One Required)
@pytest.mark.parametrize("states, should_pass", [
    ([LADERR.enabled], True),
    ([], False),  # Missing state
    ([LADERR.enabled, LADERR.disabled], False),  # Too many states
])
def test_disposition_state_cardinality(shape_graph, base_disposition, states, should_pass):
    g, disposition = base_disposition

    # Clear existing state to have a clean test
    g.remove((disposition, LADERR.state, None))

    # Add test states
    for state in states:
        g.add((disposition, LADERR.state, state))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass

# 3️⃣ - Closed Shape (Detect unexpected properties)
@pytest.mark.parametrize("extra_property, should_pass", [
    (LADERR.unexpectedProperty, False),  # Not allowed by closed shape
    (OWL.sameAs, True),  # Allowed (in ignoredProperties)
    (LADERR.description, True),  # Allowed (in ignoredProperties)
])
def test_disposition_closed_shape(shape_graph, base_disposition, extra_property, should_pass):
    g, disposition = base_disposition

    if extra_property not in {OWL.sameAs, LADERR.description}:
        g.add((disposition, extra_property, Literal("Unexpected Value")))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass
