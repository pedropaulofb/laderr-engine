import pytest
from pyshacl import validate
from rdflib import Graph, Namespace, URIRef, Literal, RDF, XSD

from laderr_engine.laderr_lib.constants import SHACL_FILES_PATH
from tests.utils import find_file_by_partial_name

LADERR = Namespace("https://w3id.org/laderr#")


@pytest.fixture(scope="module")
def shape_graph():
    g = Graph()
    shape = find_file_by_partial_name(SHACL_FILES_PATH, "laderr-shape-laderrspecification")
    g.parse(shape, format="turtle")
    return g


@pytest.fixture
def base_instance():
    g = Graph()
    spec = URIRef("https://example.org/my-spec")
    g.add((spec, RDF.type, LADERR.LaderrSpecification))  # This is MANDATORY!

    g.add((spec, LADERR.title, Literal("My Spec Title", datatype=XSD.string)))
    g.add((spec, LADERR.version, Literal("1.0", datatype=XSD.string)))
    g.add((spec, LADERR.createdBy, Literal("Author Name", datatype=XSD.string)))
    g.add((spec, LADERR.createdOn, Literal("2025-03-07T12:00:00", datatype=XSD.dateTime)))
    g.add((spec, LADERR.baseURI, Literal("https://example.org/laderr", datatype=XSD.anyURI)))
    g.add((spec, LADERR.scenario, LADERR.operational))
    g.add((LADERR.operational, RDF.type, LADERR.ScenarioType))

    construct = URIRef("https://example.org/construct/0")
    g.add((construct, RDF.type, LADERR.LaderrConstruct))
    g.add((spec, LADERR.constructs, construct))
    g.bind("laderr", LADERR)
    return g, spec


@pytest.mark.parametrize("property_uri, value, datatype, should_pass", [
    (LADERR.title, Literal("My Spec Title", datatype=XSD.string), XSD.string, True),
    (LADERR.title, Literal(123), XSD.string, False),
    (LADERR.version, Literal("1.0", datatype=XSD.string), XSD.string, True),
    (LADERR.version, Literal(1.0), XSD.string, False),
    (LADERR.createdBy, Literal("Author Name", datatype=XSD.string), XSD.string, True),
    (LADERR.createdOn, Literal("2025-03-07T12:00:00", datatype=XSD.dateTime), XSD.dateTime, True),
    (LADERR.createdOn, Literal("InvalidDate"), XSD.dateTime, False),
    (LADERR.baseURI, Literal("https://example.org/laderr", datatype=XSD.anyURI), XSD.anyURI, True),
    (LADERR.baseURI, Literal("not_a_uri"), XSD.anyURI, False),
])
def test_datatype_constraints(shape_graph, base_instance, property_uri, value, datatype, should_pass):
    g, spec = base_instance
    g.set((spec, property_uri, value))  # Replace tested property
    conforms, results_graph, results_text = validate(g, shacl_graph=shape_graph, data_graph_format="turtle",
                                                     shacl_graph_format="turtle")
    assert conforms is should_pass


@pytest.mark.parametrize("property_uri, values, should_pass", [
    (LADERR.title, ["One Title"], True),
    (LADERR.title, ["Title 1", "Title 2"], False),
    (LADERR.version, ["1.0"], True),
    (LADERR.version, ["1.0", "2.0"], False),
    (LADERR.createdOn, ["2025-03-07T12:00:00"], True),
    (LADERR.createdOn, ["2025-03-07T12:00:00", "2025-03-08T12:00:00"], False),
])
def test_cardinality_constraints(shape_graph, base_instance, property_uri, values, should_pass):
    g, spec = base_instance

    # Remove existing values to ensure clean test
    g.remove((spec, property_uri, None))

    # Add test values
    for value in values:
        if property_uri == LADERR.createdOn:
            g.add((spec, property_uri, Literal(value, datatype=XSD.dateTime)))
        else:
            g.add((spec, property_uri, Literal(value, datatype=XSD.string)))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass


def test_missing_required_properties(shape_graph, base_instance):
    """ Test that missing mandatory properties cause violations. """
    g, spec = base_instance
    # Add only 1 required property (title), leave others out.
    g.add((spec, LADERR.title, Literal("Minimal Spec")))
    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert not conforms  # Should fail due to missing required properties.


@pytest.mark.parametrize("scenario_value, should_pass", [
    (LADERR.operational, True),
    (LADERR.incident, True),
    (LADERR.resilient, False),  # Not in allowed set
    (LADERR.not_resilient, False),
])
def test_scenario_value_restriction(shape_graph, base_instance, scenario_value, should_pass):
    g, spec = base_instance

    # Clear the existing scenario triple to make sure only the tested one is present
    g.remove((spec, LADERR.scenario, None))

    # Now add the scenario under test
    g.add((spec, LADERR.scenario, scenario_value))
    g.add((scenario_value, RDF.type, LADERR.ScenarioType))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass


def test_scenario_cardinality(shape_graph, base_instance):
    """Test that exactly one scenario is required."""
    g, spec = base_instance
    g.add((spec, LADERR.scenario, LADERR.operational))
    g.add((spec, LADERR.scenario, LADERR.incident))
    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert not conforms  # Multiple scenarios are not allowed.


@pytest.mark.parametrize("construct_count, should_pass", [
    (1, True),
    (0, False)
])
def test_constructs_min_count(shape_graph, base_instance, construct_count, should_pass):
    g, spec = base_instance
    for i in range(construct_count):
        construct = URIRef(f"https://example.org/construct/{i}")
        g.add((construct, RDF.type, LADERR.LaderrConstruct))
        g.add((spec, LADERR.constructs, construct))
    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass


@pytest.mark.parametrize("construct_count, should_pass", [
    (1, True),
    (0, False)
])
def test_constructs_min_count(shape_graph, base_instance, construct_count, should_pass):
    g, spec = base_instance

    # Clear out all existing 'constructs' triples to start fresh
    g.remove((spec, LADERR.constructs, None))

    # Now add the desired number of constructs
    for i in range(construct_count):
        construct = URIRef(f"https://example.org/construct/{i}")
        g.add((construct, RDF.type, LADERR.LaderrConstruct))
        g.add((spec, LADERR.constructs, construct))

    # Validate
    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")

    assert conforms is should_pass
