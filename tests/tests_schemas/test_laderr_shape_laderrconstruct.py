import pytest
from pyshacl import validate
from rdflib import Graph, Namespace, URIRef, Literal, RDF, XSD, RDFS

from laderr_engine.laderr_lib.globals import SHACL_FILES_PATH
from tests.utils import find_file_by_partial_name

LADERR = Namespace("https://w3id.org/laderr#")
OWL = Namespace("http://www.w3.org/2002/07/owl#")


@pytest.fixture(scope="module")
def shape_graph():
    g = Graph()
    shape = find_file_by_partial_name(SHACL_FILES_PATH, "laderr-shape-laderrconstruct")
    g.parse(shape, format="turtle")
    return g


@pytest.fixture
def base_construct():
    g = Graph()
    construct = URIRef("https://example.org/construct/0")
    g.add((construct, RDF.type, LADERR.ScenarioComponent))

    # Adding ignored properties (necessary to prevent errors due to 'sh:closed true')
    g.add((construct, OWL.sameAs, construct))  # Optional ignored property
    g.add((construct, RDFS.label, Literal("Initial Label", datatype=XSD.string)))  # Required
    g.bind("laderr", LADERR)
    g.bind("rdfs", RDFS)
    g.bind("owl", OWL)

    return g, construct


# 1️⃣ - Datatype Tests (description and label)
@pytest.mark.parametrize("property_uri, value, datatype, should_pass", [
    (LADERR.description, Literal("This is a description", datatype=XSD.string), XSD.string, True),
    (LADERR.description, Literal(123), XSD.string, False),  # Invalid datatype

    (RDFS.label, Literal("Valid Label", datatype=XSD.string), XSD.string, True),
    (RDFS.label, Literal(123), XSD.string, False),  # Invalid datatype
])
def test_construct_property_datatypes(shape_graph, base_construct, property_uri, value, datatype, should_pass):
    g, construct = base_construct

    # Remove existing value (if any) for this property to ensure a clean test
    g.remove((construct, property_uri, None))

    # Set the test value
    g.add((construct, property_uri, value))

    conforms, _, results_text = validate(g, shacl_graph=shape_graph, data_graph_format="turtle",
                                         shacl_graph_format="turtle")
    assert conforms is should_pass


# 2️⃣ - Cardinality Tests (description and label)
@pytest.mark.parametrize("property_uri, values, should_pass", [
    (LADERR.description, ["A description"], True),  # Single description (OK)
    (LADERR.description, ["Desc 1", "Desc 2"], False),  # Multiple descriptions (Violation)

    (RDFS.label, ["Label 1"], True),  # Exactly one label (OK)
    (RDFS.label, ["Label 1", "Label 2"], False),  # Multiple labels (Violation)
    (RDFS.label, [], False),  # No label at all (Violation)
])
def test_construct_property_cardinality(shape_graph, base_construct, property_uri, values, should_pass):
    g, construct = base_construct

    # Remove existing values to ensure clean test
    g.remove((construct, property_uri, None))

    # Add test values
    for value in values:
        g.add((construct, property_uri, Literal(value, datatype=XSD.string)))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass


# 3️⃣ - Closed Shape Test (disallow unexpected properties)
@pytest.mark.parametrize("extra_property, should_pass", [
    (LADERR.unexpectedProperty, False),  # Adding unknown property should fail due to sh:closed true
    (OWL.sameAs, True),  # Allowed because it's in ignoredProperties
])
def test_construct_closed_shape(shape_graph, base_construct, extra_property, should_pass):
    g, construct = base_construct

    if extra_property != OWL.sameAs:
        g.add((construct, extra_property, Literal("Unexpected Value")))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass
