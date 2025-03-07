import pytest
from icecream import ic
from rdflib import Graph, Namespace, URIRef, RDF
from pyshacl import validate

from laderr_engine.laderr_lib.constants import SHACL_FILES_PATH
from tests.aux_functions import find_file_by_partial_name

# Namespaces
LADERR = Namespace("https://w3id.org/laderr#")

@pytest.fixture(scope="module")
def shape_graph():
    g = Graph()
    shape = find_file_by_partial_name(SHACL_FILES_PATH, "laderr-shape-threat")
    g.parse(shape, format="turtle")
    return g

@pytest.fixture
def base_threat():
    g = Graph()

    threat = URIRef("https://example.org/threat/0")
    asset = URIRef("https://example.org/asset/0")

    g.add((threat, RDF.type, LADERR.Threat))
    g.add((asset, RDF.type, LADERR.Asset))

    g.add((threat, LADERR.threatens, asset))

    g.bind("laderr", LADERR)
    return g, threat, asset

@pytest.mark.parametrize("remove_threatens, should_pass", [
    (False, True),  # Valid case - threat has 'threatens' relationship
    (True, False),  # Invalid case - missing 'threatens' relationship
])
def test_threat_threatens_constraint(shape_graph, base_threat, remove_threatens, should_pass):
    g, threat, asset = base_threat

    if remove_threatens:
        g.remove((threat, LADERR.threatens, asset))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass
