import pytest
from pyshacl import validate
from rdflib import Graph, Namespace, URIRef, RDF

from laderr_engine.laderr_lib.constants import SHACL_FILES_PATH
from tests.utils import find_file_by_partial_name

# Namespaces
LADERR = Namespace("https://w3id.org/laderr#")


@pytest.fixture(scope="module")
def shape_graph():
    g = Graph()
    shape = find_file_by_partial_name(SHACL_FILES_PATH, "laderr-shape-control")
    g.parse(shape, format="turtle")
    return g


@pytest.fixture
def base_control():
    """Create a base Control with one Threat and one Asset."""
    g = Graph()

    control = URIRef("https://example.org/control/0")
    threat = URIRef("https://example.org/threat/0")
    asset = URIRef("https://example.org/asset/0")

    g.add((control, RDF.type, LADERR.Control))
    g.add((threat, RDF.type, LADERR.Threat))
    g.add((asset, RDF.type, LADERR.Asset))

    g.add((control, LADERR.inhibits, threat))
    g.add((control, LADERR.protects, asset))

    g.bind("laderr", LADERR)
    return g, control, threat, asset


@pytest.mark.parametrize("inhibits_count, protects_count, should_pass", [
    (0, 0, False),  # Neither `inhibits` nor `protects` is present -> should fail
    (1, 0, True),   # Has `inhibits`, missing `protects` -> should pass
    (0, 1, True),   # Has `protects`, missing `inhibits` -> should pass
    (1, 1, True),   # Has both -> should pass
    (3, 0, True),  # Multiple threats and no assets -> should pass
    (0, 3, True),  # Multiple assets and no threats -> should pass
    (3, 3, True),   # Multiple threats and assets -> should pass
])
def test_control_relationships(shape_graph, base_control, inhibits_count, protects_count, should_pass):
    g, control, _, _ = base_control

    # Remove all existing relationships to reset
    g.remove((control, LADERR.inhibits, None))
    g.remove((control, LADERR.protects, None))

    # Add exactly `inhibits_count` threats
    for i in range(inhibits_count):
        threat = URIRef(f"https://example.org/threat/{i}")
        g.add((threat, RDF.type, LADERR.Threat))
        g.add((control, LADERR.inhibits, threat))

    # Add exactly `protects_count` assets
    for i in range(protects_count):
        asset = URIRef(f"https://example.org/asset/{i}")
        g.add((asset, RDF.type, LADERR.Asset))
        g.add((control, LADERR.protects, asset))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass
