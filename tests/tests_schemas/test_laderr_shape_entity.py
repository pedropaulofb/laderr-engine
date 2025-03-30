import pytest
from pyshacl import validate
from rdflib import Graph, Namespace, URIRef, RDF

from laderr_engine.laderr_lib.globals import SHACL_FILES_PATH
from tests.utils import find_file_by_partial_name

# Namespaces
LADERR = Namespace("https://w3id.org/laderr#")


@pytest.fixture(scope="module")
def shape_graph():
    g = Graph()
    shape = find_file_by_partial_name(SHACL_FILES_PATH, "laderr-shape-entity")
    g.parse(shape, format="turtle")
    return g


@pytest.fixture
def base_entity():
    """Create a minimal valid Entity linked to one Capability."""
    g = Graph()

    entity = URIRef("https://example.org/entity/0")
    capability = URIRef("https://example.org/capability/0")

    g.add((entity, RDF.type, LADERR.Entity))
    g.add((capability, RDF.type, LADERR.Capability))
    g.add((entity, LADERR.capabilities, capability))

    g.bind("laderr", LADERR)
    return g, entity, capability


@pytest.mark.parametrize("capability_count, should_pass", [
    (0, False),  # No capability linked - Warning (SHACL may not fail, but we want to enforce it fails in testing)
    (1, True),  # One capability - Valid
    (3, True),  # Multiple capabilities - Still valid
])
def test_entity_capabilities(shape_graph, base_entity, capability_count, should_pass):
    g, entity, _ = base_entity

    # Remove all existing capabilities
    g.remove((entity, LADERR.capabilities, None))

    # Add exactly `capability_count` capabilities
    for i in range(capability_count):
        capability = URIRef(f"https://example.org/capability/{i}")
        g.add((capability, RDF.type, LADERR.Capability))
        g.add((entity, LADERR.capabilities, capability))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass
