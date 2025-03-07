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
    shape = find_file_by_partial_name(SHACL_FILES_PATH, "laderr-shape-capability")
    g.parse(shape, format="turtle")
    return g

@pytest.fixture
def base_capability():
    """Create a base instance of Capability with a linked Entity."""
    g = Graph()

    capability = URIRef("https://example.org/capability/0")
    entity = URIRef("https://example.org/entity/0")

    g.add((capability, RDF.type, LADERR.Capability))
    g.add((entity, LADERR.capabilities, capability))
    g.add((entity, RDF.type, LADERR.Entity))

    g.bind("laderr", LADERR)
    return g, capability, entity

@pytest.mark.parametrize("entity_count, should_pass", [
    (1, True),  # Exactly one entity is correct
    (0, False), # No entity is incorrect
    (2, False), # More than one entity is incorrect
])
def test_capability_entity_link(shape_graph, base_capability, entity_count, should_pass):
    g, capability, initial_entity = base_capability

    # Remove existing links to start clean
    g.remove((None, LADERR.capabilities, capability))

    # Add the desired number of entities linking to the capability
    for i in range(entity_count):
        entity = URIRef(f"https://example.org/entity/{i}")
        g.add((entity, RDF.type, LADERR.Entity))
        g.add((entity, LADERR.capabilities, capability))

    conforms, _, results_text = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass
