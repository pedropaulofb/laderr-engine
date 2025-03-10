import pytest
from icecream import ic
from rdflib import Graph, Namespace, URIRef, RDF
from pyshacl import validate

from laderr_engine.laderr_lib.constants import SHACL_FILES_PATH
from tests.aux import find_file_by_partial_name

# Namespaces
LADERR = Namespace("https://w3id.org/laderr#")

@pytest.fixture(scope="module")
def shape_graph():
    g = Graph()
    shape = find_file_by_partial_name(SHACL_FILES_PATH, "laderr-shape-resilience")
    g.parse(shape, format="turtle")
    return g

@pytest.fixture
def base_resilience():
    g = Graph()

    resilience = URIRef("https://example.org/resilience/0")
    asset = URIRef("https://example.org/asset/0")
    capability = URIRef("https://example.org/capability/0")
    threat_capability = URIRef("https://example.org/capability/1")
    vulnerability = URIRef("https://example.org/vulnerability/0")

    g.add((resilience, RDF.type, LADERR.Resilience))
    g.add((asset, RDF.type, LADERR.Asset))
    g.add((capability, RDF.type, LADERR.Capability))
    g.add((threat_capability, RDF.type, LADERR.Capability))
    g.add((vulnerability, RDF.type, LADERR.Vulnerability))

    g.add((asset, LADERR.resiliences, resilience))
    g.add((resilience, LADERR.preserves, capability))
    g.add((resilience, LADERR.preservesAgainst, threat_capability))
    g.add((resilience, LADERR.preservesDespite, vulnerability))
    g.add((capability, LADERR.sustains, resilience))

    g.bind("laderr", LADERR)
    return g, resilience, asset, capability, threat_capability, vulnerability

@pytest.mark.parametrize("missing_property, should_pass", [
    (None, True),  # Everything present
    ("asset", False),  # Missing link to asset
    ("preserves", False),  # Missing preserves link
    ("preservesAgainst", False),  # Missing preservesAgainst link
    ("preservesDespite", False),  # Missing preservesDespite link
    ("sustains", False),  # Missing sustain link (inverse)
])
def test_resilience_constraints(shape_graph, base_resilience, missing_property, should_pass):
    g, resilience, asset, capability, threat_capability, vulnerability = base_resilience

    if missing_property == "asset":
        g.remove((asset, LADERR.resiliences, resilience))

    if missing_property == "preserves":
        g.remove((resilience, LADERR.preserves, capability))

    if missing_property == "preservesAgainst":
        g.remove((resilience, LADERR.preservesAgainst, threat_capability))

    if missing_property == "preservesDespite":
        g.remove((resilience, LADERR.preservesDespite, vulnerability))

    if missing_property == "sustains":
        g.remove((capability, LADERR.sustains, resilience))

    conforms, _, _ = validate(g, shacl_graph=shape_graph, data_graph_format="turtle", shacl_graph_format="turtle")
    assert conforms is should_pass
