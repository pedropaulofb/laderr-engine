import pytest
from rdflib import Graph, Namespace, URIRef, RDF, Literal, RDFS
from laderr_engine.laderr_lib.services.inference_rules import InferenceRules  # Adjust if needed

LADERR = Namespace("https://w3id.org/laderr#")

@pytest.fixture
def laderr_graph_with_valid_resilience_case():
    g = Graph()

    # Entities
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")
    entity3 = URIRef("https://example.org/entity3")

    # Capabilities
    capability1 = URIRef("https://example.org/capability1")  # belongs to entity1
    capability2 = URIRef("https://example.org/capability2")  # belongs to entity2 (disabling capability)
    capability3 = URIRef("https://example.org/capability3")  # belongs to entity3 (exploiting capability)

    # Vulnerability
    vulnerability1 = URIRef("https://example.org/vulnerability1")

    # Link capabilities to entities
    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity2, LADERR.capabilities, capability2))
    g.add((entity3, LADERR.capabilities, capability3))

    # Link vulnerability to entity1
    g.add((entity1, LADERR.vulnerabilities, vulnerability1))

    # Capability2 disables vulnerability1
    g.add((capability2, LADERR.disables, vulnerability1))

    # Vulnerability exposes capability1 (this is the corrected relation)
    g.add((vulnerability1, LADERR.exposes, capability1))

    # Capability3 exploits vulnerability1
    g.add((capability3, LADERR.exploits, vulnerability1))

    # Capability2 is enabled
    g.add((capability2, LADERR.state, LADERR.enabled))

    return g, entity1, capability1, capability2, capability3, vulnerability1


def test_resilience_inferred(laderr_graph_with_valid_resilience_case):
    g, entity1, capability1, capability2, capability3, vulnerability1 = laderr_graph_with_valid_resilience_case

    InferenceRules.execute_rule_resilience(g)

    # Check that exactly one Resilience has been created
    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(resilience_instances) == 1, "Expected exactly one inferred Resilience instance."

    resilience = resilience_instances[0]

    # Check the label exists and is non-empty (actual label value can't be predicted because it's random)
    label = g.value(resilience, RDFS.label)
    assert label is not None and len(str(label)) > 0, "Inferred Resilience should have a non-empty label."

    resilience = resilience_instances[0]

    # Check all expected relationships were added
    assert (entity1, LADERR.resiliences, resilience) in g
    assert (resilience, LADERR.preserves, capability1) in g
    assert (resilience, LADERR.preservesAgainst, capability3) in g
    assert (resilience, LADERR.preservesDespite, vulnerability1) in g
    assert (capability2, LADERR.sustains, resilience) in g
    assert (resilience, LADERR.state, LADERR.enabled) in g


def test_resilience_not_inferred_without_enabled_state():
    g = Graph()

    # Similar to previous, but capability2 (the sustainer) is not enabled
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")
    entity3 = URIRef("https://example.org/entity3")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")
    capability3 = URIRef("https://example.org/capability3")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity2, LADERR.capabilities, capability2))
    g.add((entity3, LADERR.capabilities, capability3))

    g.add((entity1, LADERR.vulnerabilities, vulnerability1))

    g.add((capability2, LADERR.disables, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))
    g.add((capability3, LADERR.exploits, vulnerability1))

    # No enabled state for capability2 (critical condition missing)
    InferenceRules.execute_rule_resilience(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(resilience_instances) == 0, "No Resilience should be inferred if the disabling capability is not enabled."


def test_resilience_not_inferred_with_same_entity_capabilities():
    g = Graph()

    # All capabilities belong to the same entity (should prevent resilience inference)
    entity1 = URIRef("https://example.org/entity1")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")
    capability3 = URIRef("https://example.org/capability3")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity1, LADERR.capabilities, capability2))
    g.add((entity1, LADERR.capabilities, capability3))

    g.add((entity1, LADERR.vulnerabilities, vulnerability1))

    g.add((capability2, LADERR.disables, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))
    g.add((capability3, LADERR.exploits, vulnerability1))

    g.add((capability2, LADERR.state, LADERR.enabled))

    InferenceRules.execute_rule_resilience(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(resilience_instances) == 0, "No Resilience should be inferred if all capabilities belong to the same entity."


def test_resilience_not_inferred_without_exploits_relationship():
    g = Graph()

    # Missing the "exploits" link between capability3 and vulnerability1
    entity1 = URIRef("https://example.org/entity1")
    entity2 = URIRef("https://example.org/entity2")

    capability1 = URIRef("https://example.org/capability1")
    capability2 = URIRef("https://example.org/capability2")

    vulnerability1 = URIRef("https://example.org/vulnerability1")

    g.add((entity1, LADERR.capabilities, capability1))
    g.add((entity2, LADERR.capabilities, capability2))

    g.add((entity1, LADERR.vulnerabilities, vulnerability1))

    g.add((capability2, LADERR.disables, vulnerability1))
    g.add((vulnerability1, LADERR.exposes, capability1))

    g.add((capability2, LADERR.state, LADERR.enabled))

    InferenceRules.execute_rule_resilience(g)

    resilience_instances = list(g.subjects(RDF.type, LADERR.Resilience))
    assert len(resilience_instances) == 0, "No Resilience should be inferred if no capability exploits the vulnerability."

