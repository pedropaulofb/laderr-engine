import random
import string

from loguru import logger
from rdflib import Graph, URIRef, RDF

from laderr_engine.laderr_lib.constants import LADERR_NS
from laderr_engine.laderr_lib.services.graph import GraphHandler

VERBOSE = True


class InferenceRules:
    """
    Implements inference rules for LaDeRR graphs.
    """

    @staticmethod
    def execute_rule_protects(laderr_graph: Graph):
        """
        Applies the 'protects' inference rule: 
        If an entity with a capability disables a vulnerability of another entity, it protects it.
        """
        new_triples = set()

        for o1, d1 in laderr_graph.subject_objects(LADERR_NS.vulnerabilities):
            for o2, d2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                if (d2, LADERR_NS.disables, d1) in laderr_graph:
                    new_triples.add((o2, LADERR_NS.protects, o1))

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:protects {triple[2]}")

    @staticmethod
    def execute_rule_inhibits(laderr_graph: Graph):
        """
        Applies the 'inhibits' inference rule: 
        If a capability disables another capability, it inhibits the entity possessing the latter capability.
        """
        new_triples = set()

        for o1, d1 in laderr_graph.subject_objects(LADERR_NS.capabilities):
            for o2, d2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                if (d2, LADERR_NS.disables, d1) in laderr_graph:
                    new_triples.add((o2, LADERR_NS.inhibits, o1))

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:inhibits {triple[2]}")

    @staticmethod
    def execute_rule_threatens(laderr_graph: Graph):
        """
        Applies the 'threatens' inference rule: 
        If a capability exploits a vulnerability of another entity, it threatens it.
        """
        new_triples = set()

        for o1, d1 in laderr_graph.subject_objects(LADERR_NS.vulnerabilities):
            for o2, d2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                if (d2, LADERR_NS.exploits, d1) in laderr_graph:
                    new_triples.add((o2, LADERR_NS.threatens, o1))

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:threatens {triple[2]}")

    @staticmethod
    def execute_rule_resilience(laderr_graph):
        new_triples = set()

        enabled = LADERR_NS.enabled

        # Iterate over all combinations of entities and capabilities
        for o1, c1 in laderr_graph.subject_objects(LADERR_NS.capabilities):
            for o2, c2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                for o3, c3 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                    for o1_vuln, v1 in laderr_graph.subject_objects(LADERR_NS.vulnerabilities):
                        # Check entities align
                        if o1 != o1_vuln:
                            continue

                        # Check capabilities belong to distinct entities
                        if o1 in {o2, o3}:
                            continue

                        # Capability c2 must have state ENABLED
                        if (c2, LADERR_NS.state, enabled) not in laderr_graph:
                            continue

                        # Check the required property relationships
                        if not (
                            (c2, LADERR_NS.disables, v1) in laderr_graph and
                            (c1, LADERR_NS.exposedBy, v1) in laderr_graph and
                            (c3, LADERR_NS.exploits, v1) in laderr_graph
                        ):
                            continue

                        # Check if Resilience already exists
                        existing_resilience = None
                        for r in laderr_graph.subjects(RDF.type, LADERR_NS.Resilience):
                            if (
                                (o1, LADERR_NS.resiliences, r) in laderr_graph and
                                (r, LADERR_NS.preserves, c1) in laderr_graph and
                                (r, LADERR_NS.preservesAgainst, c3) in laderr_graph and
                                (r, LADERR_NS.preservesDespite, v1) in laderr_graph and
                                (c2, LADERR_NS.sustains, r) in laderr_graph
                            ):
                                existing_resilience = r
                                break

                        if existing_resilience is None:
                            # Create new Resilience individual
                            resilience_id = "R" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=2))
                            base_uri = GraphHandler.get_base_prefix(laderr_graph)
                            resilience_uri = URIRef(f"{base_uri}{resilience_id}")

                            # Add triples for new Resilience
                            new_triples.update({
                                (resilience_uri, RDF.type, LADERR_NS.Resilience),
                                (o1, LADERR_NS.resiliences, resilience_uri),
                                (resilience_uri, LADERR_NS.preserves, c1),
                                (resilience_uri, LADERR_NS.preservesAgainst, c3),
                                (resilience_uri, LADERR_NS.preservesDespite, v1),
                                (c2, LADERR_NS.sustains, resilience_uri),
                                (resilience_uri, LADERR_NS.state, enabled)  # New requirement: resilience must also be ENABLED
                            })

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} {triple[1]} {triple[2]}")
