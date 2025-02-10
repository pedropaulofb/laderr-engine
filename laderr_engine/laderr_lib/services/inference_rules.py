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
        If an object with a capability disables a vulnerability of another object, it protects it.
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
        If a capability disables another capability, it inhibits the object possessing the latter capability.
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
        If a capability exploits a vulnerability of another object, it threatens it.
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
    def execute_rule_resilience(laderr_graph: Graph):
        new_triples = set()

        for o1, c1 in laderr_graph.subject_objects(LADERR_NS.capabilities):
            for o2, c2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                for o3, c3 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                    for v1, c1_exposes in laderr_graph.subject_objects(LADERR_NS.exposes):
                        if (
                                (o1, LADERR_NS.capabilities, c1) in laderr_graph and
                                (o1, LADERR_NS.vulnerabilities, v1) in laderr_graph and
                                (o2, LADERR_NS.capabilities, c2) in laderr_graph and
                                (o3, LADERR_NS.capabilities, c3) in laderr_graph and
                                (c2, LADERR_NS.disables, v1) in laderr_graph and
                                (c3, LADERR_NS.exploits, v1) in laderr_graph
                        ):
                            # Check if a Resilience individual already exists
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
                                # Generate a random Resilience ID
                                resilience_id = "R" + ''.join(
                                    random.choices(string.ascii_uppercase + string.digits, k=2))
                                base_uri = GraphHandler.get_base_prefix(laderr_graph)
                                resilience_uri = URIRef(f"{base_uri}{resilience_id}")

                                # Add the new Resilience individual and relationships
                                new_triples.add((resilience_uri, RDF.type, LADERR_NS.Resilience))
                                new_triples.add((o1, LADERR_NS.resiliences, resilience_uri))
                                new_triples.add((resilience_uri, LADERR_NS.preserves, c1))
                                new_triples.add((resilience_uri, LADERR_NS.preservesAgainst, c3))
                                new_triples.add((resilience_uri, LADERR_NS.preservesDespite, v1))
                                new_triples.add((c2, LADERR_NS.sustains, resilience_uri))

        for triple in new_triples:
            # Ensure the base namespace is correctly bound
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} {triple[1]} {triple[2]}")
