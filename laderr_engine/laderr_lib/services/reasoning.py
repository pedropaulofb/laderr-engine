import hashlib

from icecream import ic
from owlrl import DeductiveClosure, RDFS_Semantics
from rdflib import Graph

from laderr_engine.laderr_lib.constants import LADERR_NS
from laderr_engine.laderr_lib.services.graph import GraphHandler
from laderr_engine.laderr_lib.services.inference_rules import InferenceRules
from laderr_engine.laderr_lib.services.validation import ValidationHandler


class ReasoningHandler:
    """
    Handles reasoning and inference over RDF graphs.

    This class applies predefined rules iteratively until no more new inferences can be made.
    """

    @staticmethod
    def calculate_hash(graph: Graph) -> str:
        """
        Computes a hash of the RDF graph's triples.

        This helps detect changes in the graph after applying inference rules.

        :param graph: The RDF graph to hash.
        :type graph: Graph
        :return: A hash string representing the graph's state.
        :rtype: str
        """
        graph_string = graph.serialize(format="nt")  # Convert graph to normalized format
        return hashlib.sha256(graph_string.encode()).hexdigest()

    @staticmethod
    def execute(graph: Graph) -> Graph:
        """
        Applies inference rules iteratively until no new triples are inferred.

        The method runs inference, checks for graph changes, and repeats until stabilization.

        :param graph: The RDF graph to process.
        :type graph: Graph
        :return: The enriched RDF graph after reasoning.
        :rtype: Graph
        """
        hash_before = 1
        hash_after = 2

        base_prefix = GraphHandler.get_base_prefix(graph)
        graph = GraphHandler.create_combined_graph(graph)

        # Rebind prefixes after merging
        graph.bind("", base_prefix)  # Bind the `laderr:` namespace
        graph.bind("laderr", LADERR_NS)  # Bind the `laderr:` namespace

        while hash_before != hash_after:
            hash_before = ReasoningHandler.calculate_hash(graph)

            DeductiveClosure(RDFS_Semantics).expand(graph)
            InferenceRules.execute_rule_disabled_state(graph)
            InferenceRules.execute_rule_protects(graph)
            InferenceRules.execute_rule_inhibits(graph)
            InferenceRules.execute_rule_threatens(graph)
            InferenceRules.execute_rule_resilience(graph)
            InferenceRules.execute_rule_succeeded_to_damage(graph)
            InferenceRules.execute_rule_failed_to_damage(graph)
            InferenceRules.execute_rule_scenario_resilient(graph)

            hash_after = ReasoningHandler.calculate_hash(graph)

        return GraphHandler.clean_graph(graph, base_prefix)
