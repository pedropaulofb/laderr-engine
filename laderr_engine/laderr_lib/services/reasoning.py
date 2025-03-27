import hashlib

from loguru import logger
from owlrl import DeductiveClosure, RDFS_Semantics
from rdflib import Graph

from laderr_engine.laderr_lib.constants import LADERR_NS
from laderr_engine.laderr_lib.services.graph import GraphHandler
from laderr_engine.laderr_lib.services.inference_rules import InferenceRules


class ReasoningHandler:
    """
    Handles reasoning and inference over RDF graphs.

    This class applies predefined rules iteratively until no more new inferences can be made.
    """

    @staticmethod
    def _calculate_hash(graph: Graph) -> str:
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

        base_prefix = GraphHandler.get_base_prefix(graph)
        graph = GraphHandler.create_combined_graph(graph)

        # Rebind prefixes after merging
        graph.bind("", base_prefix)  # Bind the `laderr:` namespace
        graph.bind("laderr", LADERR_NS)  # Bind the `laderr:` namespace

        iteration = 0
        while True:
            iteration += 1
            logger.success(f"Starting reasoning iteration {iteration}. Current number of triples is {len(graph)}.")
            hash_before = ReasoningHandler._calculate_hash(graph)

            DeductiveClosure(RDFS_Semantics).expand(graph)
            InferenceRules.execute_rule_disabled_state(graph)
            InferenceRules.execute_rule_protects(graph)
            InferenceRules.execute_rule_threatens(graph)
            InferenceRules.execute_rule_inhibits(graph)
            InferenceRules.execute_rule_resilience(graph)
            InferenceRules.execute_rule_resilience_scenario(graph)
            InferenceRules.execute_rule_positive_damage(graph)
            InferenceRules.execute_rule_negative_damage(graph)
            InferenceRules.execute_rule_scenario_status(graph)
            InferenceRules.execute_rule_damage_from_scenario(graph)

            hash_after = ReasoningHandler._calculate_hash(graph)

            if hash_before == hash_after:
                break

        logger.success(f"Reasoning concluded after {iteration} iteration(s). Final number of triples is {len(graph)}.")
        return GraphHandler.clean_graph(graph, base_prefix)
