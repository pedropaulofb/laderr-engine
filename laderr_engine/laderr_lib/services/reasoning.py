import hashlib

from icecream import ic
from rdflib import Graph

from laderr_engine.laderr_lib.services.inference_rules import InferenceRules

DEBUG = False


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

        teste = 1

        while hash_before != hash_after:

            hash_before = ReasoningHandler.calculate_hash(graph)
            DEBUG and ic(hash_before)

            InferenceRules.execute_rule_inhibits(graph)
            DEBUG and ic("inhibits", ReasoningHandler.calculate_hash(graph))
            InferenceRules.execute_rule_protects(graph)
            DEBUG and ic("protects", ReasoningHandler.calculate_hash(graph))
            InferenceRules.execute_rule_threatens(graph)
            DEBUG and ic("threatens", ReasoningHandler.calculate_hash(graph))
            InferenceRules.execute_rule_resilience(graph)
            DEBUG and ic("resilience", ReasoningHandler.calculate_hash(graph))

            hash_after = ReasoningHandler.calculate_hash(graph)
            DEBUG and ic(hash_after)

            if teste == 2:
                break
            teste = 2

        return graph
