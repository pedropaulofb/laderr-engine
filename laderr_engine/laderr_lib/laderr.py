from loguru import logger
from rdflib import Graph

from laderr_engine.laderr_lib.handlers.graph import GraphHandler
from laderr_engine.laderr_lib.handlers.validation import ValidationHandler

VERBOSE = True

class Laderr:
    """
    A utility class for providing methods to operate on RDF data and SHACL validation.
    This class is not meant to be instantiated.
    """

    def __init__(self):
        raise TypeError(f"{self.__class__.__name__} is a utility class and cannot be instantiated.")

    @staticmethod
    def load_spec_to_laderr_graph(laderr_file_path: str) -> Graph:
        """
        Loads a LaDeRR specification file and converts it into a unified RDF graph.

        This method reads a specification file, processes metadata and data, and returns an RDFLib graph
        containing all structured information.

        :param laderr_file_path: Path to the LaDeRR specification file.
        :type laderr_file_path: str
        :return: A single RDF graph containing the parsed specification.
        :rtype: Graph
        """
        laderr_graph = GraphHandler.create_laderr_graph(laderr_file_path)
        VERBOSE and logger.success(f"LaDeRR graph successfully created for: {laderr_file_path}")
        return laderr_graph

    @classmethod
    def validate_spec(cls, laderr_file_path: str):
        return ValidationHandler.validate_specification(laderr_file_path)

    # @classmethod
    # def validate_laderr_graph(cls, laderr_file_path: str):
        # return ValidationHandler.validate_graph(laderr_file_path)

    @classmethod
    def save_laderr_graph(cls, graph: Graph, output_path: str)->None:
        GraphHandler.save_graph(graph, output_path)
        VERBOSE and logger.success(f"LaDeRR graph successfully saved in: {output_path}")

    # @classmethod
    # def save_laderr_graph_to_spec(cls, graph: Graph, output_path: str):
    #     return GraphHandler.save_graph(graph, output_path)
