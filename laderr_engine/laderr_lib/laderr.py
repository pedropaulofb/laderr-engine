from rdflib import Graph

from laderr_engine.laderr_lib.handlers.graph import GraphHandler
from laderr_engine.laderr_lib.handlers.specification import SpecificationHandler
from laderr_engine.laderr_lib.handlers.validation import ValidationHandler


class Laderr:
    """
    A utility class for providing methods to operate on RDF data and SHACL validation.
    This class is not meant to be instantiated.
    """

    def __init__(self):
        raise TypeError(f"{self.__class__.__name__} is a utility class and cannot be instantiated.")

    @classmethod
    def load_specification_to_graph(cls, laderr_file_path: str):


    @classmethod
    def validate_specification(cls, laderr_file_path: str):
        return ValidationHandler.validate_specification(laderr_file_path)

    @classmethod
    def validate_graph(cls, laderr_file_path: str):
        return ValidationHandler.validate_graph(laderr_file_path)

    @classmethod
    def save_graph_to_specification(cls, graph: Graph, output_path: str):
        return GraphHandler.save_graph(graph, output_path)
