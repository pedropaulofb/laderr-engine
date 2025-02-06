"""
Module for handling RDF graph operations in the LaDeRR framework.

This module provides functionalities for loading RDF schemas and saving RDF graphs in various formats.
"""
import os

from rdflib import Graph
from rdflib.exceptions import ParserError

from laderr_engine.test_files import RDF_FILE_PATH


class GraphHandler:
    """
    Handles operations related to RDF graph loading and saving.

    This class provides methods to:
    - Load RDF schemas from a file into an RDFLib graph.
    - Serialize and save RDF graphs to a file in a specified format.
    """

    @classmethod
    def load_schema(cls) -> Graph:
        """
        Loads an RDF schema file into an RDFLib graph.

        This method reads an RDF file and parses its contents into an RDFLib graph, allowing further processing and
        validation of RDF data structures.

        :return: An RDFLib graph containing the parsed RDF data.
        :rtype: Graph
        :raises FileNotFoundError: If the specified RDF file does not exist.
        :raises ValueError: If the RDF file is malformed or cannot be parsed.
        """
        # Initialize the graph
        graph = Graph()

        try:
            # Parse the file into the graph
            graph.parse(RDF_FILE_PATH)
        except (ParserError, ValueError) as e:
            raise ValueError(f"Failed to parse the RDF file '{RDF_FILE_PATH}'. Ensure it is a valid RDF file.") from e

        return graph

    @staticmethod
    def save_graph(graph: Graph, file_path: str, format: str = "turtle") -> None:
        """
        Serializes and saves an RDF graph to a file.

        This method takes an RDF graph and serializes it into a specified format before writing it to a file.
        The function ensures that the target directory exists before attempting to write the file.

        :param graph: The RDF graph to be serialized and saved.
        :type graph: Graph
        :param file_path: Path where the serialized RDF graph will be stored.
        :type file_path: str
        :param format: The serialization format (e.g., "turtle", "xml", "nt", "json-ld"). Default is "turtle".
        :type format: str
        :raises ValueError: If the specified serialization format is not supported.
        :raises OSError: If the file cannot be written due to permission issues or invalid path.
        """
        try:
            # Ensure the output directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Serialize and save the graph
            graph.serialize(destination=file_path, format=format)
            print(f"Graph saved successfully to '{file_path}' in format '{format}'.")
        except ValueError as e:
            raise ValueError(f"Serialization format '{format}' is not supported.") from e
        except OSError as e:
            raise OSError(f"Could not write to file '{file_path}': {e}") from e
