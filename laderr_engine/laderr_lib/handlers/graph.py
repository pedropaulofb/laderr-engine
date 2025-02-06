from rdflib import Graph
from rdflib.exceptions import ParserError

from laderr_engine.test_files import RDF_FILE_PATH


class GraphHandler:
    @classmethod
    def _load_schema(cls) -> Graph:
        """
        Safely reads an RDF file into an RDFLib graph.

        :return: An RDFLib graph containing the data from the file.
        :rtype: Graph
        :raises FileNotFoundError: If the specified file does not exist.
        :raises ValueError: If the file is not a valid RDF file or cannot be parsed.
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
    def _save_graph(graph: Graph, file_path: str, format: str = "turtle") -> None:
        """
        Saves an RDF graph to a file in the specified format.

        :param graph: The RDF graph to save.
        :type graph: Graph
        :param file_path: The path where the graph will be saved.
        :type file_path: str
        :param format: The serialization format (e.g., "turtle", "xml", "nt", "json-ld").
                       Default is "turtle".
        :type format: str
        :raises ValueError: If the format is not supported.
        :raises OSError: If the file cannot be written.
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
