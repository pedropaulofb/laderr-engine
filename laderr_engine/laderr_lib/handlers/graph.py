"""
Module for handling RDF graph operations in the LaDeRR framework.

This module provides functionalities for loading RDF schemas and saving RDF graphs in various formats.
"""
import os

from rdflib import Graph, RDF, XSD, Literal, RDFS, Namespace
from rdflib.exceptions import ParserError

from laderr_engine.laderr_lib.handlers.specification import SpecificationHandler
from laderr_engine.laderr_lib.utils.constants import LADERR_SCHEMA_PATH


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
            graph.parse(LADERR_SCHEMA_PATH)
        except (ParserError, ValueError) as e:
            raise ValueError(
                f"Failed to parse the RDF file '{LADERR_SCHEMA_PATH}'. Ensure it is a valid RDF file.") from e

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

    @classmethod
    def _convert_data_to_graph(cls, spec_metadata: dict[str, object], spec_data: dict[str, object]) -> Graph:
        """
        Converts the 'data' section of a LaDeRR specification into an RDF graph.

        The function iterates over the specification's data structure, assigning unique URIs to instances while mapping
        their properties to RDF triples. Additionally, it maintains the `composedOf` relationship between the
        `LaderrSpecification` entity and its instances.

        If an instance lacks an explicit `id` property, it is automatically assigned the section's key name.

        :param spec_metadata: Dictionary containing metadata information, including base URI.
        :type spec_metadata: dict[str, object]
        :param spec_data: Dictionary representing the data structure of the specification.
        :type spec_data: dict[str, object]
        :return: An RDFLib graph containing all data instances and their relationships.
        :rtype: Graph
        :raises ValueError: If the data structure does not conform to the expected dictionary format.
        """
        # Initialize an empty graph
        graph = Graph()

        # Get the base URI from spec_metadata_dict and bind namespaces
        base_uri = cls._validate_base_uri(spec_metadata)
        data_ns = Namespace(base_uri)
        laderr_ns = cls.LADER_NS
        graph.bind("", data_ns)  # Bind the `:` namespace
        graph.bind("laderr", laderr_ns)  # Bind the `laderr:` namespace

        # Create or identify the single RiskSpecification instance
        specification_uri = data_ns.LaderrSpecification
        graph.add((specification_uri, RDF.type, laderr_ns.LaderrSpecification))

        # Iterate over the sections in the data
        for class_type, instances in spec_data.items():
            if not isinstance(instances, dict):
                raise ValueError(f"Invalid structure for {class_type}. Expected a dictionary of instances.")

            for key, properties in instances.items():
                if not isinstance(properties, dict):
                    raise ValueError(
                        f"Invalid structure for instance '{key}' in '{class_type}'. Expected a dictionary of properties.")

                # Determine the `id` of the instance (default to section key if not explicitly set)
                instance_id = properties.get("id", key)

                # Create the RDF node for the instance
                instance_uri = data_ns[instance_id]
                graph.add((instance_uri, RDF.type, laderr_ns[class_type]))

                # Add properties to the instance
                for prop, value in properties.items():
                    if prop == "id":
                        continue  # Skip `id`, it's already used for the URI

                    if prop == "label":
                        # Map 'label' to 'rdfs:label'
                        graph.add((instance_uri, RDFS.label, Literal(value)))
                    else:
                        # Map other properties to laderr namespace
                        if isinstance(value, list):
                            for item in value:
                                graph.add((instance_uri, laderr_ns[prop], Literal(item)))
                        else:
                            graph.add((instance_uri, laderr_ns[prop], Literal(value)))

                # Add the composedOf relationship
                graph.add((specification_uri, laderr_ns.composedOf, instance_uri))

        return graph

    @classmethod
    def _convert_metadata_to_graph(cls, metadata: dict[str, object]) -> Graph:
        """
        Converts LaDeRR specification metadata into an RDF graph.

        This method extracts metadata attributes and represents them as RDF triples, ensuring proper data types
        (e.g., `xsd:string`, `xsd:dateTime`). The `baseUri` is used to establish the namespace, and all metadata
        properties are assigned to the `LaderrSpecification` instance.

        :param metadata: Dictionary containing metadata attributes such as title, version, and authorship.
        :type metadata: dict[str, object]
        :return: An RDFLib graph representing the specification metadata.
        :rtype: Graph
        :raises ValueError: If the provided metadata contains invalid formats or unsupported data types.
        """
        # Define expected datatypes for spec_metadata_dict keys
        expected_datatypes = {"title": XSD.string, "description": XSD.string, "version": XSD.string,
                              "createdBy": XSD.string, "createdOn": XSD.dateTime, "modifiedOn": XSD.dateTime,
                              "baseUri": XSD.anyURI, }

        # Validate base URI and bind namespaces
        base_uri = cls._validate_base_uri(metadata)
        data_ns = Namespace(base_uri)
        laderr_ns = cls.LADER_NS

        # Create a new graph
        graph = Graph()
        graph.bind("", data_ns)  # Bind the `:` namespace
        graph.bind("laderr", laderr_ns)  # Bind the `laderr:` namespace

        # Create or identify LaderrSpecification instance
        specification = data_ns.LaderrSpecification
        graph.add((specification, RDF.type, laderr_ns.LaderrSpecification))

        # Add spec_metadata_dict as properties of the specification
        for key, value in metadata.items():
            property_uri = laderr_ns[key]  # Schema properties come from laderr namespace
            datatype = expected_datatypes.get(key, XSD.anyURI)  # Default to xsd:string if not specified

            # Handle lists
            if isinstance(value, list):
                for item in value:
                    graph.add((specification, property_uri, Literal(item, datatype=datatype)))
            else:
                # Add single value with specified datatype
                graph.add((specification, property_uri, Literal(value, datatype=datatype)))

        return graph

    @staticmethod
    def _create_combined_graph(metadata_graph: Graph, data_graph: Graph) -> Graph:
        """
        Creates a combined RDF graph by merging metadata and data graphs.

        This method takes two RDFLib graphs (one containing metadata and the other containing structured data)
        and merges them, ensuring that all triples are included in the final graph.

        :param metadata_graph: RDF graph containing metadata properties of the LaDeRR specification.
        :type metadata_graph: Graph
        :param data_graph: RDF graph containing data instances and their relationships.
        :type data_graph: Graph
        :return: A single RDFLib graph containing both metadata and data.
        :rtype: Graph
        """
        # Create a new graph to store the combined information
        combined_graph = Graph()

        # Merge metadata graph
        combined_graph += metadata_graph

        # Merge data graph
        combined_graph += data_graph

        return combined_graph

    @classmethod
    def create_laderr_graph(cls, laderr_file_path: str) -> Graph:
        """
        Creates a unified RDF graph for a LaDeRR specification.

        Reads a specification file, converts metadata and data into RDF graphs, and merges them.

        :param laderr_file_path: Path to the LaDeRR specification file.
        :type laderr_file_path: str
        :return: A single RDFLib graph containing all metadata and data from the specification.
        :rtype: Graph
        """
        spec_metadata, spec_data = SpecificationHandler.read_specification(laderr_file_path)
        laderr_metadata_graph = cls._convert_metadata_to_graph(spec_metadata)
        laderr_data_graph = cls._convert_data_to_graph(spec_data)
        return cls._create_combined_graph(laderr_metadata_graph, laderr_data_graph)
