"""
Module for handling RDF laderr_graph operations in the LaDeRR framework.

This module provides functionalities for loading RDF schemas and saving RDF graphs in various formats.
"""
import os

from loguru import logger
from rdflib import Graph, RDF, XSD, Literal, RDFS, Namespace, URIRef
from rdflib.exceptions import ParserError

from laderr_engine.laderr_lib.constants import LADERR_SCHEMA_PATH, LADERR_NS
from laderr_engine.laderr_lib.services.specification import SpecificationHandler
from laderr_engine.laderr_lib.services.validation import ValidationHandler

VERBOSE = True


class GraphHandler:
    """
    Handles operations related to RDF laderr_graph loading and saving.

    This class provides methods to:
    - Load RDF schemas from a file into an RDFLib laderr_graph.
    - Serialize and save RDF graphs to a file in a specified format.
    """

    @classmethod
    def load_laderr_schema(cls) -> Graph:
        """
        Loads an RDF schema file into an RDFLib laderr_graph.

        This method reads an RDF file and parses its contents into an RDFLib laderr_graph, allowing further processing and
        validation of RDF data structures.

        :return: An RDFLib laderr_graph containing the parsed RDF data.
        :rtype: Graph
        :raises FileNotFoundError: If the specified RDF file does not exist.
        :raises ValueError: If the RDF file is malformed or cannot be parsed.
        """
        # Initialize the laderr_graph
        graph = Graph()

        try:
            # Parse the file into the laderr_graph
            graph.parse(LADERR_SCHEMA_PATH)
        except (ParserError, ValueError) as e:
            raise ValueError(
                f"Failed to parse the RDF file '{LADERR_SCHEMA_PATH}'. Ensure it is a valid RDF file.") from e

        return graph

    @staticmethod
    def save_graph(graph: Graph, file_path: str, format: str = "turtle") -> None:
        """
        Serializes and saves an RDF laderr_graph to a file.

        This method takes an RDF laderr_graph and serializes it into a specified format before writing it to a file.
        The function ensures that the target directory exists before attempting to write the file.

        :param graph: The RDF laderr_graph to be serialized and saved.
        :type graph: Graph
        :param file_path: Path where the serialized RDF laderr_graph will be stored.
        :type file_path: str
        :param format: The serialization format (e.g., "turtle", "xml", "nt", "json-ld"). Default is "turtle".
        :type format: str
        :raises ValueError: If the specified serialization format is not supported.
        :raises OSError: If the file cannot be written due to permission issues or invalid path.
        """
        try:
            # Ensure the output directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Serialize and save the laderr_graph
            graph.serialize(destination=file_path, format=format)
            logger.success(f"Graph saved successfully to '{file_path}' in format '{format}'.")
        except ValueError as e:
            raise ValueError(f"Serialization format '{format}' is not supported.") from e
        except OSError as e:
            raise OSError(f"Could not write to file '{file_path}': {e}") from e

    @staticmethod
    def _initialize_graph_with_namespaces(spec_metadata: dict[str, object]) -> tuple[Graph, Namespace, Namespace]:
        """
        Initializes an RDFLib laderr_graph with the appropriate namespaces.

        This method creates an RDF laderr_graph and binds the necessary namespaces, ensuring that
        all RDF entities can be correctly referenced.

        :param spec_metadata: Dictionary containing metadata information, including base URI.
        :type spec_metadata: dict[str, object]
        :return: A tuple containing the RDF laderr_graph, data namespace, and specification URI.
        :rtype: tuple[Graph, Namespace, Namespace]
        """
        base_uri = ValidationHandler.validate_base_uri(spec_metadata)
        data_ns = Namespace(base_uri)
        graph = Graph()
        graph.bind("", data_ns)  # Bind default namespace
        graph.bind("laderr", LADERR_NS)  # Bind LaDeRR namespace

        # Create the central LaderrSpecification instance
        specification_uri = data_ns.LaderrSpecification
        graph.add((specification_uri, RDF.type, LADERR_NS.LaderrSpecification))

        return graph, data_ns, specification_uri

    @staticmethod
    def _process_instance(graph: Graph, data_ns: Namespace, class_type: str, instance_id: str,
                          properties: dict[str, object]) -> None:
        """
        Processes a single instance and adds it to the RDF graph.

        This method converts an instance's properties into RDF triples, including handling labels,
        lists, and special mappings (such as 'state' for Dispositions, Capabilities, and Vulnerabilities).

        If a 'Disposition', 'Capability', or 'Vulnerability' instance does not have a 'state',
        a default state 'laderr:Enabled' is assigned **only once**.

        :param graph: The RDF graph being constructed.
        :param data_ns: The namespace to use for instance URIs.
        :param class_type: The class type of the instance.
        :param instance_id: The unique identifier for the instance.
        :param properties: Dictionary of properties for the instance.
        :raises ValueError: If the properties structure is invalid.
        """
        instance_uri = URIRef(f"{data_ns}{instance_id}")  # Ensure instance is URI
        graph.add((instance_uri, RDF.type, LADERR_NS[class_type]))

        has_state = False  # Track if state exists

        for prop, value in properties.items():
            if prop == "id":
                continue  # Skip `id`, already used as URI

            if prop == "label":
                graph.add((instance_uri, RDFS.label, Literal(value)))  # Label remains a Literal

            elif prop == "state":
                # Convert state to URI (NOT a string literal)
                state_uri = LADERR_NS.enabled if value.lower() == "enabled" else LADERR_NS.disabled
                graph.add((instance_uri, LADERR_NS.state, state_uri))
                has_state = True  # Mark that a state was explicitly provided

            elif prop in {"label", "description"}:  # Ensure these are stored as URIs
                # Default case: Store values as Literals unless explicitly listed above
                if isinstance(value, list):
                    for item in value:
                        graph.add((instance_uri, LADERR_NS[prop], Literal(item)))
                else:
                    graph.add((instance_uri, LADERR_NS[prop], Literal(value)))

            else:
                if isinstance(value, list):
                    for item in value:
                        graph.add((instance_uri, LADERR_NS[prop], URIRef(f"{data_ns}{item}")))  # Store as URIRef
                else:
                    graph.add((instance_uri, LADERR_NS[prop], URIRef(f"{data_ns}{value}")))  # Store as URIRef

        # Ensure state is always added as a URI
        if class_type in {"Disposition", "Capability", "Vulnerability"} and not has_state:
            graph.add((instance_uri, LADERR_NS.state, LADERR_NS.enabled))  # Store as URI
            VERBOSE and logger.info(f"Added default state 'enabled' to: {instance_uri}")

    @staticmethod
    def convert_data_to_graph(spec_metadata: dict[str, object],
                              spec_data: dict[str, dict[str, dict[str, object]]]) -> Graph:
        """
        Converts the 'data' section of a LaDeRR specification into an RDF laderr_graph.

        This method initializes an RDF laderr_graph, iterates through the specification data,
        and processes each class type and its instances into RDF triples.

        :param spec_metadata: Dictionary containing metadata information, including base URI.
        :type spec_metadata: dict[str, object]
        :param spec_data: Nested dictionary representing the data structure of the specification.
                          It maps class types to instances, each containing their properties.
        :type spec_data: dict[str, dict[str, dict[str, object]]]
        :return: An RDFLib laderr_graph containing all data instances and their relationships.
        :rtype: Graph
        :raises ValueError: If the structure of spec_data does not conform to expected nested dictionaries.
        """
        graph, data_ns, specification_uri = GraphHandler._initialize_graph_with_namespaces(spec_metadata)

        for class_type, instances in spec_data.items():
            if not isinstance(instances, dict):
                raise ValueError(f"Invalid structure for {class_type}. Expected a dictionary of instances.")

            for key, properties in instances.items():
                if not isinstance(properties, dict):
                    raise ValueError(
                        f"Invalid structure for instance '{key}' in '{class_type}'. Expected a dictionary of properties.")

                instance_id = properties.get("id", key)

                # Process the instance
                GraphHandler._process_instance(graph, data_ns, class_type, instance_id, properties)

                # Ensure instance URI is correctly formed
                instance_uri = URIRef(f"{data_ns}{instance_id}")
                graph.add((specification_uri, LADERR_NS.composedOf, instance_uri))

        return graph

    @staticmethod
    def convert_metadata_to_graph(metadata: dict[str, object]) -> tuple[Graph, Namespace]:
        """
        Converts LaDeRR specification metadata into an RDF laderr_graph.

        This method extracts metadata attributes and represents them as RDF triples, ensuring proper data types
        (e.g., `xsd:string`, `xsd:dateTime`). The `baseUri` is used to establish the namespace, and all metadata
        properties are assigned to the `LaderrSpecification` instance.

        :param metadata: Dictionary containing metadata attributes such as title, version, and authorship.
        :type metadata: dict[str, object]
        :return: A tuple containing the RDFLib laderr_graph representing the specification metadata and the namespace.
        :rtype: tuple[Graph, Namespace]
        :raises ValueError: If the provided metadata contains invalid formats or unsupported data types.
        """
        # Define expected datatypes for spec_metadata_dict keys
        expected_datatypes = {"title": XSD.string, "description": XSD.string, "version": XSD.string,
                              "createdBy": XSD.string, "createdOn": XSD.dateTime, "modifiedOn": XSD.dateTime,
                              "baseUri": XSD.anyURI, }

        # Validate base URI and bind namespaces
        base_uri = ValidationHandler.validate_base_uri(metadata)
        data_ns = Namespace(base_uri)

        # Create a new laderr_graph
        graph = Graph()
        graph.bind("", data_ns)  # Bind the `:` namespace
        graph.bind("laderr", LADERR_NS)  # Bind the `laderr:` namespace

        # Create or identify LaderrSpecification instance
        specification = data_ns.LaderrSpecification
        graph.add((specification, RDF.type, LADERR_NS.LaderrSpecification))

        # Add spec_metadata_dict as properties of the specification
        for key, value in metadata.items():
            property_uri = LADERR_NS[key]  # Schema properties come from laderr namespace
            datatype = expected_datatypes.get(key, XSD.anyURI)  # Default to xsd:string if not specified

            # Handle lists
            if isinstance(value, list):
                for item in value:
                    graph.add((specification, property_uri, Literal(item, datatype=datatype)))
            else:
                # Add single value with specified datatype
                graph.add((specification, property_uri, Literal(value, datatype=datatype)))

        return graph, data_ns

    @staticmethod
    def create_combined_graph(laderr_graph: Graph) -> Graph:

        combined_graph = Graph()

        schema_graph = GraphHandler.load_laderr_schema()

        combined_graph += schema_graph
        combined_graph += laderr_graph

        return combined_graph

    @staticmethod
    def create_laderr_graph(laderr_file_path: str) -> Graph:
        """
        Creates a unified RDF laderr_graph for a LaDeRR specification.

        Reads a specification file, converts metadata and data into RDF graphs, and merges them.

        :param laderr_file_path: Path to the LaDeRR specification file.
        :type laderr_file_path: str
        :return: A single RDFLib laderr_graph containing all metadata and data from the specification.
        :rtype: Graph
        """
        spec_metadata, spec_data = SpecificationHandler.read_specification(laderr_file_path)
        laderr_metadata_graph, base_uri = GraphHandler.convert_metadata_to_graph(spec_metadata)
        laderr_data_graph = GraphHandler.convert_data_to_graph(spec_metadata, spec_data)

        # Create a new laderr_graph to store the combined information
        laderr_graph = Graph()

        # Merge metadata laderr_graph
        laderr_graph += laderr_metadata_graph

        # Merge data laderr_graph
        laderr_graph += laderr_data_graph

        # Validate base URI and bind namespaces
        laderr_graph.bind("", base_uri)  # Bind the `laderr:` namespace
        laderr_graph.bind("laderr", LADERR_NS)  # Bind the `laderr:` namespace

        return laderr_graph

    @staticmethod
    def get_base_prefix(graph: Graph) -> str:
        """
        Retrieves the base prefix (default namespace) of the RDF graph.

        :param graph: The RDFLib graph
        :return: The base prefix as a string, or None if not found
        """
        for prefix, namespace in graph.namespaces():
            if prefix == "":  # The base namespace is always bound to an empty prefix ""
                return str(namespace)
        logger.warning("Base prefix not found")
