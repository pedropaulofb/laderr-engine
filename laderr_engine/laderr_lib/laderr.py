import os
import tomllib

from icecream import ic
from loguru import logger
from rdflib import Graph, Namespace, RDF, Literal, XSD, RDFS
from rdflib.exceptions import ParserError

from laderr_engine.laderr_lib.handlers.handler_validator import HandlerValidator
from laderr_engine.test_files import RDF_FILE_PATH


class Laderr:
    """
    A utility class for providing methods to operate on RDF data and SHACL validation.
    This class is not meant to be instantiated.
    """

    def __init__(self):
        raise TypeError(f"{self.__class__.__name__} is a utility class and cannot be instantiated.")

    @classmethod
    def _load_spec_data(cls, spec_metadata: dict[str, object], spec_data: dict[str, object]) -> Graph:
        """
        Loads the data section from the specification into an RDFLib graph and adds the `composedOf` relationship.

        If the `id` property is not explicitly defined within a section, the id is automatically set to the section's
        key name (e.g., "X" from [RiskEvent.X]).

        The base URI from `spec_metadata` is used as the namespace for the data.

        :param spec_metadata: Metadata dictionary containing the base URI.
        :type spec_metadata: dict[str, object]
        :param spec_data: Dictionary representing the `data` section of the specification.
        :type spec_data: dict[str, object]
        :return: RDFLib graph containing the data and `composedOf` relationship.
        :rtype: Graph
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
    def _load_spec_metadata(cls, metadata: dict[str, object]) -> Graph:
        """
        Creates an RDF graph containing only the provided spec_metadata_dict.

        :param metadata: Metadata dictionary to add to the graph.
        :type metadata: dict[str, object]
        :return: A new RDFLib graph containing only the spec_metadata_dict.
        :rtype: Graph
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

    @classmethod
    def validate_specification(cls, laderr_file_path: str):
        return HandlerValidator.validate_specification(laderr_file_path)

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

    @classmethod
    def _read_specification(cls, laderr_file_path: str) -> tuple[dict[str, object], dict[str, object]]:
        """
        Reads a TOML file, parses its content into a Python dictionary, and extracts preamble keys into a `spec_metadata_dict` dict.

        This function uses Python's built-in `tomllib` library to parse TOML files. The file must be passed as a binary
        stream, as required by `tomllib`. It processes the top-level keys that are not part of any section (preamble) and
        stores them in a separate `spec_metadata_dict` dictionary. Handles cases where `createdBy` is a string or a list of strings.

        :param laderr_file_path: The path to the TOML file to be read.
        :type laderr_file_path: str
        :return: A tuple containing:
            - `spec_metadata_dict`: A dictionary with preamble keys and their values.
            - `data`: A dictionary with the remaining TOML data (sections and their contents).
        :rtype: tuple[dict[str, object], dict[str, object]]
        :raises FileNotFoundError: If the specified file does not exist or cannot be found.
        :raises tomllib.TOMLDecodeError: If the TOML file contains invalid syntax or cannot be parsed.
        """
        try:
            with open(laderr_file_path, "rb") as file:
                data: dict[str, object] = tomllib.load(file)

            # Separate spec_metadata_dict and data
            spec_metadata = {key: value for key, value in data.items() if not isinstance(value, dict)}
            spec_data = {key: value for key, value in data.items() if isinstance(value, dict)}

            # Add `id` to each item in spec_data if missing
            for class_type, instances in spec_data.items():
                if isinstance(instances, dict):
                    for key, properties in instances.items():
                        if isinstance(properties, dict) and "id" not in properties:
                            properties["id"] = key  # Default `id` to the section key

            # Normalize `createdBy` to always be a list if it's a string
            if "createdBy" in spec_metadata and isinstance(spec_metadata["createdBy"], str):
                spec_metadata["createdBy"] = [spec_metadata["createdBy"]]

            logger.success("LaDeRR specification's syntax successfully validated.")
            return spec_metadata, spec_data

        except FileNotFoundError as e:
            logger.error(f"Error: File '{laderr_file_path}' not found.")
            raise e
        except tomllib.TOMLDecodeError as e:
            logger.error(f"Error: Syntactical error. Failed to parse LaDeRR/TOML file. {e}")
            raise e

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

    @classmethod
    def _report_validation_result(cls, conforms: bool, report_text: str) -> None:
        """
        Reports the results of SHACL validation to the user.

        :param conforms: Boolean indicating if the RDF graph conforms to the SHACL shapes.
        :type conforms: bool
        :param report_text: String with the validation results in text format.
        :type report_text: str
        """

        if conforms:
            logger.success("The LaDeRR specification is correct.")
        else:
            logger.error("The LaDeRR specification is not correct.")

        # Print the full textual validation report
        logger.info(f"\nFull Validation Report: {report_text}")

    @classmethod
    def write_specification(cls, metadata_graph: Graph, data_graph: Graph, output_file: str) -> None:
        """
        Serializes the metadata and data graphs into TOML format and writes to a specified file.

        :param metadata_graph: RDF graph containing metadata.
        :type metadata_graph: Graph
        :param data_graph: RDF graph containing data instances.
        :type data_graph: Graph
        :param output_file: Path to the output TOML file.
        :type output_file: str
        """
        import toml
        from collections import defaultdict

        # Extract metadata from the metadata_graph
        metadata = {}
        for subject, predicate, obj in metadata_graph:
            # Use simple predicate names, removing namespace
            predicate_name = predicate.split("#")[-1]
            if isinstance(obj, Literal):
                value = obj.toPython()
                if predicate_name in metadata:
                    if not isinstance(metadata[predicate_name], list):
                        metadata[predicate_name] = [metadata[predicate_name]]
                    metadata[predicate_name].append(value)
                else:
                    metadata[predicate_name] = value

        # Sort metadata by keys
        sorted_metadata = dict(sorted(metadata.items()))

        # Extract data instances from the data_graph
        instances = defaultdict(lambda: defaultdict(dict))
        for subject, predicate, obj in data_graph:
            if subject != metadata_graph.value(predicate=RDF.type, object=cls.LADER_NS.LaderrSpecification):
                instance_type = str(data_graph.value(subject=subject, predicate=RDF.type)).split("#")[-1]
                instance_id = str(subject).split("#")[-1]
                predicate_name = predicate.split("#")[-1]

                if isinstance(obj, Literal):
                    value = obj.toPython()
                    if predicate_name in instances[instance_type][instance_id]:
                        if not isinstance(instances[instance_type][instance_id][predicate_name], list):
                            instances[instance_type][instance_id][predicate_name] = [
                                instances[instance_type][instance_id][predicate_name]]
                        instances[instance_type][instance_id][predicate_name].append(value)
                    else:
                        instances[instance_type][instance_id][predicate_name] = value

        # Combine metadata and instances into a TOML structure
        toml_structure = {**sorted_metadata,
                          **{instance_type: dict(instance_data) for instance_type, instance_data in instances.items()}}

        # Write the TOML structure to the file
        try:
            with open(output_file, "w", encoding="utf-8") as file:
                toml.dump(toml_structure, file)
            logger.success(f"Specification serialized successfully to '{output_file}'.")
        except Exception as e:
            logger.error(f"Failed to serialize specification to TOML: {e}")
            raise
