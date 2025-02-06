"""
Module for handling LaDeRR specification operations, including reading, writing, and conversion between RDF graphs and
TOML-based specifications.
"""

import tomllib

from loguru import logger
from rdflib import Graph, Namespace, RDF, RDFS, Literal, XSD


class SpecificationHandler:
    """
    Handles reading, writing, and converting LaDeRR specifications between TOML format and RDF graphs.

    This class provides utility methods for processing specification metadata and data, ensuring correct transformation
    into RDF triples while maintaining relationships and properties. The methods support serialization, validation, and
    data extraction.

    :cvar LADER_NS: Namespace for LaDeRR ontology.
    :vartype LADER_NS: Namespace
    """

    @classmethod
    def convert_specification_data_to_graph(cls, spec_metadata: dict[str, object], spec_data: dict[str, object]) -> Graph:
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
    def convert_specification_metadata_to_graph(cls, metadata: dict[str, object]) -> Graph:
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

    @classmethod
    def read_specification(cls, laderr_file_path: str) -> tuple[dict[str, object], dict[str, object]]:
        """
        Reads a LaDeRR specification from a TOML file and extracts structured metadata and data sections.

        This function parses the TOML file, separating top-level metadata from structured data sections.
        Metadata attributes that appear at the root level are stored in a dedicated metadata dictionary,
        while the remaining data is organized into nested dictionaries.

        If the `createdBy` field is a single string, it is automatically converted into a list for consistency.

        :param laderr_file_path: Path to the TOML file containing the LaDeRR specification.
        :type laderr_file_path: str
        :return: A tuple containing:
            - `spec_metadata`: Dictionary with metadata attributes.
            - `spec_data`: Dictionary representing structured data instances.
        :rtype: tuple[dict[str, object], dict[str, object]]
        :raises FileNotFoundError: If the specified TOML file does not exist.
        :raises tomllib.TOMLDecodeError: If the TOML file is malformed or contains syntactical errors.
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

    @classmethod
    def write_specification(cls, metadata_graph: Graph, data_graph: Graph, output_file: str) -> None:
        """
        Serializes a LaDeRR specification into TOML format and writes it to a file.

        This function extracts metadata and data instances from the provided RDF graphs, converting them into a
        structured dictionary format suitable for TOML serialization. Metadata fields are sorted for consistency.

        Data instances are categorized by type and structured in a hierarchical format that preserves relationships.

        :param metadata_graph: RDF graph containing metadata properties of the LaDeRR specification.
        :type metadata_graph: Graph
        :param data_graph: RDF graph containing data instances and their relationships.
        :type data_graph: Graph
        :param output_file: Destination file path for the serialized TOML specification.
        :type output_file: str
        :raises OSError: If the output file cannot be written to the specified location.
        :raises Exception: If an unexpected serialization error occurs.
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
