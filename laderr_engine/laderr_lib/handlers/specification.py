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

    :cvar LADERR_NS: Namespace for LaDeRR ontology.
    :vartype LADERR_NS: Namespace
    """

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
    def write_specification(cls, laderr_graph: Graph, output_file: str) -> None:
        """
        Serializes a LaDeRR specification into TOML format and writes it to a file.

        This function extracts metadata and data instances from the provided RDF graphs, converting them into a
        structured dictionary format suitable for TOML serialization. Metadata fields are sorted for consistency.

        Data instances are categorized by type and structured in a hierarchical format that preserves relationships.

        :param metadata_graph: RDF laderr_graph containing metadata properties of the LaDeRR specification.
        :type metadata_graph: Graph
        :param data_graph: RDF laderr_graph containing data instances and their relationships.
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
