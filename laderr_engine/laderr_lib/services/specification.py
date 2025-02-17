"""
Module for handling LaDeRR specification operations, including reading, writing, and conversion between RDF graphs and
TOML-based specifications.
"""

import tomllib
from collections import defaultdict
from datetime import datetime

import tomli_w
from loguru import logger
from rdflib import Graph, RDF, Literal, URIRef

from laderr_engine.laderr_lib.constants import LADERR_NS


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

    @staticmethod
    def write_specification(laderr_graph: Graph, output_file_path: str) -> None:
        """
        Serializes a LaDeRR specification into TOML format and writes it to a file.

        Extracts metadata and data instances from an RDF graph, converting them into a
        structured dictionary format suitable for TOML serialization. Metadata fields are sorted for consistency.

        :param laderr_graph: RDF graph containing metadata and structured data instances.
        :type laderr_graph: Graph
        :param output_file_path: Destination file path for the serialized TOML specification.
        :type output_file_path: str
        """
        # Extract metadata from the graph
        metadata = {}
        specification_uri = URIRef(f"{laderr_graph.value(predicate=RDF.type, object=LADERR_NS.LaderrSpecification)}")

        for predicate, obj in laderr_graph.predicate_objects(subject=specification_uri):
            prop_name = predicate.split("#")[-1]  # Extract property name
            if isinstance(obj, Literal):
                value = obj.toPython()

                # Ensure date-time is formatted in ISO 8601 (2025-01-17T12:00:00Z)
                if isinstance(value, datetime):
                    value = value.strftime("%Y-%m-%dT%H:%M:%SZ")

                # Remove duplicates: Store values as sets (auto-removes duplicates)
                if prop_name in metadata:
                    if not isinstance(metadata[prop_name], set):
                        metadata[prop_name] = {metadata[prop_name]}  # Convert single value to set
                    metadata[prop_name].add(value)
                else:
                    metadata[prop_name] = {value} if isinstance(value, (int, float)) else value

        # Convert sets back to lists (TOML does not support sets)
        for key in metadata:
            if isinstance(metadata[key], set):
                values = sorted(list(metadata[key]))  # Sort values alphabetically
                metadata[key] = values[0] if len(values) == 1 else values
        # Sort metadata for consistency
        sorted_metadata = dict(sorted(metadata.items()))  # Sort attributes alphabetically

        # Extract instances and store attributes
        instances = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        for subject in laderr_graph.subjects(predicate=RDF.type):
            if subject == specification_uri:
                continue  # Skip main specification entry

            instance_type = str(laderr_graph.value(subject=subject, predicate=RDF.type)).split("#")[-1]
            instance_id = str(subject).split("#")[-1]

            for predicate, obj in laderr_graph.predicate_objects(subject=subject):
                prop_name = predicate.split("#")[-1]

                if isinstance(obj, Literal):
                    value = obj.toPython()

                    # Ensure date-time values maintain correct format
                    if isinstance(value, datetime):
                        value = value.strftime("%Y-%m-%dT%H:%M:%SZ")

                else:
                    value = str(obj).split("#")[-1]  # Extract entity ID for URIs

                # Store unique values using sets
                instances[instance_type][instance_id][prop_name].add(value)

        # Convert sets back to lists, but keep single values as plain strings
        for instance_type in instances:
            for instance_id in instances[instance_type]:
                for key in instances[instance_type][instance_id]:
                    values = sorted(list(instances[instance_type][instance_id][key]))  # ✅ Sort values alphabetically
                    instances[instance_type][instance_id][key] = values[0] if len(values) == 1 else values

        # Remove redundant "type" field
        for instance_type in instances:
            for instance_id in instances[instance_type]:
                if "type" in instances[instance_type][instance_id]:
                    del instances[instance_type][instance_id]["type"]

        # Sort attributes inside each section alphabetically ✅
        for instance_type in instances:
            for instance_id in instances[instance_type]:
                instances[instance_type][instance_id] = dict(sorted(instances[instance_type][instance_id].items()))

        # Construct final TOML structure
        toml_structure = {
            **sorted_metadata,
            **{instance_type: dict(instance_data) for instance_type, instance_data in instances.items()},
        }

        # Open file in text mode & write string instead of bytes
        try:
            with open(output_file_path, "w", encoding="utf-8") as file:
                toml_string = tomli_w.dumps(toml_structure)  # Generate TOML string

                # Ensure lists are formatted inline correctly
                toml_string = toml_string.replace("[\n    ", "[")  # Remove leading spaces after opening bracket
                toml_string = toml_string.replace(",\n    ", ", ")  # Remove newlines between list items
                toml_string = toml_string.replace("\n]", "]")  # Ensure closing bracket is on the same line

                # Ensure **NO trailing commas** before closing brackets
                import re

                toml_string = re.sub(r",(\s*)]", "]", toml_string)  # Remove last comma before closing bracket

                file.write(toml_string)  # Write processed TOML string

            logger.success(f"Specification serialized successfully to '{output_file_path}'.")
        except Exception as e:
            logger.error(f"Failed to serialize specification to TOML: {e}")
            raise
