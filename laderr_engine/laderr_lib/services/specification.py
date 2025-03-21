"""
Module for handling LaDeRR specification operations, including reading, writing, and conversion between RDF graphs and
TOML-based specifications.

This module provides functionality to:
- Read a LaDeRR specification from a TOML file into structured metadata and data dictionaries.
- Apply default values where necessary to ensure the specification is complete.
- Convert a LaDeRR specification (represented as an RDF graph) into TOML and write it to disk.
"""
import re
import tomllib
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

import tomli_w  # Used only for writing TOML, not reading
from loguru import logger
from rdflib import Graph, RDF, Literal, URIRef, RDFS

from laderr_engine.laderr_lib.constants import LADERR_NS, VERBOSE


class SpecificationHandler:
    """
    Handles reading, writing, and converting LaDeRR specifications between TOML format and RDF graphs.

    Responsibilities:
    - Parsing LaDeRR specifications from TOML files.
    - Ensuring all required attributes have default values if they are missing.
    - Serializing LaDeRR specifications from RDF graphs to TOML files.
    - Sorting and formatting data for consistent TOML output.
    """

    @staticmethod
    def read_specification(laderr_file_path: str) -> tuple[dict[str, object], dict[str, object]]:
        """
        Reads a LaDeRR specification from a TOML file and extracts structured metadata and data sections.

        The TOML file is split into:
        - `spec_metadata`: Top-level attributes (title, version, createdBy, etc.).
        - `spec_data`: Nested constructs such as entities, capabilities, and vulnerabilities.

        If `createdBy` is a string, it is normalized into a list.
        If `scenario`, `baseURI`, or other defaults are missing, they are added.

        :param laderr_file_path: Path to the TOML file containing the LaDeRR specification.
        :type laderr_file_path: str
        :return: A tuple containing:
            - spec_metadata (dict): Top-level metadata attributes.
            - spec_data (dict): Structured constructs (entities, capabilities, vulnerabilities).
        :rtype: tuple[dict[str, object], dict[str, object]]
        :raises FileNotFoundError: If the file does not exist.
        :raises tomllib.TOMLDecodeError: If the file is not valid TOML.
        """
        try:
            with open(laderr_file_path, "rb") as file:
                data: dict[str, object] = tomllib.load(file)

            spec_metadata = {key: value for key, value in data.items() if not isinstance(value, dict)}
            spec_data = {key: value for key, value in data.items() if isinstance(value, dict)}

            SpecificationHandler._apply_defaults(spec_metadata, spec_data)

            logger.success("LaDeRR specification's syntax successfully validated.")
            return spec_metadata, spec_data

        except FileNotFoundError as e:
            logger.error(f"Error: File '{laderr_file_path}' not found.")
            raise e
        except tomllib.TOMLDecodeError as e:
            logger.error(f"Error: Syntactical error. Failed to parse LaDeRR/TOML file. {e}")
            raise e

    @staticmethod
    def _apply_defaults(spec_metadata: dict[str, object], spec_data: dict[str, object]) -> None:
        """
        Applies all necessary default values to the metadata and data parts of the specification,
        including validating the 'baseURI' field.

        Each time a default is applied or a correction is made, it is logged to inform the user (if VERBOSE is True).

        :param spec_metadata: Dictionary with metadata attributes.
        :param spec_data: Dictionary representing structured data instances.
        """

        # Validate and apply default to baseURI
        default_base_uri = "https://laderr.laderr#"
        base_uri = spec_metadata.get("baseURI", default_base_uri)
        parsed = urlparse(base_uri)

        if not all([parsed.scheme, parsed.netloc]):
            logger.warning(f"Invalid base URI '{base_uri}' provided. Using default '{default_base_uri}'.")
            spec_metadata["baseURI"] = default_base_uri
        else:
            spec_metadata["baseURI"] = base_uri  # Reassign explicitly in case it was missing

        # Metadata defaults
        if "scenario" not in spec_metadata:
            spec_metadata["scenario"] = "operational"
            VERBOSE and logger.info("Added default value 'operational' for metadata field 'scenario'.")

        if "createdBy" in spec_metadata and isinstance(spec_metadata["createdBy"], str):
            spec_metadata["createdBy"] = [spec_metadata["createdBy"]]

        # Data defaults
        for class_type, instances in spec_data.items():
            if isinstance(instances, dict):
                for key, properties in instances.items():
                    if isinstance(properties, dict):
                        # If user provided `id`, check if it's conflicting
                        if "id" in properties and properties["id"] != key:
                            logger.warning(
                                f"Ignoring user-provided 'id' = '{properties['id']}' for {class_type} '{key}', "
                                f"as 'id' must match the section key."
                            )

                        # Force `id` to be derived from section key
                        properties["id"] = key

                        if "label" not in properties:
                            properties["label"] = properties["id"]
                            VERBOSE and logger.info(
                                f"For {class_type} with id '{properties['id']}', added default 'label' = '{properties['label']}'"
                            )

                        if class_type in {"Disposition", "Capability", "Vulnerability"} and "state" not in properties:
                            properties["state"] = "enabled"
                            VERBOSE and logger.info(
                                f"For {class_type} with id '{properties['id']}', added default 'state' = 'enabled'"
                            )

    @staticmethod
    def write_specification(laderr_graph: Graph, output_file_path: str) -> None:
        """
        Serializes a LaDeRR specification (RDF graph) into TOML format and writes it to a file.

        :param laderr_graph: The RDFLib graph representing the LaDeRR specification.
        :type laderr_graph: Graph
        :param output_file_path: Path to write the output TOML file.
        :type output_file_path: str
        """
        data = {}

        # Extract the Specification instance
        specification_uri = None
        for s, p, o in laderr_graph.triples((None, RDF.type, LADERR_NS.Specification)):
            specification_uri = s
            break

        if specification_uri is None:
            raise ValueError("No Specification instance found in the RDF graph.")

        # Extract metadata properties
        metadata = {}
        metadata_keys = {"title", "description", "version", "createdBy", "createdOn", "modifiedOn", "baseURI",
                         "scenario"}

        for p, o in laderr_graph.predicate_objects(specification_uri):
            key = p.split("#")[-1] if str(p).startswith(str(LADERR_NS)) else None
            if key and key in metadata_keys:

                if isinstance(o, Literal):
                    if o.datatype and o.datatype == RDF.XMLLiteral:
                        value = o.toPython().toxml()  # Convert XML to a string
                    else:
                        value = o.toPython()
                else:
                    value = str(o).split("#")[-1]  # Extract entity ID for URIs

                if isinstance(value, datetime):
                    value = value.strftime("%Y-%m-%dT%H:%M:%SZ")

                if key == "scenario":
                    value = value.split("#")[-1]  # Convert full URI to short form

                if key in metadata:
                    if not isinstance(metadata[key], list):
                        metadata[key] = [metadata[key]]
                    metadata[key].append(value)
                else:
                    metadata[key] = value

        # Ensure lists are properly formatted
        for key in metadata:
            if isinstance(metadata[key], list):
                values = sorted(metadata[key])
                metadata[key] = values[0] if len(values) == 1 else values

        # Sort metadata for consistency
        data.update(dict(sorted(metadata.items())))

        # Define specific class mappings
        specific_classes = {"Asset", "Threat", "Control", "Resilience", "Capability", "Vulnerability"}

        # Extract structured constructs (Entities, Capabilities, Vulnerabilities, etc.)
        constructs = defaultdict(lambda: defaultdict(dict))
        for s, p, o in laderr_graph.triples((None, RDF.type, None)):
            class_type = str(o).split("#")[-1] if str(o).startswith(str(LADERR_NS)) else None
            if class_type and class_type in specific_classes:
                instance_id = str(s).split("#")[-1]
                constructs[class_type][instance_id] = {}

        # Extract properties for each construct
        for class_type, instances in constructs.items():
            for instance_id in instances.keys():
                instance_uri = URIRef(f"{metadata['baseURI']}{instance_id}")
                for p, o in laderr_graph.predicate_objects(instance_uri):
                    key = p.split("#")[-1] if str(p).startswith(str(LADERR_NS)) else None
                    if key is None and p == RDFS.label:
                        key = "label"  # Map rdfs:label to label field

                    if key and key not in {"type"}:  # Ignore rdf:type
                        if isinstance(o, Literal):
                            value = o.toPython()
                        else:
                            value = str(o).split("#")[-1]  # Extract entity ID for URIs

                        if isinstance(value, str) and key in {"label", "description"}:
                            value = value.strip()  # Avoid leading/trailing spaces

                        if key in instances[instance_id]:
                            if not isinstance(instances[instance_id][key], list):
                                instances[instance_id][key] = [instances[instance_id][key]]
                            instances[instance_id][key].append(value)
                        else:
                            instances[instance_id][key] = value

        # Ensure lists are properly formatted
        for class_type in constructs:
            for instance_id in constructs[class_type]:
                for key in constructs[class_type][instance_id]:
                    values = constructs[class_type][instance_id][key]
                    if isinstance(values, list):
                        values = sorted(set(values))  # Ensure unique sorted values
                        constructs[class_type][instance_id][key] = values[0] if len(values) == 1 else values

        # Sort constructs and attributes alphabetically
        for class_type in constructs:
            for instance_id in constructs[class_type]:
                constructs[class_type][instance_id] = dict(sorted(constructs[class_type][instance_id].items()))

        data.update(dict(sorted(constructs.items())))

        # Write to TOML file
        with open(output_file_path, "w", encoding="utf-8") as toml_file:
            toml_string = tomli_w.dumps(data)

            # Format lists inline
            toml_string = toml_string.replace("[\n    ", "[").replace(",\n    ", ", ").replace("\n]", "]")
            toml_string = re.sub(r",(\s*)]", "]", toml_string)  # Remove last comma before closing bracket

            toml_file.write(toml_string)

        logger.success(f"LaDeRR specification successfully written to {output_file_path}")
