"""
Module for handling LaDeRR specification operations, including reading, writing, and conversion between RDF graphs and
TOML-based specifications.

This module provides functionality to:
- Read a LaDeRR specification from a TOML file into structured metadata and data dictionaries.
- Apply default values where necessary to ensure the specification is complete.
- Convert a LaDeRR specification (represented as an RDF graph) into TOML and write it to disk.
"""
import random
import re
import string
import tomllib
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

import tomli_w  # Used only for writing TOML, not reading
from icecream import ic
from loguru import logger
from rdflib import Graph, RDF, Literal, URIRef, RDFS

from laderr_engine.laderr_lib.constants import LADERR_NS, VERBOSE


import tomllib
from typing import Any

class SpecificationHandler:

    @staticmethod
    def read_specification(laderr_file_path: str) -> tuple[dict[str, Any], dict[str, dict[str, dict[str, Any]]]]:
        """
        Reads a LaDeRR specification from a TOML file using its flattened structure.

        :param laderr_file_path: Path to the TOML file containing the LaDeRR specification.
        :return: A tuple containing:
            - spec_metadata (dict): Top-level metadata.
            - spec_data (dict): A flat dictionary where each key is a construct type (e.g., "Scenario", "Entity"),
                                and values are dictionaries keyed by their identifiers.
        """
        try:
            with open(laderr_file_path, "rb") as file:
                data: dict[str, Any] = tomllib.load(file)

            # Extract metadata (anything that's not a dictionary)
            spec_metadata = {key: value for key, value in data.items() if not isinstance(value, dict)}

            # Initialize the spec_data dictionary
            spec_data: dict[str, dict[str, dict[str, Any]]] = {}

            for category, sub_dict in data.items():
                if not isinstance(sub_dict, dict):
                    continue  # Skip metadata

                for identifier, entry in sub_dict.items():
                    if not isinstance(entry, dict):
                        continue  # Malformed entry, skip

                    spec_data.setdefault(category, {})
                    spec_data[category][identifier] = entry.copy()

                    # Assign 'id' always
                    spec_data[category][identifier].setdefault("id", identifier)

            SpecificationHandler._apply_metadata_defaults(spec_metadata)
            SpecificationHandler._inject_default_scenario_if_missing(spec_data)
            SpecificationHandler._apply_data_defaults(spec_data)

            logger.success("LaDeRR specification's syntax successfully validated.")
            return spec_metadata, spec_data

        except FileNotFoundError as e:
            logger.error(f"Error: File '{laderr_file_path}' not found.")
            raise e
        except tomllib.TOMLDecodeError as e:
            logger.error(f"Error: Syntactical error. Failed to parse LaDeRR/TOML file. {e}")
            raise e
        except Exception as e:
            logger.error(f"Error reading LaDeRR specification: {e}")
            raise

    @staticmethod
    def _apply_metadata_defaults(spec_metadata: dict[str, object]) -> None:
        """
        Applies default values and validation to metadata fields in the specification.

        Changes applied:
        - The 'scenario' field is removed and no longer assigned a default.
        - 'title', 'version', and 'createdOn' are now optional.
        - 'baseURI' is validated and defaulted if missing.
        - 'createdBy' is converted to a list if present.

        :param spec_metadata: Dictionary with metadata attributes.
        """

        # Validate and apply default to baseURI
        default_base_uri = "https://laderr.laderr#"
        base_uri = spec_metadata.get("baseURI", default_base_uri)
        parsed = urlparse(base_uri)

        if not all([parsed.scheme, parsed.netloc]):
            logger.warning(f"Invalid base URI '{base_uri}' provided. Using default '{default_base_uri}'.")
            spec_metadata["baseURI"] = default_base_uri
        else:
            spec_metadata["baseURI"] = base_uri  # Ensure explicit assignment if missing

        # Ensure 'createdBy' is always a list if present
        if "createdBy" in spec_metadata and isinstance(spec_metadata["createdBy"], str):
            spec_metadata["createdBy"] = [spec_metadata["createdBy"]]

    @staticmethod
    def _apply_data_defaults(spec_data: dict[str, dict[str, dict[str, Any]]]) -> None:
        """
        Applies default values to constructs in the flattened LaDeRR specification format.

        Adds:
        - For Scenario constructs:
            - Default 'situation' = "operational"
            - Default 'status' = "vulnerable"
            - Default 'label' = <id>
            - Enforce 'id' = <key>
        - For all other constructs:
            - Default 'label' = <id>
            - Convert 'scenario' to 'scenarios' = [scenario]
            - Default 'scenarios' = all scenario IDs, if not already set
            - Default 'state' = "enabled" for Disposition, Capability, Vulnerability

        :param spec_data: Dictionary with top-level construct types (e.g., "Scenario", "Entity").
        """
        # Step 1: Collect all scenario IDs
        scenario_ids = list(spec_data.get("Scenario", {}).keys())

        for construct_type, items in spec_data.items():
            if not isinstance(items, dict):
                continue

            for instance_id, instance_data in items.items():
                if instance_id in {"id", "label"} or not isinstance(instance_data, dict):
                    continue

                # Enforce id
                if "id" in instance_data and instance_data["id"] != instance_id:
                    logger.warning(
                        f"Ignoring user-provided 'id' = '{instance_data['id']}' for {construct_type} '{instance_id}', "
                        f"as 'id' must match the section key."
                    )
                instance_data["id"] = instance_id

                # Default label
                if "label" not in instance_data:
                    instance_data["label"] = instance_id
                    VERBOSE and logger.info(
                        f"For {construct_type} '{instance_id}', added default 'label' = '{instance_id}'."
                    )

                if construct_type == "Scenario":
                    # Defaults for scenarios
                    if "situation" not in instance_data:
                        instance_data["situation"] = "operational"
                        VERBOSE and logger.info(
                            f"Scenario '{instance_id}' missing 'situation', defaulting to 'operational'."
                        )

                    if "status" not in instance_data:
                        instance_data["status"] = "vulnerable"
                        VERBOSE and logger.info(
                            f"Scenario '{instance_id}' missing 'status', defaulting to 'vulnerable'."
                        )
                else:
                    # Convert 'scenario' to 'scenarios' if needed
                    if "scenario" in instance_data:
                        if "scenarios" not in instance_data:
                            scenario_value = instance_data["scenario"]
                            if isinstance(scenario_value, list):
                                instance_data["scenarios"] = scenario_value
                            else:
                                instance_data["scenarios"] = [scenario_value]
                            VERBOSE and logger.info(
                                f"{construct_type} '{instance_id}' used 'scenario'; converted to 'scenarios'."
                            )
                        else:
                            logger.warning(
                                f"{construct_type} '{instance_id}' has both 'scenario' and 'scenarios'. "
                                f"'scenario' will be ignored."
                            )
                        del instance_data["scenario"]

                    # Assign all scenarios if 'scenarios' still not set
                    if "scenarios" not in instance_data:
                        instance_data["scenarios"] = scenario_ids.copy()
                        VERBOSE and logger.info(
                            f"{construct_type} '{instance_id}' not linked to any scenario. "
                            f"Defaulting to all scenarios: {scenario_ids}"
                        )

                    # Defaults for specific types
                    if construct_type in {"Disposition", "Capability", "Vulnerability"}:
                        if "state" not in instance_data:
                            instance_data["state"] = "enabled"
                            VERBOSE and logger.info(
                                f"For {construct_type} '{instance_id}', added default 'state' = 'enabled'."
                            )


    @staticmethod
    def _inject_default_scenario_if_missing(spec_data: dict[str, dict[str, dict[str, Any]]]) -> None:
        """
        Ensures at least one Scenario exists in the spec_data. If not, creates one with a random ID (format: SXXX).

        The new scenario is added with empty values. Default values like 'situation', 'status', etc. will be filled
        by `_apply_data_defaults`.

        :param spec_data: The specification data dictionary.
        """
        if "Scenario" not in spec_data or not spec_data["Scenario"]:
            # Generate a random scenario ID in the format SXXX
            random_suffix = ''.join(random.choices(string.ascii_uppercase, k=3))
            scenario_id = f"S{random_suffix}"

            spec_data.setdefault("Scenario", {})
            spec_data["Scenario"][scenario_id] = {}

            logger.warning(f"No scenario declared in the specification. Added default scenario '{scenario_id}'.")

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
