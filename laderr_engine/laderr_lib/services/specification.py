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
from icecream import ic
from loguru import logger
from rdflib import Graph, RDF, Literal, URIRef, RDFS

from laderr_engine.laderr_lib.constants import LADERR_NS, VERBOSE


import tomllib
from typing import Any

class SpecificationHandler:

    @staticmethod
    def read_specification(laderr_file_path: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        """
        Reads a LaDeRR specification from a TOML file using its hierarchical structure.

        :param laderr_file_path: Path to the TOML file containing the LaDeRR specification.
        :return: A tuple containing:
            - spec_metadata (dict): Top-level metadata.
            - spec_data (dict): Grouped constructs inside "Scenario".
        """
        try:
            with open(laderr_file_path, "rb") as file:
                data: dict[str, Any] = tomllib.load(file)

            # Extract metadata (anything that's not a dictionary)
            spec_metadata = {key: value for key, value in data.items() if not isinstance(value, dict)}

            # Ensure "Scenario" is the top-level category
            spec_data: dict[str, dict[str, Any]] = {"Scenario": {}}

            scenario_definitions = data.get("Scenario", {})

            for scenario_id, scenario_info in scenario_definitions.items():
                scenario_dict = scenario_info if isinstance(scenario_info, dict) else {}
                scenario_dict.setdefault("situation", "operational")
                scenario_dict.setdefault("status", "vulnerable")
                scenario_dict["label"] = scenario_id
                scenario_dict["id"] = scenario_id
                spec_data["Scenario"][scenario_id] = scenario_dict

            # Populate scenarios with their constructs
            for scenario_id in scenario_definitions:
                if scenario_id in data:
                    # Merge the nested constructs into the scenario's dictionary
                    for construct_type, constructs in data[scenario_id].items():
                        spec_data["Scenario"][scenario_id].setdefault(construct_type, {}).update(constructs)

            SpecificationHandler._apply_metadata_defaults(spec_metadata)
            SpecificationHandler._apply_data_defaults(spec_data)

            logger.success("LaDeRR specification's syntax successfully validated.")

            return spec_metadata, spec_data

        except FileNotFoundError as e:
            logger.error(f"Error: File '{laderr_file_path}' not found.")
            raise e
        except tomllib.TOMLDecodeError as e:
            logger.error(f"Error: Syntactical error. Failed to parse LaDeRR/TOML file. {e}")
            raise e

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
        Applies necessary default values to structured data constructs in the new specification format.

        This includes:
        - Setting defaults for Scenario attributes: `situation`, `status`, and `label`.
        - Enforcing `id` and `label` for construct instances.
        - Setting default `state = "enabled"` for Capabilities and Vulnerabilities.

        :param spec_data: Dictionary where top-level keys are construct categories (e.g., "Scenario").
        """
        for construct_category, items in spec_data.items():
            # Only process the "Scenario" category
            if construct_category != "Scenario" or not isinstance(items, dict):
                continue

            for scenario_id, scenario_content in items.items():
                if not isinstance(scenario_content, dict):
                    continue

                # Process the scenario itself (metadata like situation, label, etc.)
                if "situation" not in scenario_content:
                    scenario_content["situation"] = "incident"
                    VERBOSE and logger.info(
                        f"Scenario '{scenario_id}' missing 'situation', defaulting to 'incident'."
                    )

                if "status" not in scenario_content:
                    scenario_content["status"] = "vulnerable"
                    VERBOSE and logger.info(
                        f"Scenario '{scenario_id}' missing 'status', defaulting to 'vulnerable'."
                    )

                if "label" not in scenario_content:
                    scenario_content["label"] = scenario_id
                    VERBOSE and logger.info(
                        f"Scenario '{scenario_id}' missing 'label', defaulting to '{scenario_id}'."
                    )

                scenario_content["id"] = scenario_id  # Always enforce `id`

                # Now process internal constructs (Entity, Capability, etc.)
                for class_type, instance_dict in scenario_content.items():
                    if class_type in {"label", "id", "situation", "status"}:
                        continue  # Skip scalar scenario fields

                    if not isinstance(instance_dict, dict):
                        continue  # Skip malformed

                    for instance_id, properties in instance_dict.items():
                        if not isinstance(properties, dict):
                            continue

                        if "id" in properties and properties["id"] != instance_id:
                            logger.warning(
                                f"Ignoring user-provided 'id' = '{properties['id']}' for {class_type} '{instance_id}', "
                                f"as 'id' must match the section key."
                            )
                        properties["id"] = instance_id

                        if "label" not in properties:
                            properties["label"] = instance_id
                            VERBOSE and logger.info(
                                f"For {class_type} '{instance_id}' in scenario '{scenario_id}', "
                                f"added default 'label' = '{instance_id}'."
                            )

                        if class_type in {"Disposition", "Capability", "Vulnerability"} and "state" not in properties:
                            properties["state"] = "enabled"
                            VERBOSE and logger.info(
                                f"For {class_type} '{instance_id}' in scenario '{scenario_id}', "
                                f"added default 'state' = 'enabled'."
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
