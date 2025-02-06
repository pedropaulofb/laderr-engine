"""
Module for validating LaDeRR specifications and RDF graphs using SHACL constraints.

This module provides functions to perform syntactic and semantic validation of LaDeRR specification files,
as well as SHACL validation of RDF graphs.
"""

import os
from urllib.parse import urlparse

from icecream import ic
from loguru import logger
from pyshacl import validate
from rdflib import Namespace, Graph

from laderr_engine.laderr_lib import Laderr
from laderr_engine.laderr_lib.utils.constants import SHACL_FILES_PATH


class ValidationHandler:
    """
    Handles the validation of LaDeRR specifications and RDF graphs.

    This class provides methods for validating RDF data against SHACL constraints, ensuring that LaDeRR
    specifications conform to syntactic and semantic requirements.

    :cvar LADER_NS: Namespace for LaDeRR ontology.
    :vartype LADER_NS: Namespace
    """

    @classmethod
    def validate_specification(cls, laderr_file_path: str):
        """
        Validates a LaDeRR specification file, performing both syntactic and semantic validation.

        This method:
        - Reads the TOML specification file.
        - Parses it into structured metadata and data dictionaries.
        - Converts the parsed data into RDF graphs.
        - Combines metadata and data graphs into a unified RDF model.
        - Loads SHACL schemas and performs validation against the specification.
        - Reports the validation results and saves the processed RDF graph.

        :param laderr_file_path: Path to the LaDeRR specification file to be validated.
        :type laderr_file_path: str
        :return: Boolean indicating whether the specification file is valid.
        :rtype: bool
        :raises FileNotFoundError: If the specified file does not exist.
        :raises tomllib.TOMLDecodeError: If the TOML file contains invalid syntax.
        """
        # Syntactical validation
        spec_metadata_dict, spec_data_dict = Laderr._read_specification(laderr_file_path)

        # Semantic validation
        spec_metadata_graph = Laderr._load_spec_metadata(spec_metadata_dict)
        spec_data_graph = Laderr._load_spec_data(spec_metadata_dict, spec_data_dict)

        # Combine graphs
        unified_graph = Graph()
        unified_graph += spec_metadata_graph
        unified_graph += spec_data_graph

        Laderr.write_specification(spec_metadata_graph, spec_data_graph, "./test_output.toml")

        # Combine instances with Schema for correct SHACL evaluation
        laderr_schema = Laderr._load_schema()
        validation_graph = Graph()
        validation_graph += unified_graph
        validation_graph += laderr_schema

        # Bind namespaces in the unified graph
        base_uri = cls._validate_base_uri(spec_metadata_dict)
        unified_graph.bind("", Namespace(base_uri))  # Bind `:` to the base URI
        unified_graph.bind("laderr", cls.LADER_NS)  # Bind `laderr:` to the schema namespace

        ic(len(spec_metadata_graph), len(spec_data_graph), len(unified_graph), len(laderr_schema),
           len(validation_graph))

        conforms, _, report_text = Laderr._validate_with_shacl(validation_graph)
        Laderr._report_validation_result(conforms, report_text)
        Laderr._save_graph(unified_graph, "./result.ttl")
        return conforms

    @classmethod
    def _validate_base_uri(cls, spec_metadata_dict: dict[str, object]) -> str:
        """
        (Internal) Ensures that the base URI provided in the specification metadata is valid.

        If the base URI is missing or invalid, a default URI (`https://laderr.laderr#`) is assigned.

        :param spec_metadata_dict: Metadata dictionary containing the base URI field.
        :type spec_metadata_dict: dict[str, object]
        :return: A validated base URI.
        :rtype: str
        """
        base_uri = spec_metadata_dict.get("baseUri", "https://laderr.laderr#")
        # Check if base_uri is a valid URI
        parsed = urlparse(base_uri)
        if not all([parsed.scheme, parsed.netloc]):
            ic("here")
            logger.warning(f"Invalid base URI '{base_uri}' provided. Using default 'https://laderr.laderr#'.")

        return base_uri

    @classmethod
    def validate_graph(cls, graph: Graph) -> tuple[bool, str, Graph]:
        """
        Validates an RDF graph using SHACL constraints.

        This method checks whether the provided RDF graph conforms to the SHACL schema rules
        defined for LaDeRR specifications.

        :param graph: RDF graph to validate.
        :type graph: Graph
        :return: A tuple containing:
            - A boolean indicating whether the graph conforms to SHACL constraints.
            - A string containing detailed validation results.
            - A graph representing the SHACL validation report.
        :rtype: tuple[bool, str, Graph]
        """
        shacl_graph = Laderr._merge_shacl_files(SHACL_FILES_PATH)
        ic(len(shacl_graph))

        conforms, report_graph, report_text = validate(data_graph=graph, shacl_graph=shacl_graph, inference="both",
                                                       allow_infos=True, allow_warnings=True)

        return conforms, report_graph, report_text

    @classmethod
    def load_shacl_schemas(cls, shacl_files_path: str) -> Graph:
        """
        Loads SHACL schema files from a directory and merges them into a single RDFLib graph.

        This method iterates over all SHACL files in the specified directory and attempts to parse them.
        If any SHACL file is invalid, a warning is logged.

        :param shacl_files_path: Directory path containing SHACL schema files.
        :type shacl_files_path: str
        :return: A single RDFLib graph containing all loaded SHACL shapes.
        :rtype: Graph
        :raises FileNotFoundError: If the specified directory does not exist.
        :raises ValueError: If no valid SHACL files are found in the directory.
        """
        # Initialize an empty RDFLib graph
        merged_graph = Graph()

        # Ensure the provided path is valid
        if not os.path.isdir(shacl_files_path):
            raise FileNotFoundError(f"The path '{shacl_files_path}' does not exist or is not a directory.")

        # Iterate over all files in the directory
        for filename in os.listdir(shacl_files_path):
            ic(filename)
            file_path = os.path.join(shacl_files_path, filename)

            # Skip non-files
            if not os.path.isfile(file_path):
                continue

            # Attempt to parse the SHACL file
            try:
                merged_graph.parse(file_path, format="turtle")
            except Exception as e:
                logger.warning(f"Failed to parse SHACL file '{filename}': {e}")

        if len(merged_graph) == 0:
            raise ValueError(f"No valid SHACL files found in the directory '{shacl_files_path}'.")

        return merged_graph

    @classmethod
    def _report_validation_result(cls, conforms: bool, report_text: str) -> None:
        """
        (Internal) Reports the results of SHACL validation to the user.

        This method logs whether the RDF graph conforms to SHACL constraints and provides a detailed validation report.

        :param conforms: Boolean indicating whether the RDF graph conforms to the SHACL schema.
        :type conforms: bool
        :param report_text: Text representation of the SHACL validation report.
        :type report_text: str
        """
        if conforms:
            logger.success("The LaDeRR specification is correct.")
        else:
            logger.error("The LaDeRR specification is not correct.")

        # Print the full textual validation report
        logger.info(f"\nFull Validation Report: {report_text}")
