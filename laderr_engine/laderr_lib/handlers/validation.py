"""
Module for validating LaDeRR specifications and RDF graphs using SHACL constraints.

This module provides functions to perform syntactic and semantic validation of LaDeRR specification files,
as well as SHACL validation of RDF graphs.
"""

import os
from urllib.parse import urlparse

from loguru import logger
from pyshacl import validate
from rdflib import Namespace, Graph

from laderr_engine.laderr_lib.constants import SHACL_FILES_PATH
from laderr_engine.laderr_lib.handlers.specification import SpecificationHandler

VERBOSE = True


class ValidationHandler:
    """
    Handles the validation of LaDeRR specifications and RDF graphs.

    This class provides methods for validating RDF data against SHACL constraints, ensuring that LaDeRR
    specifications conform to syntactic and semantic requirements.

    :cvar LADERR_NS: Namespace for LaDeRR ontology.
    :vartype LADERR_NS: Namespace
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
        - Reports the validation results and saves the processed RDF laderr_graph.

        :param laderr_file_path: Path to the LaDeRR specification file to be validated.
        :type laderr_file_path: str
        :return: Boolean indicating whether the specification file is valid.
        :rtype: bool
        :raises FileNotFoundError: If the specified file does not exist.
        :raises tomllib.TOMLDecodeError: If the TOML file contains invalid syntax.
        """
        from laderr_engine.laderr_lib.handlers.graph import GraphHandler

        # Syntactical validation
        spec_metadata_dict, spec_data_dict = SpecificationHandler._read_specification(laderr_file_path)

        # Semantic validation
        spec_metadata_graph = GraphHandler.convert_metadata_to_graph(spec_metadata_dict)
        spec_data_graph = GraphHandler.convert_data_to_graph(spec_metadata_dict, spec_data_dict)

        # Combine graphs
        unified_graph = Graph()
        unified_graph += spec_metadata_graph
        unified_graph += spec_data_graph

        SpecificationHandler.write_specification(spec_metadata_graph, spec_data_graph, "./test_output.toml")

        # Combine instances with Schema for correct SHACL evaluation
        laderr_schema = GraphHandler.load_laderr_schema()
        validation_graph = Graph()
        validation_graph += unified_graph
        validation_graph += laderr_schema

        # Bind namespaces in the unified laderr_graph
        base_uri = cls.validate_base_uri(spec_metadata_dict)
        unified_graph.bind("", Namespace(base_uri))  # Bind `:` to the base URI
        unified_graph.bind("laderr", cls.LADER_NS)  # Bind `laderr:` to the schema namespace

        conforms, _, report_text = cls._validate_with_shacl(validation_graph)
        cls._report_validation_result(conforms, report_text)
        GraphHandler.save_graph(unified_graph, "./manual_test_resources/result.ttl")
        return conforms

    @classmethod
    def validate_base_uri(cls, spec_metadata_dict: dict[str, object]) -> str:
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
            logger.warning(f"Invalid base URI '{base_uri}' provided. Using default 'https://laderr.laderr#'.")

        return base_uri

    @staticmethod
    def validate_laderr_graph(laderr_graph: Graph) -> tuple[bool, str, Graph]:
        """
        Validates an RDF graph using SHACL constraints.

        This method checks whether the provided RDF graph conforms to the SHACL schema rules
        defined for LaDeRR specifications.

        :param laderr_graph: RDF graph to validate.
        :type laderr_graph: Graph
        :return: A tuple containing:
            - A boolean indicating whether the graph conforms to SHACL constraints.
            - A string containing detailed validation results.
            - A graph representing the SHACL validation report.
        :rtype: tuple[bool, str, Graph]
        """
        from laderr_engine.laderr_lib.handlers.graph import GraphHandler

        combined_graph = GraphHandler.create_combined_graph(laderr_graph)

        shacl_graph = ValidationHandler.load_shacl_schemas(SHACL_FILES_PATH)

        conforms, report_graph, report_text = validate(data_graph=combined_graph, shacl_graph=shacl_graph,
                                                       inference="both", allow_infos=True, allow_warnings=True)

        # DEBUG OPTION
        # conforms, report_graph, report_text = validate(data_graph=laderr_graph, shacl_graph=shacl_graph, inference="both",
        #                                                allow_infos=True, allow_warnings=True, meta_shacl=True)

        ValidationHandler._report_validation_result(conforms, report_text)

        return conforms, report_graph, report_text

    @staticmethod
    def load_shacl_schemas(shacl_files_path: str) -> Graph:
        """
        Loads SHACL schema files from a directory and merges them into a single RDFLib graph.

        This method iterates over all SHACL files in the specified directory, ensuring only files
        with a `.shacl` extension are processed. If any SHACL file is invalid, a warning is logged.

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
            file_path = os.path.join(shacl_files_path, filename)

            # Skip non-files and non-SHACL files
            if not os.path.isfile(file_path) or not filename.endswith(".shacl"):
                logger.info(f"Skipping non-SHACL file: {filename}")
                continue

            # Attempt to parse the SHACL file
            try:
                merged_graph.parse(file_path, format="turtle")
                logger.info(f"Loaded SHACL file: {filename}")
            except Exception as e:
                logger.warning(f"Failed to parse SHACL file '{filename}': {e}")

        # Ensure at least one valid SHACL file was loaded
        if len(merged_graph) == 0:
            raise ValueError(f"No valid SHACL files found in the directory '{shacl_files_path}'.")

        return merged_graph

    @classmethod
    def _report_validation_result(cls, conforms: bool, report_text: str) -> None:
        """
        (Internal) Reports the results of SHACL validation to the user.

        This method logs whether the RDF laderr_graph conforms to SHACL constraints and provides a detailed validation report.

        :param conforms: Boolean indicating whether the RDF laderr_graph conforms to the SHACL schema.
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
