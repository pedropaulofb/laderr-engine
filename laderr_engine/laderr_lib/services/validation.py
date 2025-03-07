"""
Module for validating LaDeRR specifications and RDF graphs using SHACL constraints.

This module provides functions to perform syntactic and semantic validation of LaDeRR specification files,
as well as SHACL validation of RDF graphs.
"""

import os
from urllib.parse import urlparse

from loguru import logger
from pyshacl import validate
from rdflib import Graph

from laderr_engine.laderr_lib.constants import SHACL_FILES_PATH, VERBOSE


class ValidationHandler:
    """
    Handles the validation of LaDeRR specifications and RDF graphs.

    This class provides methods for validating RDF data against SHACL constraints, ensuring that LaDeRR
    specifications conform to syntactic and semantic requirements.
    """
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
        from laderr_engine.laderr_lib.services.graph import GraphHandler

        combined_graph = GraphHandler.create_combined_graph(laderr_graph)

        shacl_graph = ValidationHandler.load_shacl_schemas(SHACL_FILES_PATH)

        conforms, report_graph, report_text = validate(data_graph=combined_graph, shacl_graph=shacl_graph,
                                                       inference="both", allow_infos=True, allow_warnings=True)

        # VERBOSE OPTION
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
                VERBOSE and logger.info(f"Skipping non-SHACL file: {filename}")
                continue

            # Attempt to parse the SHACL file
            try:
                merged_graph.parse(file_path, format="turtle")
                VERBOSE and logger.info(f"Loaded SHACL file: {filename}")
            except Exception as e:
                logger.warning(f"Failed to parse SHACL file '{filename}': {e}")

        # Ensure at least one valid SHACL file was loaded
        if len(merged_graph) == 0:
            raise ValueError(f"No valid SHACL files found in the directory '{shacl_files_path}'.")

        return merged_graph

    @staticmethod
    def _report_validation_result(conforms: bool, report_text: str) -> None:
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
            logger.error("The LaDeRR specification is invalid.")

        # Print the full textual validation report
        VERBOSE and logger.info(f"Full Validation Report: {report_text}")
