import os
from urllib.parse import urlparse

from icecream import ic
from loguru import logger
from pyshacl import validate
from rdflib import Namespace, Graph

from laderr_engine.laderr_lib import Laderr
from laderr_engine.laderr_lib.utils.constants import SHACL_FILES_PATH


class ValidationHandler:

    @classmethod
    def validate_specification(cls, laderr_file_path: str):
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

    def validate_graph(self):
        pass

    @classmethod
    def _validate_base_uri(cls, spec_metadata_dict: dict[str, object]) -> str:
        """
        Validates the base URI provided in the metadata dictionary. If the base URI is invalid or missing,
        a default value of "https://laderr.laderr#" is returned.

        :param spec_metadata_dict: Metadata dictionary.
        :type spec_metadata_dict: Dict[str, object]
        :return: A valid base URI.
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
    def _validate_with_shacl(cls, data_graph: Graph) -> tuple[bool, str, Graph]:
        """
        Validates an RDF graph against a SHACL shapes file.

        :param data_graph: RDF graph to validate.
        :type data_graph: Graph
        :return: A tuple containing:
            - A boolean indicating if the graph is valid.
            - A string with validation results.
            - A graph with validation report.
        :rtype: Tuple[bool, str, Graph]
        """
        shacl_graph = Laderr._merge_shacl_files(SHACL_FILES_PATH)
        ic(len(shacl_graph))

        conforms, report_graph, report_text = validate(data_graph=data_graph, shacl_graph=shacl_graph, inference="both",
                                                       allow_infos=True, allow_warnings=True)

        return conforms, report_graph, report_text

    @classmethod
    def _merge_shacl_files(cls, shacl_files_path: str) -> Graph:
        """
        Merges all SHACL files in the given path into a single RDFLib graph.

        :param shacl_files_path: The directory path containing SHACL files.
        :type shacl_files_path: str
        :return: A single RDFLib graph containing all merged SHACL shapes.
        :rtype: Graph
        :raises FileNotFoundError: If the directory or files are not found.
        :raises ValueError: If the directory does not contain valid SHACL files.
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
