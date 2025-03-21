"""
LaDeRR Library Module

This module provides a collection of static methods to operate on RDF data, perform validation, apply reasoning,
and generate visualizations for LaDeRR (Language for Describing Risk and Resilience) specifications.

### Core Functionalities:
- Convert a LaDeRR specification into an RDF graph.
- Validate RDF graphs using SHACL constraints.
- Apply reasoning to enrich RDF data.
- Save processed graphs and specifications to files.
- Generate graphical representations of LaDeRR models.

All methods are **static** within the `Laderr` class, allowing direct access without instantiation.
"""
from typing import Optional

from loguru import logger
from rdflib import Graph, Namespace

from laderr_engine.laderr_lib.services.graph import GraphHandler
from laderr_engine.laderr_lib.services.reasoning import ReasoningHandler
from laderr_engine.laderr_lib.services.specification import SpecificationHandler
from laderr_engine.laderr_lib.services.validation import ValidationHandler
from laderr_engine.laderr_lib.services.visualization import GraphCreator


class Laderr:
    """
    LaDeRR Processing Utility Class

    Provides core functionalities for handling LaDeRR specifications, including RDF graph processing,
    validation, reasoning execution, serialization, and visualization.

    **Key Functionalities:**
    - Convert LaDeRR specifications into RDF graphs.
    - Validate RDF graphs using SHACL constraints.
    - Apply reasoning to enrich RDF data.
    - Save RDF graphs and processed specifications to structured files.
    - Generate graphical representations of LaDeRR models.
    """

    def __init__(self):
        raise TypeError(f"{self.__class__.__name__} is a utility class and cannot be instantiated.")

    @staticmethod
    def load_spec_to_graph(input_spec_path: str, verbose: bool = False) -> Graph:
        """
        Loads a LaDeRR specification file and converts it into an RDF graph.

        :param input_spec_path: Path to the LaDeRR specification file.
        :type input_spec_path: str
        :param verbose: Whether to log success messages upon completion.
        :type verbose: bool
        :return: RDF graph containing the parsed LaDeRR specification.
        :rtype: Graph
        """
        laderr_graph = GraphHandler.create_laderr_graph(input_spec_path)
        if verbose:
            logger.success(f"Graph successfully created for: {input_spec_path}")
        return laderr_graph

    @staticmethod
    def validate_graph(
            laderr_graph: Graph,
            verbose: bool = False,
            stage: Optional[str] = None,
            report_file: Optional[str] = None
    ) -> tuple[bool, Graph, str]:
        """
        Validates an RDF graph using SHACL constraints.

        :param laderr_graph: The RDF graph to validate.
        :type laderr_graph: Graph
        :param verbose: Whether to log validation results.
        :type verbose: bool
        :param report_file: Optional path to save the validation report text.
        :type report_file: Optional[str]
        :param stage: Specifies validation stage ("pre", "post" or empty string) for better file naming.
        :type stage: Optional[str]
        :return: Tuple containing (conforms, validation report graph, validation report text).
        :rtype: tuple[bool, Graph, str]
        """
        conforms, report_graph, report_text = ValidationHandler.validate_laderr_graph(laderr_graph)

        # Log validation results using private method
        Laderr._log_validation_result(stage, report_graph, report_text)

        # Save report if a filename is provided
        if report_file:
            stage_txt = f"{stage} " if stage else ""
            try:
                with open(report_file, "w", encoding="utf-8") as f:
                    f.write(report_text)
                if verbose:
                    logger.success(f"Validation {stage_txt}report saved to: {report_file}")
            except IOError as e:
                logger.error(f"Error saving validation {stage_txt}report to {report_file}: {e}")

        return conforms, report_graph, report_text

    @staticmethod
    def _log_validation_result(stage: Optional[str], report_graph: Graph, report_text: str) -> None:
        """
        Logs the validation result based on severity (Infos, Warnings, or Violations).

        :param stage: Specifies validation stage ("pre", "post" or empty string) for better logging.
        :type stage: Optional[str]
        :param report_graph: The validation report graph containing validation results.
        :type report_graph: Graph
        :param report_text: The validation report text.
        :type report_text: str
        """

        sh = Namespace("http://www.w3.org/ns/shacl#")
        report_graph.bind("sh", sh)

        # Extract severity counts from the report graph
        info_count = len(list(report_graph.subjects(predicate=None, object=sh.Info)))
        warning_count = len(list(report_graph.subjects(predicate=None, object=sh.Warning)))
        violation_count = len(list(report_graph.subjects(predicate=None, object=sh.Violation)))

        stage_txt = stage.upper() if stage else "VALIDATION"

        # Determine the highest severity level and log accordingly
        if violation_count > 0:
            logger.error(f"Validation {stage_txt} FAILED. Proceeding anyway.\n{report_text}")
        elif warning_count > 0:
            logger.warning(f"Validation {stage_txt} PASSED with WARNINGS. Proceeding anyway.\n{report_text}")
        elif info_count > 0:
            logger.info(f"Validation {stage_txt} PASSED with INFOS.\n{report_text}")
        else:
            logger.success(f"Validation {stage_txt} PASSED.\n{report_text}")

    @staticmethod
    def run_reasoning_on_graph(laderr_graph: Graph, verbose: bool = False) -> Graph:
        """
        Executes reasoning on an RDF graph and returns the updated graph.

        :param laderr_graph: The RDF graph to apply reasoning on.
        :type laderr_graph: Graph
        :param verbose: Whether to log messages.
        :type verbose: bool
        :return: The RDF graph with reasoning applied.
        :rtype: Graph
        """
        laderr_graph = ReasoningHandler.execute(laderr_graph)
        if verbose:
            logger.success("Reasoning successfully applied to the graph.")
        return laderr_graph

    @staticmethod
    def save_graph(laderr_graph: Graph, output_file_path: str, verbose: bool = True) -> None:
        """
        Saves an RDF graph to a specified file.

        :param laderr_graph: The RDF graph to save.
        :type laderr_graph: Graph
        :param output_file_path: The path where the graph should be saved.
        :type output_file_path: str
        :param verbose: Whether to log success messages.
        :type verbose: bool
        """
        GraphHandler.save_graph(laderr_graph, output_file_path)
        if verbose:
            logger.success(f"Graph successfully saved to: {output_file_path}")

    @staticmethod
    def save_visualization_from_graph(laderr_graph: Graph, output_file_path: str, verbose: bool = False) -> None:
        """
        Generates a visualization from an RDF graph and saves it to a file.

        :param laderr_graph: The RDF graph to visualize.
        :type laderr_graph: Graph
        :param output_file_path: Path where the visualization should be saved.
        :type output_file_path: str
        :param verbose: Whether to log messages.
        :type verbose: bool
        """
        GraphCreator.create_graph_visualization(laderr_graph, output_file_path)
        if verbose:
            logger.success(f"Visualization successfully saved to {output_file_path}")

    @staticmethod
    def process_specification(
            input_spec_path: str,
            output_file_base: Optional[str] = None,
            validate_pre: bool = True,
            validate_post: bool = True,
            save_validation_report_pre: bool = True,
            save_validation_report_post: bool = True,
            exec_inferences: bool = True,
            save_graph_pre: bool = True,
            save_graph_post: bool = True,
            save_visualization_pre: bool = True,
            save_visualization_post: bool = True,
            save_spec: bool = True,
            verbose: bool = True
            # TODO: Check defaults for all bools to ensure'more common' configuration.
    ) -> None:
        """
        Loads, processes, and optionally validates and enriches a LaDeRR specification,
        then saves the resulting specification (if enabled) and optionally its graph representation,
        visualizations, and validation reports.

        :param input_spec_path: Path to the input LaDeRR specification file.
        :type input_spec_path: str
        :param output_file_base: Base name for the output files (without extension). Required if any save option is enabled.
        :type output_file_base: Optional[str]
        :param validate_pre: Whether to validate before reasoning.
        :type validate_pre: bool
        :param validate_post: Whether to validate after reasoning.
        :type validate_post: bool
        :param save_validation_report_pre: Whether to save the pre-reasoning validation report.
        :type save_validation_report_pre: bool
        :param save_validation_report_post: Whether to save the post-reasoning validation report.
        :type save_validation_report_post: bool
        :param exec_inferences: Whether to apply reasoning.
        :type exec_inferences: bool
        :param save_graph_pre: Whether to save the graph before processing.
        :type save_graph_pre: bool
        :param save_graph_post: Whether to save the processed graph.
        :type save_graph_post: bool
        :param save_visualization_pre: Whether to save the visualization before processing.
        :type save_visualization_pre: bool
        :param save_visualization_post: Whether to save the visualization after processing.
        :type save_visualization_post: bool
        :param save_spec: Whether to save the final processed specification.
        :type save_spec: bool
        :param verbose: Whether to log messages.
        :type verbose: bool

        :raises ValueError: If saving is enabled but `output_file_base` is not provided.
        """
        # Check if saving is requested but no output base is provided
        if not output_file_base and (
                save_graph_pre or save_graph_post or save_visualization_pre or save_visualization_post or save_spec or
                save_validation_report_pre or save_validation_report_post):
            raise ValueError("output_file_base argument must be provided when saving any output.")

        laderr_graph = GraphHandler.create_laderr_graph(input_spec_path)

        if save_graph_pre:
            GraphHandler.save_graph(laderr_graph, f"{output_file_base}_pre.ttl")
            if verbose:
                logger.success(f"Pre-processed graph saved to {output_file_base}_pre.ttl")

        if save_visualization_pre:
            GraphCreator.create_graph_visualization(laderr_graph, f"{output_file_base}_pre")
            if verbose:
                logger.success(f"Pre-processed visualization saved to {output_file_base}_pre")

        if validate_pre:
            validation_report_pre = f"{output_file_base}_validation_report_pre.txt" if save_validation_report_pre else None
            Laderr.validate_graph(laderr_graph, verbose, stage="pre", report_file=validation_report_pre)

        exit(1)

        if exec_inferences:
            laderr_graph = Laderr.run_reasoning_on_graph(laderr_graph, verbose)

        if validate_post:
            validation_report_post = f"{output_file_base}_validation_report_post.txt" if save_validation_report_post else None
            Laderr.validate_graph(laderr_graph, verbose, stage="post", report_file=validation_report_post)

        if save_graph_post:
            GraphHandler.save_graph(laderr_graph, f"{output_file_base}_post.ttl")
            if verbose:
                logger.success(f"Processed graph saved to {output_file_base}_post.ttl")

        if save_visualization_post:
            GraphCreator.create_graph_visualization(laderr_graph, f"{output_file_base}_post")
            if verbose:
                logger.success(f"Processed visualization saved to {output_file_base}_post")

        if save_spec:
            SpecificationHandler.write_specification(laderr_graph, f"{output_file_base}_post.toml")
            if verbose:
                logger.success(f"Processed specification successfully saved to: {output_file_base}_post.toml")
